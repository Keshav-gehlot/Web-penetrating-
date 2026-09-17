from __future__ import annotations

import asyncio
import logging
import os
import socket
import time
import uuid
from datetime import datetime, timedelta, timezone

from sqlalchemy import select, update

from .api.scans import execute_scan
from .config import settings
from .database import SessionLocal
from .models import Scan, WorkspaceScope
from .observability import record_operational_event
from .queue import JOB_LEASE_SECONDS, SCAN_GROUP, SCAN_STREAM, ensure_consumer_group, enqueue_retry, redis_client
from .scan_guard import acquire_slot, refresh_slot, release_slot
from .security_scope import scope_snapshot

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
log = logging.getLogger("phantom.worker")
MAX_ATTEMPTS = settings.MAX_JOB_ATTEMPTS
CONSUMER = f"{socket.gethostname()}-{os.getpid()}-{uuid.uuid4().hex[:8]}"
HEARTBEAT_TTL = max(20, int(os.getenv("PHANTOM_WORKER_HEARTBEAT_TTL", "30")))


def normalize_attempt(value: object) -> int:
    try:
        attempt = int(value)
    except (TypeError, ValueError):
        attempt = 1
    return max(1, min(attempt, MAX_ATTEMPTS))


def recovery_attempt(current_attempt: object) -> int | None:
    try:
        current = int(current_attempt or 1)
    except (TypeError, ValueError):
        current = 1
    next_attempt = max(1, current + 1)
    return next_attempt if next_attempt <= MAX_ATTEMPTS else None


async def _op(event_type: str, message: str, *, workspace_id: str | None = None, scan_id: str | None = None, severity: str = "info", metadata: dict | None = None) -> None:
    await record_operational_event(event_type, message, severity, workspace_id, scan_id, metadata)


async def claim_scan(scan_id: str, attempt: int) -> bool:
    now = datetime.now(timezone.utc)
    lease = now + timedelta(seconds=JOB_LEASE_SECONDS)
    async with SessionLocal() as db:
        result = await db.execute(update(Scan).where(Scan.id == scan_id, Scan.status == "queued").values(status="running", started_at=now, worker_id=CONSUMER, lease_expires_at=lease, cancel_requested_at=None, cancelled_at=None, error=None, attempt=attempt))
        await db.commit()
        claimed = result.rowcount == 1
    if claimed:
        await _op("worker.claimed", "Worker claimed scan execution", scan_id=scan_id, severity="info", metadata={"worker_id": CONSUMER, "attempt": attempt})
    return claimed


async def refresh_lease(scan_id: str) -> bool:
    lease = datetime.now(timezone.utc) + timedelta(seconds=JOB_LEASE_SECONDS)
    async with SessionLocal() as db:
        result = await db.execute(update(Scan).where(Scan.id == scan_id, Scan.worker_id == CONSUMER, Scan.status == "running").values(lease_expires_at=lease))
        await db.commit()
        return result.rowcount == 1


async def recover_stale_scans() -> int:
    now = datetime.now(timezone.utc)
    recovered: list[tuple[str, int, str | None]] = []
    failed: list[tuple[str, str | None]] = []
    async with SessionLocal() as db:
        rows = await db.scalars(select(Scan).where(Scan.status == "running", Scan.lease_expires_at.is_not(None), Scan.lease_expires_at < now))
        for scan in rows.all():
            next_attempt = recovery_attempt(scan.attempt)
            if next_attempt is None:
                scan.status = "failed"
                scan.error = f"Worker lease expired after {MAX_ATTEMPTS} execution attempts."
                scan.worker_id = None
                scan.lease_expires_at = None
                failed.append((scan.id, scan.workspace_id))
                continue
            old_worker = scan.worker_id
            scan.status = "queued"
            scan.worker_id = None
            scan.lease_expires_at = None
            scan.error = "Worker lease expired; scan returned to queue."
            scan.attempt = next_attempt
            recovered.append((scan.id, next_attempt, scan.workspace_id))
            del old_worker
        await db.commit()
    for scan_id, attempt, workspace_id in recovered:
        try:
            await enqueue_retry(scan_id, attempt)
            await _op("scan.recovered", "Expired worker lease recovered into queue", workspace_id=workspace_id, scan_id=scan_id, severity="warning", metadata={"attempt": attempt})
        except Exception:
            log.exception("Failed to re-enqueue recovered scan %s", scan_id)
            await _op("scan.recovery_failed", "Recovered scan could not be re-enqueued", workspace_id=workspace_id, scan_id=scan_id, severity="error", metadata={"attempt": attempt})
    for scan_id, workspace_id in failed:
        await _op("scan.retry_exhausted", "Scan failed after worker lease attempts were exhausted", workspace_id=workspace_id, scan_id=scan_id, severity="error", metadata={"max_attempts": MAX_ATTEMPTS})
    return len(recovered)


async def retry_or_fail(client, message_id: str, scan_id: str, attempt: int, message: str) -> None:
    next_status = "queued" if attempt < MAX_ATTEMPTS else "failed"
    workspace_id = None
    async with SessionLocal() as db:
        scan = await db.get(Scan, scan_id)
        workspace_id = scan.workspace_id if scan else None
        result = await db.execute(update(Scan).where(Scan.id == scan_id, Scan.worker_id == CONSUMER, Scan.status == "running").values(status=next_status, error=message, worker_id=None, lease_expires_at=None))
        await db.commit()
    if result.rowcount != 1:
        await client.xack(SCAN_STREAM, SCAN_GROUP, message_id)
        return
    if attempt < MAX_ATTEMPTS:
        await enqueue_retry(scan_id, attempt + 1)
        await _op("scan.retry_scheduled", "Scan returned to queue after worker failure", workspace_id=workspace_id, scan_id=scan_id, severity="warning", metadata={"attempt": attempt, "next_attempt": attempt + 1, "error": message})
    else:
        await _op("scan.retry_exhausted", "Scan failed after worker retry limit", workspace_id=workspace_id, scan_id=scan_id, severity="error", metadata={"attempt": attempt, "max_attempts": MAX_ATTEMPTS, "error": message})
    await client.xack(SCAN_STREAM, SCAN_GROUP, message_id)


async def _scan_execution_limits(scan_id: str) -> tuple[str | None, int]:
    async with SessionLocal() as db:
        scan = await db.get(Scan, scan_id)
        if not scan:
            return None, settings.MAX_CONCURRENT_SCANS
        workspace_id = scan.workspace_id
        if not workspace_id:
            return None, settings.MAX_CONCURRENT_SCANS
        scope_row = await db.scalar(select(WorkspaceScope).where(WorkspaceScope.workspace_id == workspace_id))
        scope = scope_snapshot(scope_row)
        limit = min(int(scope.get("max_concurrency", settings.MAX_CONCURRENT_SCANS)), settings.MAX_CONCURRENT_SCANS)
        return workspace_id, max(1, limit)


async def process_message(client, message_id: str, fields: dict[str, str]) -> None:
    scan_id = str(fields.get("scan_id", "") or "")
    if not scan_id:
        await client.xack(SCAN_STREAM, SCAN_GROUP, message_id)
        return
    attempt = normalize_attempt(fields.get("attempt", "1"))

    workspace_id, workspace_limit = await _scan_execution_limits(scan_id)
    if workspace_id is None:
        await client.xack(SCAN_STREAM, SCAN_GROUP, message_id)
        return

    workspace_slot = None
    global_slot = None
    workspace_namespace = f"workspace:{workspace_id}"
    while workspace_slot is None or global_slot is None:
        if workspace_slot is None:
            workspace_slot = await acquire_slot(client, workspace_limit, CONSUMER, namespace=workspace_namespace)
        if workspace_slot is not None and global_slot is None:
            global_slot = await acquire_slot(client, settings.MAX_CONCURRENT_SCANS, CONSUMER, namespace="global")
            if global_slot is None:
                await release_slot(client, workspace_slot[0], workspace_slot[1])
                workspace_slot = None
        if workspace_slot is None or global_slot is None:
            await asyncio.sleep(1)

    try:
        if not await claim_scan(scan_id, attempt):
            async with SessionLocal() as db:
                scan = await db.get(Scan, scan_id)
                terminal_or_active = not scan or scan.status in {"running", "completed", "failed", "cancelled", "queued"}
            if terminal_or_active:
                await client.xack(SCAN_STREAM, SCAN_GROUP, message_id)
            return
        stop = asyncio.Event()
        lease_lost = asyncio.Event()

        async def heartbeat() -> None:
            interval = max(5, min(JOB_LEASE_SECONDS // 3, HEARTBEAT_TTL))
            while not stop.is_set():
                try:
                    await asyncio.wait_for(stop.wait(), timeout=interval)
                except asyncio.TimeoutError:
                    workspace_ok = await refresh_slot(client, workspace_slot[0], workspace_slot[1])
                    global_ok = await refresh_slot(client, global_slot[0], global_slot[1])
                    if not await refresh_lease(scan_id) or not workspace_ok or not global_ok:
                        log.error("Lost execution lease for scan %s", scan_id)
                        await _op("worker.lease_lost", "Worker lost execution lease", workspace_id=workspace_id, scan_id=scan_id, severity="error", metadata={"worker_id": CONSUMER, "attempt": attempt})
                        lease_lost.set()
                        stop.set()
                        return

        heartbeat_task = asyncio.create_task(heartbeat())
        execution_task = asyncio.create_task(asyncio.wait_for(execute_scan(scan_id, expected_worker=CONSUMER), timeout=settings.SCAN_TOTAL_TIMEOUT_SECONDS))
        try:
            done, _ = await asyncio.wait({execution_task, heartbeat_task}, return_when=asyncio.FIRST_COMPLETED)
            if heartbeat_task in done and lease_lost.is_set():
                execution_task.cancel()
                await asyncio.gather(execution_task, return_exceptions=True)
                return
            if heartbeat_task in done:
                execution_task.cancel()
                await asyncio.gather(execution_task, return_exceptions=True)
                await retry_or_fail(client, message_id, scan_id, attempt, "Worker heartbeat stopped unexpectedly")
                return
            success = execution_task.result()
            async with SessionLocal() as db:
                scan = await db.get(Scan, scan_id)
                cancelled = bool(scan and scan.status == "cancelled")
            if success or cancelled:
                await client.xack(SCAN_STREAM, SCAN_GROUP, message_id)
            else:
                await retry_or_fail(client, message_id, scan_id, attempt, "Scan execution failed")
        except asyncio.CancelledError:
            execution_task.cancel()
            await asyncio.gather(execution_task, return_exceptions=True)
            raise
        except asyncio.TimeoutError:
            await retry_or_fail(client, message_id, scan_id, attempt, f"Scan exceeded {settings.SCAN_TOTAL_TIMEOUT_SECONDS}s execution budget")
        except Exception as exc:
            log.exception("Scan %s failed", scan_id)
            if not execution_task.done():
                execution_task.cancel()
            await asyncio.gather(execution_task, return_exceptions=True)
            await retry_or_fail(client, message_id, scan_id, attempt, f"Worker error: {exc}")
        finally:
            stop.set()
            if not heartbeat_task.done():
                await heartbeat_task
    finally:
        if global_slot is not None:
            await release_slot(client, global_slot[0], global_slot[1])
        if workspace_slot is not None:
            await release_slot(client, workspace_slot[0], workspace_slot[1])


async def recover_stale_jobs(client) -> None:
    cursor = "0-0"
    while True:
        result = await client.xautoclaim(SCAN_STREAM, SCAN_GROUP, CONSUMER, JOB_LEASE_SECONDS * 1000, cursor, count=50)
        cursor, messages = result[0], result[1]
        for message_id, fields in messages:
            await process_message(client, message_id, fields)
        if cursor == "0-0" or not messages:
            return


async def main() -> None:
    client = redis_client()
    await ensure_consumer_group(client)
    heartbeat_key = f"phantom:worker:heartbeat:{CONSUMER}"
    last_recovery = 0.0
    log.info("PHANTOM worker started stream=%s group=%s consumer=%s max_concurrent=%s", SCAN_STREAM, SCAN_GROUP, CONSUMER, settings.MAX_CONCURRENT_SCANS)
    await _op("worker.started", "PHANTOM worker started", metadata={"worker_id": CONSUMER, "max_concurrent": settings.MAX_CONCURRENT_SCANS})
    try:
        while True:
            now = time.time()
            await client.set(heartbeat_key, str(now), ex=HEARTBEAT_TTL)
            if now - last_recovery >= 10:
                recovered = await recover_stale_scans()
                await recover_stale_jobs(client)
                if recovered:
                    log.warning("Recovered %s stale DB lease(s)", recovered)
                last_recovery = now
            batches = await client.xreadgroup(SCAN_GROUP, CONSUMER, {SCAN_STREAM: ">"}, count=1, block=5000)
            for _, messages in batches:
                for message_id, fields in messages:
                    await process_message(client, message_id, fields)
    except (KeyboardInterrupt, asyncio.CancelledError):
        log.info("PHANTOM worker shutting down")
    finally:
        await _op("worker.stopped", "PHANTOM worker stopped", severity="warning", metadata={"worker_id": CONSUMER})
        await client.delete(heartbeat_key)
        await client.aclose()


if __name__ == "__main__":
    asyncio.run(main())
