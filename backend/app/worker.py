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
from .models import Scan
from .queue import JOB_LEASE_SECONDS, SCAN_GROUP, SCAN_STREAM, ensure_consumer_group, enqueue_retry, redis_client
from .scan_guard import acquire_slot, refresh_slot, release_slot

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
log = logging.getLogger("phantom.worker")
MAX_ATTEMPTS = settings.MAX_JOB_ATTEMPTS
CONSUMER = f"{socket.gethostname()}-{os.getpid()}-{uuid.uuid4().hex[:8]}"
HEARTBEAT_TTL = max(20, int(os.getenv("PHANTOM_WORKER_HEARTBEAT_TTL", "30")))


async def claim_scan(scan_id: str, attempt: int) -> bool:
    now = datetime.now(timezone.utc)
    lease = now + timedelta(seconds=JOB_LEASE_SECONDS)
    async with SessionLocal() as db:
        result = await db.execute(
            update(Scan)
            .where(Scan.id == scan_id, Scan.status == "queued")
            .values(
                status="running",
                started_at=now,
                worker_id=CONSUMER,
                lease_expires_at=lease,
                cancel_requested_at=None,
                cancelled_at=None,
                error=None,
                attempt=attempt,
            )
        )
        await db.commit()
        return result.rowcount == 1


async def refresh_lease(scan_id: str) -> bool:
    lease = datetime.now(timezone.utc) + timedelta(seconds=JOB_LEASE_SECONDS)
    async with SessionLocal() as db:
        result = await db.execute(
            update(Scan)
            .where(Scan.id == scan_id, Scan.worker_id == CONSUMER, Scan.status == "running")
            .values(lease_expires_at=lease)
        )
        await db.commit()
        return result.rowcount == 1


async def recover_stale_scans() -> int:
    now = datetime.now(timezone.utc)
    recovered: list[str] = []
    async with SessionLocal() as db:
        rows = await db.scalars(
            select(Scan).where(
                Scan.status == "running",
                Scan.lease_expires_at.is_not(None),
                Scan.lease_expires_at < now,
            )
        )
        for scan in rows.all():
            scan.status = "queued"
            scan.worker_id = None
            scan.lease_expires_at = None
            scan.error = "Worker lease expired; scan returned to queue."
            recovered.append(scan.id)
        if recovered:
            await db.commit()
    return len(recovered)


async def retry_or_fail(client, message_id: str, scan_id: str, attempt: int, message: str) -> None:
    next_status = "queued" if attempt < MAX_ATTEMPTS else "failed"
    async with SessionLocal() as db:
        result = await db.execute(
            update(Scan)
            .where(Scan.id == scan_id, Scan.worker_id == CONSUMER, Scan.status == "running")
            .values(status=next_status, error=message, worker_id=None, lease_expires_at=None)
        )
        await db.commit()

    # If this worker no longer owns the scan, another worker has recovered it.
    # Never overwrite the recovered worker's state or enqueue a duplicate retry.
    if result.rowcount != 1:
        await client.xack(SCAN_STREAM, SCAN_GROUP, message_id)
        return

    if attempt < MAX_ATTEMPTS:
        await enqueue_retry(scan_id, attempt + 1)
    await client.xack(SCAN_STREAM, SCAN_GROUP, message_id)


async def process_message(client, message_id: str, fields: dict[str, str]) -> None:
    scan_id = str(fields.get("scan_id", "") or "")
    if not scan_id:
        await client.xack(SCAN_STREAM, SCAN_GROUP, message_id)
        return

    try:
        attempt = int(fields.get("attempt", "1"))
    except (TypeError, ValueError):
        await client.xack(SCAN_STREAM, SCAN_GROUP, message_id)
        return

    slot = None
    while slot is None:
        slot = await acquire_slot(client, settings.MAX_CONCURRENT_SCANS, CONSUMER)
        if slot is None:
            await asyncio.sleep(1)

    slot_key, slot_token = slot
    try:
        if not await claim_scan(scan_id, attempt):
            async with SessionLocal() as db:
                scan = await db.get(Scan, scan_id)
                # A queued scan may belong to another valid message; a running
                # scan is already being processed by another worker. In either
                # case this duplicate message must not poison the consumer group.
                terminal_or_active = not scan or scan.status in {"running", "completed", "failed", "cancelled", "queued"}
            if terminal_or_active:
                await client.xack(SCAN_STREAM, SCAN_GROUP, message_id)
            return

        stop = asyncio.Event()

        async def heartbeat() -> None:
            interval = max(5, min(JOB_LEASE_SECONDS // 3, HEARTBEAT_TTL))
            while not stop.is_set():
                try:
                    await asyncio.wait_for(stop.wait(), timeout=interval)
                except asyncio.TimeoutError:
                    if not await refresh_lease(scan_id) or not await refresh_slot(client, slot_key, slot_token):
                        log.error("Lost execution lease for scan %s", scan_id)
                        stop.set()
                        return

        heartbeat_task = asyncio.create_task(heartbeat())
        try:
            success = await asyncio.wait_for(
                execute_scan(scan_id, expected_worker=CONSUMER),
                timeout=settings.SCAN_TOTAL_TIMEOUT_SECONDS,
            )
            async with SessionLocal() as db:
                scan = await db.get(Scan, scan_id)
                cancelled = bool(scan and scan.status == "cancelled")
            if success or cancelled:
                await client.xack(SCAN_STREAM, SCAN_GROUP, message_id)
            else:
                await retry_or_fail(client, message_id, scan_id, attempt, "Scan execution failed")
        except asyncio.CancelledError:
            raise
        except asyncio.TimeoutError:
            await retry_or_fail(client, message_id, scan_id, attempt, f"Scan exceeded {settings.SCAN_TOTAL_TIMEOUT_SECONDS}s execution budget")
        except Exception as exc:
            log.exception("Scan %s failed", scan_id)
            await retry_or_fail(client, message_id, scan_id, attempt, f"Worker error: {exc}")
        finally:
            stop.set()
            await heartbeat_task
    finally:
        await release_slot(client, slot_key, slot_token)


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
        await client.delete(heartbeat_key)
        await client.aclose()


if __name__ == "__main__":
    asyncio.run(main())
