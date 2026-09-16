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

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
log = logging.getLogger("phantom.worker")
MAX_ATTEMPTS = int(os.getenv("PHANTOM_MAX_JOB_ATTEMPTS", "3"))
CONSUMER = f"{socket.gethostname()}-{os.getpid()}-{uuid.uuid4().hex[:8]}"


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


async def release_scan(scan_id: str, status: str, error: str | None = None) -> None:
    async with SessionLocal() as db:
        await db.execute(
            update(Scan)
            .where(Scan.id == scan_id, Scan.worker_id == CONSUMER)
            .values(status=status, error=error, worker_id=None, lease_expires_at=None)
        )
        await db.commit()


async def recover_stale_jobs(client) -> None:
    cursor = "0-0"
    while True:
        result = await client.xautoclaim(
            SCAN_STREAM, SCAN_GROUP, CONSUMER, JOB_LEASE_SECONDS * 1000, cursor, count=50
        )
        cursor, messages = result[0], result[1]
        for message_id, fields in messages:
            await process_message(client, message_id, fields)
        if cursor == "0-0" or not messages:
            break


async def process_message(client, message_id: str, fields: dict[str, str]) -> None:
    scan_id = str(fields.get("scan_id", ""))
    if not scan_id:
        await client.xack(SCAN_STREAM, SCAN_GROUP, message_id)
        return
    try:
        attempt = int(fields.get("attempt", "1"))
    except ValueError:
        await client.xack(SCAN_STREAM, SCAN_GROUP, message_id)
        return

    if not await claim_scan(scan_id, attempt):
        async with SessionLocal() as db:
            scan = await db.get(Scan, scan_id)
            terminal = not scan or scan.status in {"completed", "failed", "cancelled"}
        if terminal:
            await client.xack(SCAN_STREAM, SCAN_GROUP, message_id)
        return

    try:
        await asyncio.wait_for(execute_scan(scan_id), timeout=settings.SCAN_TOTAL_TIMEOUT_SECONDS)
        await client.xack(SCAN_STREAM, SCAN_GROUP, message_id)
    except asyncio.CancelledError:
        raise
    except asyncio.TimeoutError:
        await retry_or_fail(client, message_id, scan_id, attempt, f"Scan exceeded {settings.SCAN_TOTAL_TIMEOUT_SECONDS}s execution budget")
    except Exception as exc:
        log.exception("Scan %s failed", scan_id)
        await retry_or_fail(client, message_id, scan_id, attempt, f"Worker error: {exc}")


async def retry_or_fail(client, message_id: str, scan_id: str, attempt: int, message: str) -> None:
    next_status = "queued" if attempt < MAX_ATTEMPTS else "failed"
    if attempt < MAX_ATTEMPTS:
        await enqueue_retry(scan_id, attempt + 1)
    await release_scan(scan_id, next_status, message)
    await client.xack(SCAN_STREAM, SCAN_GROUP, message_id)


async def main() -> None:
    log.info("PHANTOM worker started; stream=%s group=%s consumer=%s", SCAN_STREAM, SCAN_GROUP, CONSUMER)
    client = redis_client()
    await ensure_consumer_group(client)
    last_recovery = 0.0
    try:
        while True:
            now = time.time()
            if now - last_recovery >= 30:
                await recover_stale_jobs(client)
                last_recovery = now
            batches = await client.xreadgroup(SCAN_GROUP, CONSUMER, {SCAN_STREAM: ">"}, count=1, block=5000)
            for _, messages in batches:
                for message_id, fields in messages:
                    await process_message(client, message_id, fields)
    except (KeyboardInterrupt, asyncio.CancelledError):
        log.info("Worker shutting down")
    except (ConnectionError, socket.error):
        log.exception("Redis connection failed")
        raise
    finally:
        await client.aclose()


if __name__ == "__main__":
    asyncio.run(main())
