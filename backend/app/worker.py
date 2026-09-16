from __future__ import annotations

import asyncio
import logging
import os
import socket
import time
import uuid
from datetime import datetime, timezone

from sqlalchemy import select

from .api.scans import execute_scan
from .config import settings
from .database import SessionLocal
from .models import Scan
from .queue import JOB_LEASE_SECONDS, SCAN_GROUP, SCAN_STREAM, ensure_consumer_group, enqueue_retry, redis_client

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
log = logging.getLogger("phantom.worker")
MAX_ATTEMPTS = int(os.getenv("PHANTOM_MAX_JOB_ATTEMPTS", "3"))
CONSUMER = f"{socket.gethostname()}-{os.getpid()}-{uuid.uuid4().hex[:8]}"


async def recover_stale_jobs(client) -> None:
    cursor = "0-0"
    while True:
        result = await client.xautoclaim(
            SCAN_STREAM, SCAN_GROUP, CONSUMER, JOB_LEASE_SECONDS * 1000, cursor, count=50
        )
        cursor = result[0]
        messages = result[1]
        for message_id, fields in messages:
            await process_message(client, message_id, fields)
        if cursor == "0-0" or not messages:
            break


async def process_message(client, message_id: str, fields: dict[str, str]) -> None:
    scan_id = str(fields.get("scan_id", ""))
    if not scan_id:
        await client.xack(SCAN_STREAM, SCAN_GROUP, message_id)
        return
    attempt = int(fields.get("attempt", "1"))
    async with SessionLocal() as db:
        scan = await db.get(Scan, scan_id)
        if not scan or scan.status in {"completed", "cancelled"}:
            await client.xack(SCAN_STREAM, SCAN_GROUP, message_id)
            return
        if scan.status == "running":
            return
        scan.status = "running"
        scan.started_at = datetime.now(timezone.utc)
        scan.error = None
        await db.commit()

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
    if attempt < MAX_ATTEMPTS:
        await enqueue_retry(scan_id, attempt + 1)
    async with SessionLocal() as db:
        scan = await db.get(Scan, scan_id)
        if scan:
            scan.status = "queued" if attempt < MAX_ATTEMPTS else "failed"
            scan.error = message
            await db.commit()
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
            batches = await client.xreadgroup(
                SCAN_GROUP, CONSUMER, {SCAN_STREAM: ">"}, count=1, block=5000
            )
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
