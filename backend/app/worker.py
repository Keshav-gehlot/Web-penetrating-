from __future__ import annotations

import asyncio
import json
import logging
import os
import socket
import time
from datetime import datetime, timezone

from sqlalchemy import select

from .api.scans import execute_scan
from .config import settings
from .database import SessionLocal
from .models import Scan
from .queue import PROCESSING_QUEUE, SCAN_QUEUE, enqueue_retry, redis_client

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
log = logging.getLogger("phantom.worker")
MAX_ATTEMPTS = int(os.getenv("PHANTOM_MAX_JOB_ATTEMPTS", "3"))


async def mark_stale_scans() -> None:
    cutoff = time.time() - settings.SCAN_TOTAL_TIMEOUT_SECONDS
    recovered: list[str] = []
    async with SessionLocal() as db:
        rows = await db.scalars(select(Scan).where(Scan.status == "running", Scan.started_at.is_not(None)))
        for scan in rows.all():
            if scan.started_at.timestamp() < cutoff:
                scan.status = "queued"
                scan.error = "Worker lease expired; scan returned to queue."
                recovered.append(scan.id)
        if recovered:
            await db.commit()
    for scan_id in recovered:
        await enqueue_retry(scan_id, 1)
    if recovered:
        log.warning("Recovered %s stale scan(s)", len(recovered))


async def process_job(client, raw: str) -> None:
    payload = json.loads(raw)
    scan_id = str(payload["scan_id"])
    attempt = int(payload.get("attempt", 1))
    log.info("Executing scan %s (attempt %s/%s)", scan_id, attempt, MAX_ATTEMPTS)

    async with SessionLocal() as db:
        scan = await db.get(Scan, scan_id)
        if not scan:
            log.warning("Ignoring missing scan %s", scan_id)
            return
        if scan.status in {"completed", "cancelled"}:
            return
        if scan.status == "running":
            log.warning("Skipping scan %s because another worker owns it", scan_id)
            return
        scan.status = "running"
        scan.started_at = datetime.now(timezone.utc)
        scan.error = None
        await db.commit()

    try:
        await asyncio.wait_for(execute_scan(scan_id), timeout=settings.SCAN_TOTAL_TIMEOUT_SECONDS)
    except asyncio.TimeoutError as exc:
        message = f"Scan exceeded {settings.SCAN_TOTAL_TIMEOUT_SECONDS}s execution budget"
        log.error("%s: %s", scan_id, message)
        if attempt < MAX_ATTEMPTS:
            await enqueue_retry(scan_id, attempt + 1)
        async with SessionLocal() as db:
            scan = await db.get(Scan, scan_id)
            if scan and scan.status == "running":
                scan.status = "queued" if attempt < MAX_ATTEMPTS else "failed"
                scan.error = message
                await db.commit()
        if attempt >= MAX_ATTEMPTS:
            await client.publish(f"phantom:scan:events:{scan_id}", json.dumps({"event":"scan.failed","scan_id":scan_id,"error":message}))
    except Exception as exc:
        log.exception("Scan %s failed", scan_id)
        if attempt < MAX_ATTEMPTS:
            await enqueue_retry(scan_id, attempt + 1)
        async with SessionLocal() as db:
            scan = await db.get(Scan, scan_id)
            if scan:
                scan.status = "queued" if attempt < MAX_ATTEMPTS else "failed"
                scan.error = f"Worker error: {exc}"
                await db.commit()


async def main() -> None:
    log.info("PHANTOM worker started; queue=%s max_concurrent=%s", SCAN_QUEUE, settings.MAX_CONCURRENT_SCANS)
    client = redis_client()
    try:
        last_recovery = 0.0
        while True:
            now = time.time()
            if now - last_recovery >= 60:
                await mark_stale_scans()
                last_recovery = now
            item = await client.blmove(SCAN_QUEUE, PROCESSING_QUEUE, "LEFT", "RIGHT", timeout=5)
            if not item:
                continue
            try:
                await process_job(client, item)
            except Exception:
                log.exception("Malformed or unprocessable job: %s", item)
            finally:
                await client.lrem(PROCESSING_QUEUE, 1, item)
    except (KeyboardInterrupt, asyncio.CancelledError):
        log.info("Worker shutting down")
    except (ConnectionError, socket.error):
        log.exception("Redis connection failed")
        raise
    finally:
        await client.aclose()


if __name__ == "__main__":
    asyncio.run(main())
