from __future__ import annotations

import asyncio
import json
import logging

from .queue import SCAN_QUEUE, redis_client
from .api.scans import execute_scan

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
log = logging.getLogger("phantom.worker")


async def main() -> None:
    log.info("PHANTOM scan worker started; queue=%s", SCAN_QUEUE)
    client = redis_client()
    try:
        while True:
            item = await client.blpop(SCAN_QUEUE, timeout=5)
            if not item:
                continue
            _, raw = item
            try:
                payload = json.loads(raw)
                scan_id = str(payload["scan_id"])
                log.info("Executing scan %s", scan_id)
                await execute_scan(scan_id)
            except Exception:
                log.exception("Scan job failed before execution")
    finally:
        await client.aclose()


if __name__ == "__main__":
    asyncio.run(main())
