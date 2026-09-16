from __future__ import annotations

import json
import os
from redis.asyncio import Redis

REDIS_URL = os.getenv("PHANTOM_REDIS_URL", "redis://localhost:6379/0")
SCAN_QUEUE = "phantom:scan:jobs"


def redis_client() -> Redis:
    return Redis.from_url(REDIS_URL, decode_responses=True)


async def enqueue_scan(scan_id: str) -> None:
    client = redis_client()
    try:
        await client.rpush(SCAN_QUEUE, json.dumps({"scan_id": scan_id}))
    finally:
        await client.aclose()
