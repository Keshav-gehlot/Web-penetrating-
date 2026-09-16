from __future__ import annotations

import json
import os
import time
from redis.asyncio import Redis

REDIS_URL = os.getenv("PHANTOM_REDIS_URL", "redis://localhost:6379/0")
SCAN_QUEUE = "phantom:scan:jobs"
PROCESSING_QUEUE = "phantom:scan:jobs:processing"
JOB_TTL_SECONDS = int(os.getenv("PHANTOM_JOB_TTL_SECONDS", "900"))


def redis_client() -> Redis:
    return Redis.from_url(REDIS_URL, decode_responses=True)


async def enqueue_scan(scan_id: str) -> None:
    client = redis_client()
    try:
        payload = {"scan_id": scan_id, "queued_at": time.time()}
        await client.rpush(SCAN_QUEUE, json.dumps(payload, separators=(",", ":")))
    finally:
        await client.aclose()


async def enqueue_retry(scan_id: str, attempt: int) -> None:
    client = redis_client()
    try:
        payload = {"scan_id": scan_id, "attempt": attempt, "queued_at": time.time()}
        await client.rpush(SCAN_QUEUE, json.dumps(payload, separators=(",", ":")))
    finally:
        await client.aclose()
