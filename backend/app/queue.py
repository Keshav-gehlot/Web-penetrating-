from __future__ import annotations

import os
import time
import uuid
from redis.asyncio import Redis

REDIS_URL = os.getenv("PHANTOM_REDIS_URL", "redis://localhost:6379/0")
SCAN_STREAM = "phantom:scan:jobs"
SCAN_GROUP = "phantom-workers"
JOB_LEASE_SECONDS = int(os.getenv("PHANTOM_JOB_LEASE_SECONDS", "900"))


def redis_client() -> Redis:
    return Redis.from_url(REDIS_URL, decode_responses=True)


async def ensure_consumer_group(client: Redis) -> None:
    try:
        await client.xgroup_create(SCAN_STREAM, SCAN_GROUP, id="0", mkstream=True)
    except Exception as exc:
        if "BUSYGROUP" not in str(exc):
            raise


async def enqueue_scan(scan_id: str, attempt: int = 1) -> str:
    client = redis_client()
    try:
        return await client.xadd(
            SCAN_STREAM,
            {"scan_id": scan_id, "attempt": str(attempt), "queued_at": str(time.time()), "job_id": uuid.uuid4().hex},
            maxlen=10000,
            approximate=True,
        )
    finally:
        await client.aclose()


async def enqueue_retry(scan_id: str, attempt: int) -> str:
    return await enqueue_scan(scan_id, attempt)
