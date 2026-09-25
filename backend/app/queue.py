from __future__ import annotations

import os
import time
import uuid
from redis.asyncio import Redis


def _redis_url() -> str:
    """Return the configured Redis endpoint without reconstructing credentials."""
    return os.getenv("PHANTOM_REDIS_URL", "").strip() or "redis://localhost:6379/0"


REDIS_URL = _redis_url()
SCAN_STREAM = "phantom:scan:jobs"
SCAN_GROUP = "phantom-workers"
JOB_LEASE_SECONDS = int(os.getenv("PHANTOM_JOB_LEASE_SECONDS", "900"))
SLOT_PREFIX = "phantom:scan:slot:"
MAX_CONCURRENT_SCANS = max(1, int(os.getenv("PHANTOM_MAX_CONCURRENT_SCANS", "2")))

_RELEASE_SLOT = """
if redis.call('get', KEYS[1]) == ARGV[1] then
  return redis.call('del', KEYS[1])
end
return 0
"""


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


async def acquire_scan_slot(client: Redis, owner: str) -> str | None:
    for index in range(MAX_CONCURRENT_SCANS):
        key = f"{SLOT_PREFIX}{index}"
        if await client.set(key, owner, nx=True, ex=JOB_LEASE_SECONDS):
            return key
    return None


async def refresh_scan_slot(client: Redis, slot_key: str, owner: str) -> bool:
    current = await client.get(slot_key)
    if current != owner:
        return False
    return bool(await client.expire(slot_key, JOB_LEASE_SECONDS))


async def release_scan_slot(client: Redis, slot_key: str, owner: str) -> None:
    await client.eval(_RELEASE_SLOT, 1, slot_key, owner)
