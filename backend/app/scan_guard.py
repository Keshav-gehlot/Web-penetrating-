from __future__ import annotations

import os
import uuid
from redis.asyncio import Redis

REDIS_URL = os.getenv("PHANTOM_REDIS_URL", "redis://localhost:6379/0")
SLOT_TTL_SECONDS = int(os.getenv("PHANTOM_JOB_LEASE_SECONDS", "900"))
SLOT_PREFIX = "phantom:scan:slot:"


def redis_client() -> Redis:
    return Redis.from_url(REDIS_URL, decode_responses=True)


async def acquire_slot(client: Redis, limit: int, owner: str) -> tuple[str, str] | None:
    for index in range(max(1, limit)):
        key = f"{SLOT_PREFIX}{index}"
        token = f"{owner}:{uuid.uuid4().hex}"
        if await client.set(key, token, nx=True, ex=SLOT_TTL_SECONDS):
            return key, token
    return None


async def refresh_slot(client: Redis, key: str, token: str) -> bool:
    return bool(await client.eval("if redis.call('get', KEYS[1]) == ARGV[1] then return redis.call('expire', KEYS[1], ARGV[2]) else return 0 end", 1, key, token, SLOT_TTL_SECONDS))


async def release_slot(client: Redis, key: str, token: str) -> bool:
    return bool(await client.eval("if redis.call('get', KEYS[1]) == ARGV[1] then return redis.call('del', KEYS[1]) else return 0 end", 1, key, token))
