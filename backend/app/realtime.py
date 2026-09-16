from __future__ import annotations

import json
import os
from typing import Any

from redis.asyncio import Redis

REDIS_URL = os.getenv("PHANTOM_REDIS_URL", "redis://localhost:6379/0")
CHANNEL_PREFIX = "phantom:scan:events:"


class RedisEventBus:
    def _client(self) -> Redis:
        return Redis.from_url(REDIS_URL, decode_responses=True)

    async def publish(self, scan_id: str, event: dict[str, Any]) -> None:
        client = self._client()
        try:
            await client.publish(f"{CHANNEL_PREFIX}{scan_id}", json.dumps(event, separators=(",", ":")))
        finally:
            await client.aclose()

    async def subscribe(self, scan_id: str):
        client = self._client()
        pubsub = client.pubsub()
        await pubsub.subscribe(f"{CHANNEL_PREFIX}{scan_id}")
        return client, pubsub


bus = RedisEventBus()
