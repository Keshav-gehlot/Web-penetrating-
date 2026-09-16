from __future__ import annotations

import asyncio
from collections import defaultdict
from typing import Any


class EventBus:
    """Small in-process event bus for the single-node development runtime.

    The interface is intentionally transport-neutral so Redis pub/sub can replace
    the implementation later without changing scan or WebSocket API contracts.
    """

    def __init__(self) -> None:
        self._subscribers: dict[str, set[asyncio.Queue[dict[str, Any]]]] = defaultdict(set)
        self._lock = asyncio.Lock()

    async def subscribe(self, scan_id: str) -> asyncio.Queue[dict[str, Any]]:
        queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue(maxsize=100)
        async with self._lock:
            self._subscribers[scan_id].add(queue)
        return queue

    async def unsubscribe(self, scan_id: str, queue: asyncio.Queue[dict[str, Any]]) -> None:
        async with self._lock:
            self._subscribers[scan_id].discard(queue)
            if not self._subscribers[scan_id]:
                self._subscribers.pop(scan_id, None)

    async def publish(self, scan_id: str, event: dict[str, Any]) -> None:
        async with self._lock:
            queues = list(self._subscribers.get(scan_id, set()))
        for queue in queues:
            try:
                queue.put_nowait(event)
            except asyncio.QueueFull:
                # A slow client must not block scan execution.
                pass


bus = EventBus()
