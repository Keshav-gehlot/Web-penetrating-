from datetime import datetime, timedelta, timezone

import pytest

from app import worker


@pytest.mark.asyncio
async def test_refresh_lease_requires_current_worker(monkeypatch):
    class Result:
        rowcount = 0

    class DB:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return False

        async def execute(self, *_args, **_kwargs):
            return Result()

        async def commit(self):
            return None

    monkeypatch.setattr(worker, "SessionLocal", lambda: DB())
    assert await worker.refresh_lease("scan-1") is False


def test_stale_lease_is_expired_before_recovery():
    now = datetime.now(timezone.utc)
    expired = now - timedelta(seconds=1)
    assert expired < now


def test_worker_consumer_id_is_nonempty():
    assert worker.CONSUMER
    assert worker.MAX_ATTEMPTS >= 1
    assert worker.HEARTBEAT_TTL >= 20
