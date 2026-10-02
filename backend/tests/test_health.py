import pytest
from fastapi import Response

from app.api import health


@pytest.mark.asyncio
async def test_readiness_returns_200_when_dependencies_are_ready(monkeypatch):
    async def ready():
        return True

    monkeypatch.setattr(health, "database_ready", ready)
    monkeypatch.setattr(health, "redis_ready", ready)

    response = Response()
    payload = await health.readiness(response)

    assert response.status_code == 200
    assert payload == {
        "status": "ready",
        "dependencies": {"database": True, "redis": True},
    }


@pytest.mark.asyncio
async def test_readiness_returns_503_when_dependency_is_down(monkeypatch):
    async def database_ok():
        return True

    async def redis_down():
        return False

    monkeypatch.setattr(health, "database_ready", database_ok)
    monkeypatch.setattr(health, "redis_ready", redis_down)

    response = Response()
    payload = await health.readiness(response)

    assert response.status_code == 503
    assert payload["status"] == "not_ready"
    assert payload["dependencies"] == {"database": True, "redis": False}
