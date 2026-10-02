from __future__ import annotations

from fastapi import APIRouter, Response
from sqlalchemy import text

from ..database import SessionLocal
from ..queue import ensure_consumer_group, redis_client

router = APIRouter(tags=["health"])


async def redis_ready() -> bool:
    client = redis_client()
    try:
        await client.ping()
        await ensure_consumer_group(client)
        return True
    except Exception:
        return False
    finally:
        await client.aclose()


async def database_ready() -> bool:
    try:
        async with SessionLocal() as db:
            await db.execute(text("SELECT 1"))
        return True
    except Exception:
        return False


@router.get("/ready")
async def readiness(response: Response):
    database = await database_ready()
    redis = await redis_ready()
    ready = database and redis
    if not ready:
        response.status_code = 503
    return {"status": "ready" if ready else "not_ready", "dependencies": {"database": database, "redis": redis}}
