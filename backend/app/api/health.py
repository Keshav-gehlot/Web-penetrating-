from __future__ import annotations

from fastapi import APIRouter, status
from fastapi.responses import JSONResponse
from sqlalchemy import text

from ..database import SessionLocal
from ..auth_store import auth_engine, ensure_auth_store
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


async def auth_database_ready() -> bool:
    try:
        await ensure_auth_store()
        async with auth_engine.connect() as connection:
            await connection.execute(text("SELECT 1"))
        return True
    except Exception:
        return False


@router.get("/ready")
async def readiness():
    database = await database_ready()
    auth_database = await auth_database_ready()
    redis = await redis_ready()
    ready = database and auth_database and redis
    print(
        f"PHANTOM readiness database={database} auth_database={auth_database} redis={redis}",
        flush=True,
    )
    payload = {
        "status": "ready" if ready else "not_ready",
        "dependencies": {
            "database": database,
            "auth_database": auth_database,
            "redis": redis,
        },
    }
    return JSONResponse(
        payload,
        status_code=status.HTTP_200_OK if ready else status.HTTP_503_SERVICE_UNAVAILABLE,
    )
