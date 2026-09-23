from __future__ import annotations

from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine

from .config import settings
from .security import verify_password

auth_engine = create_async_engine(settings.AUTH_DATABASE_URL, pool_pre_ping=True, pool_recycle=1800)

_IS_POSTGRES = settings.AUTH_DATABASE_URL.startswith(("postgresql://", "postgres://", "postgresql+asyncpg://"))
_TABLE = "phantom_auth.users" if _IS_POSTGRES else "phantom_auth_users"


async def ensure_auth_store() -> None:
    async with auth_engine.begin() as connection:
        if _IS_POSTGRES:
            await connection.execute(text("CREATE SCHEMA IF NOT EXISTS phantom_auth"))
        await connection.execute(text(f"""
            CREATE TABLE IF NOT EXISTS {_TABLE} (
                id VARCHAR(36) PRIMARY KEY,
                email VARCHAR(255) NOT NULL UNIQUE,
                password_hash VARCHAR(255) NOT NULL,
                is_active BOOLEAN NOT NULL DEFAULT TRUE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """))


async def provision_user(user_id: str, email: str, password_hash: str, is_active: bool = True) -> None:
    email = email.strip().lower()
    async with auth_engine.begin() as connection:
        await connection.execute(
            text(f"""
                INSERT INTO {_TABLE} (id, email, password_hash, is_active)
                VALUES (:id, :email, :password_hash, :is_active)
                ON CONFLICT (email) DO NOTHING
            """),
            {"id": str(user_id), "email": email, "password_hash": password_hash, "is_active": bool(is_active)},
        )


async def set_password(email: str, user_id: str, password_hash: str) -> None:
    email = email.strip().lower()
    async with auth_engine.begin() as connection:
        result = await connection.execute(
            text(f"""
                UPDATE {_TABLE}
                SET id=:id, password_hash=:password_hash, is_active=TRUE, updated_at=CURRENT_TIMESTAMP
                WHERE email=:email
            """),
            {"id": str(user_id), "email": email, "password_hash": password_hash},
        )
        if result.rowcount == 0:
            await connection.execute(
                text(f"""
                    INSERT INTO {_TABLE} (id, email, password_hash, is_active)
                    VALUES (:id, :email, :password_hash, TRUE)
                    ON CONFLICT (email) DO UPDATE SET
                        id=EXCLUDED.id,
                        password_hash=EXCLUDED.password_hash,
                        is_active=TRUE,
                        updated_at=CURRENT_TIMESTAMP
                """),
                {"id": str(user_id), "email": email, "password_hash": password_hash},
            )


async def verify_credentials(email: str, password: str) -> bool:
    email = email.strip().lower()
    async with auth_engine.connect() as connection:
        row = (
            await connection.execute(
                text(f"SELECT password_hash, is_active FROM {_TABLE} WHERE email=:email"),
                {"email": email},
            )
        ).mappings().first()
    if not row or not row["is_active"]:
        return False
    return verify_password(password, str(row["password_hash"]))
