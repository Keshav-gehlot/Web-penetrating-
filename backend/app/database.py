from __future__ import annotations
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase
from .config import settings
engine=create_async_engine(settings.DATABASE_URL,pool_pre_ping=True,pool_recycle=1800)
SessionLocal=async_sessionmaker(engine,class_=AsyncSession,expire_on_commit=False)
class Base(DeclarativeBase): pass
async def get_db():
    async with SessionLocal() as session: yield session
async def init_db()->None:
    from .models import Organization, Workspace, User, WorkspaceMember, Asset, Finding, Scan  # noqa: F401
    from .api.audit import AuditEvent  # noqa: F401
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
        if settings.DATABASE_URL.startswith("postgresql"):
            for statement in (
                "ALTER TABLE assets ADD COLUMN IF NOT EXISTS workspace_id VARCHAR(36)",
                "ALTER TABLE scans ADD COLUMN IF NOT EXISTS workspace_id VARCHAR(36)",
                "ALTER TABLE findings ADD COLUMN IF NOT EXISTS status VARCHAR(32)",
                "ALTER TABLE findings ADD COLUMN IF NOT EXISTS fingerprint VARCHAR(64)",
                "ALTER TABLE findings ADD COLUMN IF NOT EXISTS cve VARCHAR(32)",
                "ALTER TABLE findings ADD COLUMN IF NOT EXISTS cwe VARCHAR(32)",
                "ALTER TABLE findings ADD COLUMN IF NOT EXISTS cvss DOUBLE PRECISION",
                "ALTER TABLE findings ADD COLUMN IF NOT EXISTS assignee VARCHAR(255)",
                "ALTER TABLE findings ADD COLUMN IF NOT EXISTS first_seen TIMESTAMPTZ",
                "ALTER TABLE findings ADD COLUMN IF NOT EXISTS last_seen TIMESTAMPTZ",
                "ALTER TABLE audit_events ADD COLUMN IF NOT EXISTS workspace_id VARCHAR(36)",
                "UPDATE findings SET status='open' WHERE status IS NULL",
                "UPDATE findings SET first_seen=created_at WHERE first_seen IS NULL",
                "UPDATE findings SET last_seen=created_at WHERE last_seen IS NULL",
            ): await connection.execute(text(statement))
