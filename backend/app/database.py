from __future__ import annotations

from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase

from .config import settings

engine = create_async_engine(settings.DATABASE_URL, pool_pre_ping=True, pool_recycle=1800)
SessionLocal = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)


class Base(DeclarativeBase):
    pass


async def get_db():
    async with SessionLocal() as session:
        yield session


async def check_database() -> bool:
    try:
        async with engine.connect() as connection:
            await connection.execute(text("SELECT 1"))
        return True
    except Exception:
        return False


async def init_db() -> None:
    # Bootstrap credentials are retained for first-user provisioning and are
    # mirrored into the isolated authentication store at startup.
    from .models import Organization, User, Workspace, WorkspaceMember  # noqa: F401
    from .security import hash_password
    from .auth_store import ensure_auth_store, provision_user
    from uuid import uuid4

    await ensure_auth_store()

    async with SessionLocal() as db:
        org = await db.scalar(select(Organization).where(Organization.slug == "phantom"))
        if not org:
            org = Organization(id=str(uuid4()), name="PHANTOM", slug="phantom")
            db.add(org)
            await db.flush()

        workspace = await db.get(Workspace, "default")
        if not workspace:
            workspace = Workspace(
                id="default",
                organization_id=org.id,
                name="PHANTOM Security Workspace",
                slug="default",
            )
            db.add(workspace)
            await db.flush()

        user = await db.scalar(select(User).where(User.email == settings.BOOTSTRAP_EMAIL.lower()))
        if not user:
            user = User(
                email=settings.BOOTSTRAP_EMAIL.lower(),
                display_name="PHANTOM Administrator",
                password_hash=hash_password(settings.BOOTSTRAP_PASSWORD),
                is_active=True,
            )
            db.add(user)
            await db.flush()

        membership = await db.scalar(
            select(WorkspaceMember).where(
                WorkspaceMember.workspace_id == workspace.id,
                WorkspaceMember.user_id == user.id,
            )
        )
        if not membership:
            db.add(WorkspaceMember(workspace_id=workspace.id, user_id=user.id, role=settings.BOOTSTRAP_ROLE))

        await db.commit()
