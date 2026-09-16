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
    from .security import hash_password
    from sqlalchemy import select
    from uuid import uuid4
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
    async with SessionLocal() as db:
        org=await db.scalar(select(Organization).where(Organization.slug=="phantom"))
        if not org:
            org=Organization(id=str(uuid4()),name="PHANTOM",slug="phantom");db.add(org);await db.flush()
        workspace=await db.get(Workspace,"default")
        if not workspace:
            workspace=Workspace(id="default",organization_id=org.id,name="PHANTOM Security Workspace",slug="default");db.add(workspace);await db.flush()
        user=await db.scalar(select(User).where(User.email==settings.BOOTSTRAP_EMAIL.lower()))
        if not user:
            user=User(email=settings.BOOTSTRAP_EMAIL.lower(),display_name="PHANTOM Administrator",password_hash=hash_password(settings.BOOTSTRAP_PASSWORD),is_active=True);db.add(user);await db.flush()
        membership=await db.scalar(select(WorkspaceMember).where(WorkspaceMember.workspace_id==workspace.id,WorkspaceMember.user_id==user.id))
        if not membership:
            db.add(WorkspaceMember(workspace_id=workspace.id,user_id=user.id,role=settings.BOOTSTRAP_ROLE))
        await db.commit()
