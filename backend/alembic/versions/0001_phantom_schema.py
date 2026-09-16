"""Initial PHANTOM workspace schema."""
from alembic import op
import sqlalchemy as sa

revision="0001_phantom_schema"
down_revision=None
branch_labels=None
depends_on=None

def upgrade() -> None:
    bind=op.get_bind(); inspector=sa.inspect(bind)
    if not inspector.has_table("organizations"):
        op.create_table("organizations",sa.Column("id",sa.String(36),primary_key=True),sa.Column("name",sa.String(160),nullable=False),sa.Column("slug",sa.String(80),nullable=False,unique=True),sa.Column("created_at",sa.DateTime(timezone=True),server_default=sa.func.now(),nullable=False))
    if not inspector.has_table("workspaces"):
        op.create_table("workspaces",sa.Column("id",sa.String(36),primary_key=True),sa.Column("organization_id",sa.String(36),sa.ForeignKey("organizations.id",ondelete="CASCADE"),nullable=False),sa.Column("name",sa.String(160),nullable=False),sa.Column("slug",sa.String(80),nullable=False),sa.Column("created_at",sa.DateTime(timezone=True),server_default=sa.func.now(),nullable=False),sa.UniqueConstraint("organization_id","slug",name="uq_workspace_org_slug"))
    if not inspector.has_table("users"):
        op.create_table("users",sa.Column("id",sa.String(36),primary_key=True),sa.Column("email",sa.String(255),nullable=False,unique=True),sa.Column("display_name",sa.String(120),nullable=False),sa.Column("password_hash",sa.String(255),nullable=False),sa.Column("is_active",sa.Boolean(),nullable=False,server_default=sa.true()),sa.Column("created_at",sa.DateTime(timezone=True),server_default=sa.func.now(),nullable=False))
    if not inspector.has_table("workspace_members"):
        op.create_table("workspace_members",sa.Column("id",sa.String(36),primary_key=True),sa.Column("workspace_id",sa.String(36),sa.ForeignKey("workspaces.id",ondelete="CASCADE"),nullable=False),sa.Column("user_id",sa.String(36),sa.ForeignKey("users.id",ondelete="CASCADE"),nullable=False),sa.Column("role",sa.String(32),nullable=False),sa.Column("created_at",sa.DateTime(timezone=True),server_default=sa.func.now(),nullable=False),sa.UniqueConstraint("workspace_id","user_id",name="uq_workspace_member"))
    if not inspector.has_table("assets"):
        op.create_table("assets",sa.Column("id",sa.String(36),primary_key=True),sa.Column("host",sa.String(255),nullable=False),sa.Column("target",sa.Text(),nullable=False),sa.Column("workspace_id",sa.String(36),sa.ForeignKey("workspaces.id"),nullable=True),sa.Column("created_at",sa.DateTime(timezone=True),server_default=sa.func.now(),nullable=False),sa.UniqueConstraint("workspace_id","host",name="uq_asset_workspace_host"))
    if not inspector.has_table("scans"):
        op.create_table("scans",sa.Column("id",sa.String(36),primary_key=True),sa.Column("target",sa.Text(),nullable=False),sa.Column("host",sa.String(255),nullable=False),sa.Column("profile",sa.String(32),nullable=False),sa.Column("status",sa.String(32),nullable=False,server_default="queued"),sa.Column("modules",sa.JSON(),nullable=False),sa.Column("workspace_id",sa.String(36),sa.ForeignKey("workspaces.id"),nullable=True),sa.Column("created_at",sa.DateTime(timezone=True),server_default=sa.func.now(),nullable=False),sa.Column("started_at",sa.DateTime(timezone=True)),sa.Column("completed_at",sa.DateTime(timezone=True)),sa.Column("error",sa.Text()),sa.Column("asset_id",sa.String(36),sa.ForeignKey("assets.id")))
    if not inspector.has_table("findings"):
        op.create_table("findings",sa.Column("id",sa.String(36),primary_key=True),sa.Column("scan_id",sa.String(36),sa.ForeignKey("scans.id",ondelete="CASCADE"),nullable=False),sa.Column("module",sa.String(100),nullable=False),sa.Column("title",sa.Text(),nullable=False),sa.Column("severity",sa.String(20),nullable=False),sa.Column("status",sa.String(32),nullable=False,server_default="open"),sa.Column("fingerprint",sa.String(64),nullable=False),sa.Column("cve",sa.String(32)),sa.Column("cwe",sa.String(32)),sa.Column("cvss",sa.Float()),sa.Column("assignee",sa.String(255)),sa.Column("description",sa.Text(),nullable=False),sa.Column("remediation",sa.Text(),nullable=False),sa.Column("evidence",sa.JSON(),nullable=False),sa.Column("confidence",sa.Float(),nullable=False,server_default="1"),sa.Column("first_seen",sa.DateTime(timezone=True),server_default=sa.func.now(),nullable=False),sa.Column("last_seen",sa.DateTime(timezone=True),server_default=sa.func.now(),nullable=False),sa.Column("created_at",sa.DateTime(timezone=True),server_default=sa.func.now(),nullable=False))

    indexes={"workspaces":["organization_id"],"users":["email"],"workspace_members":["workspace_id","user_id","role"],"assets":["workspace_id","host"],"scans":["workspace_id","status","host"],"findings":["scan_id","severity","status","fingerprint","cve","cwe"]}
    inspector=sa.inspect(bind)
    for table,columns in indexes.items():
        existing={x["name"] for x in inspector.get_indexes(table)}
        for column in columns:
            name=f"ix_{table}_{column}"
            if name not in existing:op.create_index(name,table,[column])

def downgrade() -> None:
    for table in ("findings","scans","assets","workspace_members","users","workspaces","organizations"):
        op.drop_table(table)
