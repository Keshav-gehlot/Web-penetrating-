"""workspace integrations
Revision ID: 0018_integrations
Revises: 0017_report_system
"""
from alembic import op
import sqlalchemy as sa
revision="0018_integrations"
down_revision="0017_report_system"
def upgrade():
    op.create_table("integrations",
      sa.Column("id",sa.String(36),primary_key=True),
      sa.Column("workspace_id",sa.String(36),sa.ForeignKey("workspaces.id",ondelete="CASCADE"),nullable=False),
      sa.Column("provider",sa.String(32),nullable=False),
      sa.Column("name",sa.String(120),nullable=False),
      sa.Column("enabled",sa.Boolean(),nullable=False,server_default=sa.true()),
      sa.Column("status",sa.String(24),nullable=False,server_default="unverified"),
      sa.Column("config",sa.JSON(),nullable=False),
      sa.Column("secret",sa.Text(),nullable=True),
      sa.Column("last_verified_at",sa.DateTime(timezone=True),nullable=True),
      sa.Column("last_error",sa.Text(),nullable=True),
      sa.Column("created_by",sa.String(36),sa.ForeignKey("users.id",ondelete="SET NULL"),nullable=True),
      sa.Column("created_at",sa.DateTime(timezone=True),server_default=sa.func.now(),nullable=False),
      sa.Column("updated_at",sa.DateTime(timezone=True),server_default=sa.func.now(),nullable=False),
      sa.UniqueConstraint("workspace_id","provider",name="uq_integration_workspace_provider"))
    for c in ("workspace_id","provider","status"): op.create_index(f"ix_integrations_{c}","integrations",[c])
    op.create_table("integration_deliveries",
      sa.Column("id",sa.String(36),primary_key=True),
      sa.Column("workspace_id",sa.String(36),sa.ForeignKey("workspaces.id",ondelete="CASCADE"),nullable=False),
      sa.Column("integration_id",sa.String(36),sa.ForeignKey("integrations.id",ondelete="CASCADE"),nullable=False),
      sa.Column("finding_id",sa.String(36),sa.ForeignKey("findings.id",ondelete="SET NULL"),nullable=True),
      sa.Column("event_type",sa.String(64),nullable=False),
      sa.Column("status",sa.String(24),nullable=False),
      sa.Column("external_id",sa.String(255),nullable=True),
      sa.Column("external_url",sa.Text(),nullable=True),
      sa.Column("error",sa.Text(),nullable=True),
      sa.Column("created_at",sa.DateTime(timezone=True),server_default=sa.func.now(),nullable=False))
    for c in ("workspace_id","integration_id","finding_id","status","created_at"): op.create_index(f"ix_integration_deliveries_{c}","integration_deliveries",[c])
def downgrade():
    op.drop_table("integration_deliveries");op.drop_table("integrations")
