"""Create workspace-scoped audit event storage."""
from alembic import op
import sqlalchemy as sa

revision = "0003_audit_events"
down_revision = "0002_scan_execution_leases"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "audit_events",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("workspace_id", sa.String(36), sa.ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=True),
        sa.Column("actor", sa.String(255), nullable=False, server_default="system"),
        sa.Column("action", sa.String(100), nullable=False),
        sa.Column("resource_type", sa.String(100), nullable=False),
        sa.Column("resource_id", sa.String(255), nullable=True),
        sa.Column("metadata_json", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    for column in ("workspace_id", "action", "resource_type", "resource_id", "created_at"):
        op.create_index(f"ix_audit_events_{column}", "audit_events", [column])


def downgrade() -> None:
    for column in ("created_at", "resource_id", "resource_type", "action", "workspace_id"):
        op.drop_index(f"ix_audit_events_{column}", table_name="audit_events")
    op.drop_table("audit_events")
