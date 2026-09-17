"""Add persistent workspace-scoped scheduled scans."""
from alembic import op
import sqlalchemy as sa

revision = "0004_schedules"
down_revision = "0003_audit_events"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if not inspector.has_table("schedules"):
        op.create_table(
            "schedules",
            sa.Column("id", sa.String(36), primary_key=True),
            sa.Column("workspace_id", sa.String(36), sa.ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False),
            sa.Column("created_by", sa.String(36), nullable=False),
            sa.Column("name", sa.String(160), nullable=False),
            sa.Column("target", sa.Text(), nullable=False),
            sa.Column("profile", sa.String(32), nullable=False, server_default="standard"),
            sa.Column("interval_seconds", sa.Integer(), nullable=False),
            sa.Column("next_run_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
            sa.Column("last_run_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        )
    indexes = {i["name"] for i in inspector.get_indexes("schedules")}
    for column in ("workspace_id", "created_by", "next_run_at", "enabled"):
        name = f"ix_schedules_{column}"
        if name not in indexes:
            op.create_index(name, "schedules", [column])


def downgrade() -> None:
    op.drop_table("schedules")
