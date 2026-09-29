"""persist Net-Watch telemetry history and baselines

Revision ID: 0016_net_watch_history
Revises: 0015_auth_hardening
"""
from alembic import op
import sqlalchemy as sa

revision = "0016_net_watch_history"
down_revision = "0015_auth_hardening"

def upgrade():
    op.create_table("net_watch_baselines",
        sa.Column("id",sa.String(36),primary_key=True),
        sa.Column("workspace_id",sa.String(36),sa.ForeignKey("workspaces.id",ondelete="CASCADE"),nullable=False),
        sa.Column("metric",sa.String(80),nullable=False),
        sa.Column("value",sa.JSON(),nullable=False),
        sa.Column("sample_count",sa.Integer(),nullable=False,server_default="0"),
        sa.Column("updated_at",sa.DateTime(timezone=True),server_default=sa.func.now(),nullable=False),
        sa.UniqueConstraint("workspace_id","metric",name="uq_net_watch_baseline_metric"))
    op.create_index("ix_net_watch_baselines_workspace_id","net_watch_baselines",["workspace_id"])
    op.create_index("ix_net_watch_baselines_metric","net_watch_baselines",["metric"])
    op.create_table("net_watch_events",
        sa.Column("id",sa.String(36),primary_key=True),
        sa.Column("workspace_id",sa.String(36),sa.ForeignKey("workspaces.id",ondelete="CASCADE"),nullable=False),
        sa.Column("kind",sa.String(32),nullable=False),
        sa.Column("severity",sa.String(20),nullable=False,server_default="info"),
        sa.Column("summary",sa.Text(),nullable=False),
        sa.Column("explanation",sa.Text(),nullable=False,server_default=""),
        sa.Column("data",sa.JSON(),nullable=False),
        sa.Column("baseline",sa.JSON(),nullable=False),
        sa.Column("finding_id",sa.String(36),sa.ForeignKey("findings.id",ondelete="SET NULL"),nullable=True),
        sa.Column("acknowledged_at",sa.DateTime(timezone=True),nullable=True),
        sa.Column("acknowledged_by",sa.String(255),nullable=True),
        sa.Column("created_at",sa.DateTime(timezone=True),server_default=sa.func.now(),nullable=False))
    for col in ("workspace_id","kind","severity","finding_id","created_at"):
        op.create_index(f"ix_net_watch_events_{col}","net_watch_events",[col])

def downgrade():
    op.drop_table("net_watch_events")
    op.drop_table("net_watch_baselines")
