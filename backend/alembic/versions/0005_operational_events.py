"""persistent operational events
Revision ID: 0005_operational_events
Revises: 0004_schedules
"""
from alembic import op
import sqlalchemy as sa
revision="0005_operational_events"
down_revision="0004_schedules"

def upgrade():
    op.create_table("operational_events",
        sa.Column("id",sa.String(36),primary_key=True),
        sa.Column("workspace_id",sa.String(36),sa.ForeignKey("workspaces.id",ondelete="CASCADE"),nullable=True,index=True),
        sa.Column("scan_id",sa.String(36),sa.ForeignKey("scans.id",ondelete="SET NULL"),nullable=True,index=True),
        sa.Column("event_type",sa.String(64),nullable=False,index=True),
        sa.Column("severity",sa.String(16),nullable=False,server_default="info",index=True),
        sa.Column("message",sa.Text(),nullable=False),
        sa.Column("metadata",sa.JSON(),nullable=False,server_default="{}"),
        sa.Column("created_at",sa.DateTime(timezone=True),server_default=sa.func.now(),nullable=False,index=True),
    )

def downgrade():
    op.drop_table("operational_events")
