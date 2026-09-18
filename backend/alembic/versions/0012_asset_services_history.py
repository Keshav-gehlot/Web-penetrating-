"""add asset service inventory and history

Revision ID: 0012_asset_services_history
Revises: 0011_asset_inventory
"""
from alembic import op
import sqlalchemy as sa

revision = "0012_asset_services_history"
down_revision = "0011_asset_inventory"

def upgrade():
    op.create_table(
        "asset_services",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("asset_id", sa.String(36), sa.ForeignKey("assets.id", ondelete="CASCADE"), nullable=False),
        sa.Column("port", sa.Integer(), nullable=False),
        sa.Column("protocol", sa.String(16), nullable=False, server_default="tcp"),
        sa.Column("service", sa.String(100)),
        sa.Column("state", sa.String(16), nullable=False, server_default="open"),
        sa.Column("source_scan_id", sa.String(36), sa.ForeignKey("scans.id", ondelete="SET NULL")),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.UniqueConstraint("asset_id", "port", "protocol", name="uq_asset_service_port"),
    )
    op.create_index("ix_asset_services_asset_id", "asset_services", ["asset_id"])
    op.create_index("ix_asset_services_source_scan_id", "asset_services", ["source_scan_id"])

    op.create_table(
        "asset_history",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("asset_id", sa.String(36), sa.ForeignKey("assets.id", ondelete="CASCADE"), nullable=False),
        sa.Column("workspace_id", sa.String(36), sa.ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False),
        sa.Column("scan_id", sa.String(36), sa.ForeignKey("scans.id", ondelete="SET NULL")),
        sa.Column("event_type", sa.String(64), nullable=False),
        sa.Column("metadata", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_index("ix_asset_history_asset_id", "asset_history", ["asset_id"])
    op.create_index("ix_asset_history_workspace_id", "asset_history", ["workspace_id"])
    op.create_index("ix_asset_history_scan_id", "asset_history", ["scan_id"])
    op.create_index("ix_asset_history_event_type", "asset_history", ["event_type"])
    op.create_index("ix_asset_history_created_at", "asset_history", ["created_at"])

def downgrade():
    for name, table in [
        ("ix_asset_history_created_at", "asset_history"), ("ix_asset_history_event_type", "asset_history"),
        ("ix_asset_history_scan_id", "asset_history"), ("ix_asset_history_workspace_id", "asset_history"),
        ("ix_asset_history_asset_id", "asset_history"), ("ix_asset_services_source_scan_id", "asset_services"),
        ("ix_asset_services_asset_id", "asset_services")]:
        op.drop_index(name, table_name=table)
    op.drop_table("asset_history")
    op.drop_table("asset_services")
