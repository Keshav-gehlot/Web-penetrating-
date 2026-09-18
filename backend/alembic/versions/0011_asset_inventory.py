"""expand asset inventory metadata

Revision ID: 0011_asset_inventory
Revises: 0010_workspace_scope
"""

from alembic import op
import sqlalchemy as sa

revision = "0011_asset_inventory"
down_revision = "0010_workspace_scope"


def upgrade():
    op.add_column("assets", sa.Column("addresses", sa.JSON(), nullable=True))
    op.add_column("assets", sa.Column("asset_type", sa.String(length=32), nullable=True))
    op.add_column("assets", sa.Column("environment", sa.String(length=32), nullable=True))
    op.add_column("assets", sa.Column("criticality", sa.String(length=16), nullable=True))
    op.add_column("assets", sa.Column("owner", sa.String(length=255), nullable=True))
    op.add_column("assets", sa.Column("tags", sa.JSON(), nullable=True))
    op.add_column("assets", sa.Column("notes", sa.Text(), nullable=True))
    op.add_column("assets", sa.Column("status", sa.String(length=16), nullable=True))
    op.add_column("assets", sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("assets", sa.Column("last_resolved_at", sa.DateTime(timezone=True), nullable=True))

    bind = op.get_bind()
    bind.execute(sa.text("UPDATE assets SET addresses = '[]', asset_type = 'web', environment = 'unknown', criticality = 'medium', tags = '[]', notes = '', status = 'active'"))

    for name, column in [
        ("ix_assets_asset_type", "asset_type"),
        ("ix_assets_environment", "environment"),
        ("ix_assets_criticality", "criticality"),
        ("ix_assets_owner", "owner"),
        ("ix_assets_status", "status"),
        ("ix_assets_last_seen_at", "last_seen_at"),
    ]:
        op.create_index(name, "assets", [column])

    for column in ["addresses", "asset_type", "environment", "criticality", "tags", "notes", "status"]:
        op.alter_column("assets", column, nullable=False)


def downgrade():
    for name in [
        "ix_assets_last_seen_at",
        "ix_assets_status",
        "ix_assets_owner",
        "ix_assets_criticality",
        "ix_assets_environment",
        "ix_assets_asset_type",
    ]:
        op.drop_index(name, table_name="assets")
    for column in [
        "last_resolved_at", "last_seen_at", "status", "notes", "tags",
        "owner", "criticality", "environment", "asset_type", "addresses",
    ]:
        op.drop_column("assets", column)
