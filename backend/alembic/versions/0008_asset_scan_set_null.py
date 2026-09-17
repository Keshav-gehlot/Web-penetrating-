"""allow asset deletion without deleting scan history
Revision ID: 0008_asset_scan_set_null
Revises: 0007_finding_notes
"""
from alembic import op

revision = "0008_asset_scan_set_null"
down_revision = "0007_finding_notes"


def upgrade():
    with op.batch_alter_table("scans") as batch:
        batch.drop_constraint("scans_asset_id_fkey", type_="foreignkey")
        batch.create_foreign_key("scans_asset_id_fkey", "assets", ["asset_id"], ["id"], ondelete="SET NULL")


def downgrade():
    with op.batch_alter_table("scans") as batch:
        batch.drop_constraint("scans_asset_id_fkey", type_="foreignkey")
        batch.create_foreign_key("scans_asset_id_fkey", "assets", ["asset_id"], ["id"])
