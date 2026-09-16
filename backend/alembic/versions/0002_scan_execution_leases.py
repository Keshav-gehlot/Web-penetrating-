"""Add scan execution ownership and cancellation timestamps."""
from alembic import op
import sqlalchemy as sa

revision = "0002_scan_execution_leases"
down_revision = "0001_phantom_schema"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("scans", sa.Column("worker_id", sa.String(160), nullable=True))
    op.add_column("scans", sa.Column("lease_expires_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("scans", sa.Column("cancel_requested_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("scans", sa.Column("cancelled_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("scans", sa.Column("attempt", sa.Integer(), nullable=False, server_default="1"))
    op.create_index("ix_scans_worker_id", "scans", ["worker_id"])
    op.create_index("ix_scans_lease_expires_at", "scans", ["lease_expires_at"])


def downgrade() -> None:
    op.drop_index("ix_scans_lease_expires_at", table_name="scans")
    op.drop_index("ix_scans_worker_id", table_name="scans")
    op.drop_column("scans", "attempt")
    op.drop_column("scans", "cancelled_at")
    op.drop_column("scans", "cancel_requested_at")
    op.drop_column("scans", "lease_expires_at")
    op.drop_column("scans", "worker_id")
