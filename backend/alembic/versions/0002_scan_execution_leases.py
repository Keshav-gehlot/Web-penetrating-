"""Add scan execution ownership and cancellation timestamps."""
from alembic import op
import sqlalchemy as sa

revision="0002_scan_execution_leases"
down_revision="0001_phantom_schema"
branch_labels=None
depends_on=None

def upgrade() -> None:
    bind=op.get_bind();inspector=sa.inspect(bind);columns={c["name"] for c in inspector.get_columns("scans")};indexes={i["name"] for i in inspector.get_indexes("scans")}
    additions=[("worker_id",sa.Column("worker_id",sa.String(160),nullable=True)),("lease_expires_at",sa.Column("lease_expires_at",sa.DateTime(timezone=True),nullable=True)),("cancel_requested_at",sa.Column("cancel_requested_at",sa.DateTime(timezone=True),nullable=True)),("cancelled_at",sa.Column("cancelled_at",sa.DateTime(timezone=True),nullable=True)),("attempt",sa.Column("attempt",sa.Integer(),nullable=False,server_default="1"))]
    for name,column in additions:
        if name not in columns:op.add_column("scans",column)
    if "ix_scans_worker_id" not in indexes:op.create_index("ix_scans_worker_id","scans",["worker_id"])
    if "ix_scans_lease_expires_at" not in indexes:op.create_index("ix_scans_lease_expires_at","scans",["lease_expires_at"])

def downgrade() -> None:
    bind=op.get_bind();inspector=sa.inspect(bind);indexes={i["name"] for i in inspector.get_indexes("scans")};columns={c["name"] for c in inspector.get_columns("scans")}
    for name in ("ix_scans_lease_expires_at","ix_scans_worker_id"):
        if name in indexes:op.drop_index(name,table_name="scans")
    for name in ("attempt","cancelled_at","cancel_requested_at","lease_expires_at","worker_id"):
        if name in columns:op.drop_column("scans",name)
