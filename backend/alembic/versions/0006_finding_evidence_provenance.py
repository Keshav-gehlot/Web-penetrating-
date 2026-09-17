"""persist finding evidence provenance
Revision ID: 0006_finding_evidence_provenance
Revises: 0005_operational_events
"""
from alembic import op
import sqlalchemy as sa
revision="0006_finding_evidence_provenance"
down_revision="0005_operational_events"

def upgrade():
    op.add_column("findings", sa.Column("evidence_hash", sa.String(64), nullable=False, server_default=""))
    op.add_column("findings", sa.Column("evidence_collected_at", sa.DateTime(timezone=True), nullable=True, server_default=sa.func.now()))
    op.add_column("findings", sa.Column("evidence_source", sa.String(64), nullable=False, server_default="scanner"))
    op.alter_column("findings", "evidence_collected_at", nullable=False)

def downgrade():
    op.drop_column("findings", "evidence_source")
    op.drop_column("findings", "evidence_collected_at")
    op.drop_column("findings", "evidence_hash")
