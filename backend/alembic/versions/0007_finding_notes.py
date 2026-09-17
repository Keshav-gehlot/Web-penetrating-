"""store analyst notes outside immutable scanner evidence
Revision ID: 0007_finding_notes
Revises: 0006_finding_evidence_provenance
"""
from alembic import op
import sqlalchemy as sa

revision = "0007_finding_notes"
down_revision = "0006_finding_evidence_provenance"


def upgrade():
    op.create_table(
        "finding_notes",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("finding_id", sa.String(36), sa.ForeignKey("findings.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("workspace_id", sa.String(36), sa.ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("author_id", sa.String(36), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True),
        sa.Column("note", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )


def downgrade():
    op.drop_table("finding_notes")
