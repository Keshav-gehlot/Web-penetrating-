"""add explicit workspace scope approval workflow

Revision ID: 0013_scope_approval
Revises: 0014_cve_context_unique
"""

from alembic import op
import sqlalchemy as sa

revision = "0013_scope_approval"
down_revision = "0014_cve_context_unique"


def upgrade():
    op.add_column("workspace_scopes", sa.Column("approval_status", sa.String(length=16), nullable=False, server_default="pending"))
    op.add_column("workspace_scopes", sa.Column("approved_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("workspace_scopes", sa.Column("approved_by", sa.String(length=36), nullable=True))
    op.add_column("workspace_scopes", sa.Column("approval_comment", sa.Text(), nullable=True))
    op.create_index("ix_workspace_scopes_approved_by", "workspace_scopes", ["approved_by"])


def downgrade():
    op.drop_index("ix_workspace_scopes_approved_by", table_name="workspace_scopes")
    op.drop_column("workspace_scopes", "approval_comment")
    op.drop_column("workspace_scopes", "approved_by")
    op.drop_column("workspace_scopes", "approved_at")
    op.drop_column("workspace_scopes", "approval_status")
