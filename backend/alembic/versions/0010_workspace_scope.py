"""add explicit workspace assessment scope
Revision ID: 0010_workspace_scope
Revises: 0009_backfill_evidence_hashes
"""
from alembic import op
import sqlalchemy as sa

revision = "0010_workspace_scope"
down_revision = "0009_backfill_evidence_hashes"


def upgrade():
    op.create_table(
        "workspace_scopes",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("workspace_id", sa.String(length=36), nullable=False, unique=True),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("authorized_targets", sa.JSON(), nullable=False, server_default=sa.text("'[]'")),
        sa.Column("excluded_targets", sa.JSON(), nullable=False, server_default=sa.text("'[]'")),
        sa.Column("allowed_ports", sa.JSON(), nullable=False, server_default=sa.text("'[80, 443]'")),
        sa.Column("allowed_paths", sa.JSON(), nullable=False, server_default=sa.text("'[/]'")),
        sa.Column("blocked_paths", sa.JSON(), nullable=False, server_default=sa.text("'[]'")),
        sa.Column("max_requests", sa.Integer(), nullable=False, server_default="250"),
        sa.Column("max_concurrency", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("max_redirects", sa.Integer(), nullable=False, server_default="3"),
        sa.Column("authorization_acknowledged", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("authorization_acknowledged_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("acknowledged_by", sa.String(length=36), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.ForeignKeyConstraint(["workspace_id"], ["workspaces.id"], ondelete="CASCADE"),
    )
    op.create_index("ix_workspace_scopes_workspace_id", "workspace_scopes", ["workspace_id"], unique=True)
    op.create_index("ix_workspace_scopes_acknowledged_by", "workspace_scopes", ["acknowledged_by"])


def downgrade():
    op.drop_index("ix_workspace_scopes_acknowledged_by", table_name="workspace_scopes")
    op.drop_index("ix_workspace_scopes_workspace_id", table_name="workspace_scopes")
    op.drop_table("workspace_scopes")
