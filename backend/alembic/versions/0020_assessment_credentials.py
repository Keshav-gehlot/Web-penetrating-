"""assessment credentials
Revision ID: 0020_assessment_credentials
Revises: 0019_history_retention
"""
from alembic import op
import sqlalchemy as sa
revision = "0020_assessment_credentials"
down_revision = "0019_history_retention"
branch_labels = None
depends_on = None

def upgrade():
    op.create_table("assessment_credentials",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("workspace_id", sa.String(36), sa.ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False),
        sa.Column("name", sa.String(120), nullable=False),
        sa.Column("kind", sa.String(32), nullable=False),
        sa.Column("username", sa.String(255), nullable=True),
        sa.Column("header_name", sa.String(64), nullable=True),
        sa.Column("secret_ciphertext", sa.Text(), nullable=False),
        sa.Column("created_by", sa.String(36), sa.ForeignKey("users.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=True),
        sa.UniqueConstraint("workspace_id", "name", name="uq_assessment_credential_workspace_name"))
    op.create_index("ix_assessment_credentials_workspace_id", "assessment_credentials", ["workspace_id"])
    op.create_index("ix_assessment_credentials_created_by", "assessment_credentials", ["created_by"])
    op.create_index("ix_assessment_credentials_last_used_at", "assessment_credentials", ["last_used_at"])
    op.add_column("scans", sa.Column("credential_id", sa.String(36), nullable=True))
    op.create_foreign_key("fk_scans_credential_id", "scans", "assessment_credentials", ["credential_id"], ["id"], ondelete="SET NULL")
    op.create_index("ix_scans_credential_id", "scans", ["credential_id"])

def downgrade():
    op.drop_index("ix_scans_credential_id", table_name="scans")
    op.drop_constraint("fk_scans_credential_id", "scans", type_="foreignkey")
    op.drop_column("scans", "credential_id")
    op.drop_index("ix_assessment_credentials_last_used_at", table_name="assessment_credentials")
    op.drop_index("ix_assessment_credentials_created_by", table_name="assessment_credentials")
    op.drop_index("ix_assessment_credentials_workspace_id", table_name="assessment_credentials")
    op.drop_table("assessment_credentials")
