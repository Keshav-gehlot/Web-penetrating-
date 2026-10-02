"""secondary credential for authorization comparison
Revision ID: 0021_secondary_auth_comparison
Revises: 0020_assessment_credentials
"""
from alembic import op
import sqlalchemy as sa

revision = "0021_secondary_auth_comparison"
down_revision = "0020_assessment_credentials"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("scans", sa.Column("comparison_credential_id", sa.String(36), nullable=True))
    op.create_foreign_key(
        "fk_scans_comparison_credential_id",
        "scans",
        "assessment_credentials",
        ["comparison_credential_id"],
        ["id"],
        ondelete="SET NULL",
    )
    op.create_index(
        "ix_scans_comparison_credential_id",
        "scans",
        ["comparison_credential_id"],
    )


def downgrade():
    op.drop_index("ix_scans_comparison_credential_id", table_name="scans")
    op.drop_constraint(
        "fk_scans_comparison_credential_id",
        "scans",
        type_="foreignkey",
    )
    op.drop_column("scans", "comparison_credential_id")
