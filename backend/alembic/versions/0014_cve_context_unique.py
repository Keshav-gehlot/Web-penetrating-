"""allow multiple product/version contexts for the same CVE

Revision ID: 0014_cve_context_unique
Revises: 0013_cve_intelligence
"""
from alembic import op
import sqlalchemy as sa

revision = "0014_cve_context_unique"
down_revision = "0013_cve_intelligence"


def upgrade():
    op.drop_constraint("cve_intelligence_cve_key", "cve_intelligence", type_="unique")
    op.create_unique_constraint("uq_cve_intelligence_context", "cve_intelligence", ["cve", "cpe", "version"])


def downgrade():
    op.drop_constraint("uq_cve_intelligence_context", "cve_intelligence", type_="unique")
    op.create_unique_constraint("cve_intelligence_cve_key", "cve_intelligence", ["cve"])
