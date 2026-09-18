"""add controlled CVE intelligence and asset technology fingerprints

Revision ID: 0013_cve_intelligence
Revises: 0012_asset_services_history
"""
from alembic import op
import sqlalchemy as sa

revision = "0013_cve_intelligence"
down_revision = "0012_asset_services_history"


def upgrade():
    op.create_table(
        "asset_technologies",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("asset_id", sa.String(36), sa.ForeignKey("assets.id", ondelete="CASCADE"), nullable=False),
        sa.Column("vendor", sa.String(120)),
        sa.Column("product", sa.String(160), nullable=False),
        sa.Column("version", sa.String(120)),
        sa.Column("cpe", sa.String(255)),
        sa.Column("source", sa.String(64), nullable=False, server_default="scanner"),
        sa.Column("confidence", sa.Float(), nullable=False, server_default="0"),
        sa.Column("metadata_json", sa.JSON(), nullable=False, server_default="{}"),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.UniqueConstraint("asset_id", "product", "version", name="uq_asset_technology"),
    )
    for name, col in [
        ("ix_asset_technologies_asset_id", "asset_id"),
        ("ix_asset_technologies_vendor", "vendor"),
        ("ix_asset_technologies_product", "product"),
        ("ix_asset_technologies_version", "version"),
        ("ix_asset_technologies_cpe", "cpe"),
    ]:
        op.create_index(name, "asset_technologies", [col])

    op.create_table(
        "cve_intelligence",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("cve", sa.String(32), nullable=False, unique=True),
        sa.Column("cpe", sa.String(255), nullable=False),
        sa.Column("product", sa.String(160), nullable=False),
        sa.Column("version", sa.String(120), nullable=False),
        sa.Column("description", sa.Text(), nullable=False, server_default=""),
        sa.Column("severity", sa.String(20), nullable=False, server_default="info"),
        sa.Column("cvss", sa.Float()),
        sa.Column("cvss_v3_score", sa.Float()),
        sa.Column("cvss_v3_vector", sa.String(255)),
        sa.Column("cvss_v3_severity", sa.String(20)),
        sa.Column("cvss_v4_score", sa.Float()),
        sa.Column("cvss_v4_vector", sa.String(255)),
        sa.Column("cvss_v4_severity", sa.String(20)),
        sa.Column("published_at", sa.DateTime(timezone=True)),
        sa.Column("modified_at", sa.DateTime(timezone=True)),
        sa.Column("affected_versions", sa.JSON(), nullable=False, server_default="[]"),
        sa.Column("references", sa.JSON(), nullable=False, server_default="[]"),
        sa.Column("remediation", sa.Text(), nullable=False, server_default=""),
        sa.Column("source", sa.String(32), nullable=False, server_default="NVD"),
        sa.Column("fetched_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    for name, col in [
        ("ix_cve_intelligence_cve", "cve"),
        ("ix_cve_intelligence_cpe", "cpe"),
        ("ix_cve_intelligence_product", "product"),
        ("ix_cve_intelligence_version", "version"),
        ("ix_cve_intelligence_severity", "severity"),
    ]:
        op.create_index(name, "cve_intelligence", [col])

    for name, col in [
        ("product", "product"), ("version", "version"), ("cpe", "cpe"),
        ("cvss_v3_score", "cvss_v3_score"), ("cvss_v3_vector", "cvss_v3_vector"),
        ("cvss_v3_severity", "cvss_v3_severity"), ("cvss_v4_score", "cvss_v4_score"),
        ("cvss_v4_vector", "cvss_v4_vector"), ("cvss_v4_severity", "cvss_v4_severity"),
        ("cve_published_at", "cve_published_at"), ("cve_modified_at", "cve_modified_at"),
    ]:
        op.add_column("findings", sa.Column(col, sa.String(255) if "vector" in col else sa.Float() if "score" in col else sa.DateTime(timezone=True) if "at" in col else sa.String(160) if col == "product" else sa.String(120), nullable=True))
    op.add_column("findings", sa.Column("cve_affected_versions", sa.JSON(), nullable=False, server_default="[]"))
    op.add_column("findings", sa.Column("cve_references", sa.JSON(), nullable=False, server_default="[]"))


def downgrade():
    for col in ["cve_references", "cve_affected_versions", "cve_modified_at", "cve_published_at", "cvss_v4_severity", "cvss_v4_vector", "cvss_v4_score", "cvss_v3_severity", "cvss_v3_vector", "cvss_v3_score", "cpe", "version", "product"]:
        op.drop_column("findings", col)
    for name in ["ix_cve_intelligence_severity", "ix_cve_intelligence_version", "ix_cve_intelligence_product", "ix_cve_intelligence_cpe", "ix_cve_intelligence_cve"]:
        op.drop_index(name, table_name="cve_intelligence")
    op.drop_table("cve_intelligence")
    for name in ["ix_asset_technologies_cpe", "ix_asset_technologies_version", "ix_asset_technologies_product", "ix_asset_technologies_vendor", "ix_asset_technologies_asset_id"]:
        op.drop_index(name, table_name="asset_technologies")
    op.drop_table("asset_technologies")
