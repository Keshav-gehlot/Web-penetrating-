"""persistent report system
Revision ID: 0017_report_system
Revises: 0016_net_watch_history
"""
from alembic import op
import sqlalchemy as sa
revision="0017_report_system"
down_revision="0016_net_watch_history"
def upgrade():
    op.create_table("reports",
      sa.Column("id",sa.String(36),primary_key=True),sa.Column("workspace_id",sa.String(36),sa.ForeignKey("workspaces.id",ondelete="CASCADE"),nullable=False),
      sa.Column("scan_id",sa.String(36),sa.ForeignKey("scans.id",ondelete="CASCADE"),nullable=False),sa.Column("created_by",sa.String(36),sa.ForeignKey("users.id",ondelete="SET NULL"),nullable=True),
      sa.Column("title",sa.String(240),nullable=False),sa.Column("template",sa.String(32),nullable=False,server_default="technical"),sa.Column("status",sa.String(24),nullable=False,server_default="draft"),
      sa.Column("metadata_json",sa.JSON(),nullable=False),sa.Column("branding",sa.JSON(),nullable=False),sa.Column("sections",sa.JSON(),nullable=False),sa.Column("finding_ids",sa.JSON(),nullable=False),
      sa.Column("include_evidence",sa.Boolean(),nullable=False,server_default=sa.true()),sa.Column("current_version",sa.Integer(),nullable=False,server_default="1"),
      sa.Column("created_at",sa.DateTime(timezone=True),server_default=sa.func.now(),nullable=False),sa.Column("updated_at",sa.DateTime(timezone=True),server_default=sa.func.now(),nullable=False))
    for c in ("workspace_id","scan_id","created_by","template","status","created_at"): op.create_index(f"ix_reports_{c}","reports",[c])
    op.create_table("report_versions",sa.Column("id",sa.String(36),primary_key=True),sa.Column("report_id",sa.String(36),sa.ForeignKey("reports.id",ondelete="CASCADE"),nullable=False),sa.Column("version",sa.Integer(),nullable=False),sa.Column("snapshot",sa.JSON(),nullable=False),sa.Column("created_by",sa.String(36),sa.ForeignKey("users.id",ondelete="SET NULL"),nullable=True),sa.Column("created_at",sa.DateTime(timezone=True),server_default=sa.func.now(),nullable=False),sa.UniqueConstraint("report_id","version",name="uq_report_version"))
    op.create_index("ix_report_versions_report_id","report_versions",["report_id"]);op.create_index("ix_report_versions_created_at","report_versions",["created_at"])
    op.create_table("report_downloads",sa.Column("id",sa.String(36),primary_key=True),sa.Column("report_id",sa.String(36),sa.ForeignKey("reports.id",ondelete="CASCADE"),nullable=False),sa.Column("version",sa.Integer(),nullable=False),sa.Column("format",sa.String(12),nullable=False),sa.Column("downloaded_by",sa.String(36),sa.ForeignKey("users.id",ondelete="SET NULL"),nullable=True),sa.Column("downloaded_at",sa.DateTime(timezone=True),server_default=sa.func.now(),nullable=False))
    for c in ("report_id","format","downloaded_by","downloaded_at"): op.create_index(f"ix_report_downloads_{c}","report_downloads",[c])
def downgrade():
    op.drop_table("report_downloads");op.drop_table("report_versions");op.drop_table("reports")
