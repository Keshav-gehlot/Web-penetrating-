"""history and retention
Revision ID: 0019_history_retention
Revises: 0018_integrations
"""
from alembic import op
import sqlalchemy as sa
revision="0019_history_retention";down_revision="0018_integrations"
def upgrade():
 op.create_table("finding_history",
  sa.Column("id",sa.String(36),primary_key=True),sa.Column("finding_id",sa.String(36),sa.ForeignKey("findings.id",ondelete="CASCADE"),nullable=False),
  sa.Column("workspace_id",sa.String(36),sa.ForeignKey("workspaces.id",ondelete="CASCADE"),nullable=False),
  sa.Column("event_type",sa.String(64),nullable=False),sa.Column("snapshot",sa.JSON(),nullable=False),
  sa.Column("actor_id",sa.String(36),sa.ForeignKey("users.id",ondelete="SET NULL"),nullable=True),sa.Column("created_at",sa.DateTime(timezone=True),server_default=sa.func.now(),nullable=False))
 for c in ("finding_id","workspace_id","event_type","created_at"):op.create_index(f"ix_finding_history_{c}","finding_history",[c])
 op.create_table("scan_history",
  sa.Column("id",sa.String(36),primary_key=True),sa.Column("scan_id",sa.String(36),sa.ForeignKey("scans.id",ondelete="CASCADE"),nullable=False),
  sa.Column("workspace_id",sa.String(36),sa.ForeignKey("workspaces.id",ondelete="CASCADE"),nullable=False),
  sa.Column("event_type",sa.String(64),nullable=False),sa.Column("snapshot",sa.JSON(),nullable=False),
  sa.Column("created_at",sa.DateTime(timezone=True),server_default=sa.func.now(),nullable=False))
 for c in ("scan_id","workspace_id","event_type","created_at"):op.create_index(f"ix_scan_history_{c}","scan_history",[c])
 op.create_index("ix_scans_workspace_created","scans",["workspace_id","created_at"])
 op.create_index("ix_findings_scan_severity_status","findings",["scan_id","severity","status"])
 op.create_index("ix_operational_workspace_created","operational_events",["workspace_id","created_at"])
 op.create_index("ix_audit_workspace_created","audit_events",["workspace_id","created_at"])
def downgrade():
 for n,t in [("ix_audit_workspace_created","audit_events"),("ix_operational_workspace_created","operational_events"),("ix_findings_scan_severity_status","findings"),("ix_scans_workspace_created","scans")]:op.drop_index(n,table_name=t)
 op.drop_table("scan_history");op.drop_table("finding_history")
