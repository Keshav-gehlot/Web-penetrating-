"""add enterprise authentication hardening

Revision ID: 0015_auth_hardening
Revises: 0013_scope_approval
"""
from alembic import op
import sqlalchemy as sa
revision = "0015_auth_hardening"
down_revision = "0013_scope_approval"

def upgrade():
    op.add_column("users", sa.Column("email_verified", sa.Boolean(), nullable=False, server_default=sa.false()))
    op.add_column("users", sa.Column("failed_login_count", sa.Integer(), nullable=False, server_default="0"))
    op.add_column("users", sa.Column("locked_until", sa.DateTime(timezone=True), nullable=True))
    op.add_column("users", sa.Column("mfa_secret", sa.String(length=64), nullable=True))
    op.add_column("users", sa.Column("mfa_enabled", sa.Boolean(), nullable=False, server_default=sa.false()))
    op.create_table(
        "auth_sessions",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("user_id", sa.String(36), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("workspace_id", sa.String(36), sa.ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False),
        sa.Column("refresh_token_hash", sa.String(64), nullable=False, unique=True),
        sa.Column("access_token_id", sa.String(64), nullable=False, unique=True),
        sa.Column("user_agent", sa.String(512)),
        sa.Column("ip_address", sa.String(64)),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True)),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_index("ix_auth_sessions_user_id","auth_sessions",["user_id"])
    op.create_index("ix_auth_sessions_workspace_id","auth_sessions",["workspace_id"])
    op.create_index("ix_auth_sessions_expires_at","auth_sessions",["expires_at"])
    op.create_index("ix_auth_sessions_revoked_at","auth_sessions",["revoked_at"])
    op.create_table(
        "auth_invitations",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("workspace_id", sa.String(36), sa.ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False),
        sa.Column("email", sa.String(255), nullable=False),
        sa.Column("display_name", sa.String(120), nullable=False),
        sa.Column("role", sa.String(32), nullable=False),
        sa.Column("token_hash", sa.String(64), nullable=False, unique=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("accepted_at", sa.DateTime(timezone=True)),
        sa.Column("invited_by", sa.String(36), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_index("ix_auth_invitations_workspace_id","auth_invitations",["workspace_id"])
    op.create_index("ix_auth_invitations_email","auth_invitations",["email"])
    op.create_index("ix_auth_invitations_expires_at","auth_invitations",["expires_at"])
    op.create_table(
        "password_reset_tokens",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("user_id", sa.String(36), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("token_hash", sa.String(64), nullable=False, unique=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("used_at", sa.DateTime(timezone=True)),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_index("ix_password_reset_tokens_user_id","password_reset_tokens",["user_id"])
    op.create_index("ix_password_reset_tokens_expires_at","password_reset_tokens",["expires_at"])
    op.create_table(
        "email_verification_tokens",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("user_id", sa.String(36), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("token_hash", sa.String(64), nullable=False, unique=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("used_at", sa.DateTime(timezone=True)),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_index("ix_email_verification_tokens_user_id","email_verification_tokens",["user_id"])
    op.create_index("ix_email_verification_tokens_expires_at","email_verification_tokens",["expires_at"])

def downgrade():
    for n,t in [("ix_email_verification_tokens_expires_at","email_verification_tokens"),("ix_email_verification_tokens_user_id","email_verification_tokens"),("ix_password_reset_tokens_expires_at","password_reset_tokens"),("ix_password_reset_tokens_user_id","password_reset_tokens"),("ix_auth_invitations_expires_at","auth_invitations"),("ix_auth_invitations_email","auth_invitations"),("ix_auth_invitations_workspace_id","auth_invitations"),("ix_auth_sessions_revoked_at","auth_sessions"),("ix_auth_sessions_expires_at","auth_sessions"),("ix_auth_sessions_workspace_id","auth_sessions"),("ix_auth_sessions_user_id","auth_sessions")]:
        op.drop_index(n,table_name=t)
    op.drop_table("email_verification_tokens"); op.drop_table("password_reset_tokens"); op.drop_table("auth_invitations"); op.drop_table("auth_sessions")
    for n in ["mfa_enabled","mfa_secret","locked_until","failed_login_count","email_verified"]: op.drop_column("users",n)
