"""Initial schema — all authgent tables.

Revision ID: 001
Revises:
Create Date: 2025-01-01 00:00:00.000000
"""

import sqlalchemy as sa
from alembic import op

revision = "001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    # --- signing_keys ---
    op.create_table(
        "signing_keys",
        sa.Column("kid", sa.String(255), primary_key=True),
        sa.Column("algorithm", sa.String(10), server_default="ES256", nullable=False),
        sa.Column("private_key_pem", sa.Text, nullable=False),
        sa.Column("public_key_jwk", sa.JSON, nullable=False),
        sa.Column("status", sa.String(20), server_default="active", nullable=False),
        sa.Column("created_at", sa.DateTime, nullable=False),
        sa.Column("rotated_at", sa.DateTime, nullable=True),
    )

    # --- agents ---
    op.create_table(
        "agents",
        sa.Column("id", sa.String(26), primary_key=True),
        sa.Column("oauth_client_id", sa.String(255), unique=True, nullable=True),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("description", sa.Text, nullable=True),
        sa.Column("owner", sa.String(255), nullable=True),
        sa.Column("allowed_scopes", sa.JSON, nullable=True),
        sa.Column("capabilities", sa.JSON, nullable=True),
        sa.Column("allowed_exchange_targets", sa.JSON, nullable=True),
        sa.Column("status", sa.String(20), server_default="active", nullable=False),
        sa.Column("metadata", sa.JSON, nullable=True),
        sa.Column("agent_type", sa.String(50), nullable=True),
        sa.Column("agent_model", sa.String(255), nullable=True),
        sa.Column("agent_version", sa.String(50), nullable=True),
        sa.Column("agent_provider", sa.String(255), nullable=True),
        sa.Column("bill_of_materials", sa.JSON, nullable=True),
        sa.Column("attestation_level", sa.String(20), nullable=True),
        sa.Column("code_hash", sa.String(255), nullable=True),
        sa.Column("created_at", sa.DateTime, nullable=False),
        sa.Column("updated_at", sa.DateTime, nullable=False),
    )

    # --- oauth_clients ---
    op.create_table(
        "oauth_clients",
        sa.Column("client_id", sa.String(255), primary_key=True),
        sa.Column("client_secret_hash", sa.String(512), nullable=False),
        sa.Column("previous_secret_hash", sa.String(512), nullable=True),
        sa.Column("previous_secret_expires", sa.DateTime, nullable=True),
        sa.Column("client_name", sa.String(255), nullable=True),
        sa.Column("grant_types", sa.JSON, nullable=True),
        sa.Column("redirect_uris", sa.JSON, nullable=True),
        sa.Column("scope", sa.Text, nullable=True),
        sa.Column("allowed_resources", sa.JSON, nullable=True),
        sa.Column("may_act_subs", sa.JSON, nullable=True),
        sa.Column("metadata_url", sa.Text, nullable=True),
        sa.Column("token_endpoint_auth_method", sa.String(50), server_default="client_secret_post"),
        sa.Column("dpop_bound_access_tokens", sa.Boolean, server_default="false", nullable=False),
        sa.Column("agent_id", sa.String(26), sa.ForeignKey("agents.id"), nullable=True),
        sa.Column("created_at", sa.DateTime, nullable=False),
    )

    # --- authorization_codes ---
    op.create_table(
        "authorization_codes",
        sa.Column("code", sa.String(255), primary_key=True),
        sa.Column("client_id", sa.String(255), sa.ForeignKey("oauth_clients.client_id"), nullable=False),
        sa.Column("redirect_uri", sa.Text, nullable=False),
        sa.Column("scope", sa.Text, nullable=True),
        sa.Column("resource", sa.Text, nullable=True),
        sa.Column("code_challenge", sa.String(255), nullable=False),
        sa.Column("code_challenge_method", sa.String(10), server_default="S256", nullable=False),
        sa.Column("subject", sa.String(255), nullable=True),
        sa.Column("nonce", sa.String(255), nullable=True),
        sa.Column("expires_at", sa.DateTime, nullable=False),
        sa.Column("used", sa.Boolean, server_default="false", nullable=False),
    )

    # --- refresh_tokens ---
    op.create_table(
        "refresh_tokens",
        sa.Column("jti", sa.String(255), primary_key=True),
        sa.Column("client_id", sa.String(255), sa.ForeignKey("oauth_clients.client_id"), nullable=False),
        sa.Column("subject", sa.String(255), nullable=True),
        sa.Column("scope", sa.Text, nullable=True),
        sa.Column("resource", sa.Text, nullable=True),
        sa.Column("family_id", sa.String(255), nullable=False),
        sa.Column("dpop_jkt", sa.String(255), nullable=True),
        sa.Column("used", sa.Boolean, server_default="false", nullable=False),
        sa.Column("expires_at", sa.DateTime, nullable=False),
        sa.Column("created_at", sa.DateTime, nullable=False),
    )
    op.create_index("ix_refresh_tokens_family_id", "refresh_tokens", ["family_id"])

    # --- device_codes ---
    op.create_table(
        "device_codes",
        sa.Column("device_code", sa.String(255), primary_key=True),
        sa.Column("user_code", sa.String(20), unique=True, nullable=False),
        sa.Column("client_id", sa.String(255), sa.ForeignKey("oauth_clients.client_id"), nullable=False),
        sa.Column("scope", sa.Text, nullable=True),
        sa.Column("resource", sa.Text, nullable=True),
        sa.Column("status", sa.String(20), server_default="pending", nullable=False),
        sa.Column("subject", sa.String(255), nullable=True),
        sa.Column("interval", sa.Integer, server_default="5", nullable=False),
        sa.Column("expires_at", sa.DateTime, nullable=False),
        sa.Column("created_at", sa.DateTime, nullable=False),
    )

    # --- consents ---
    op.create_table(
        "consents",
        sa.Column("id", sa.String(26), primary_key=True),
        sa.Column("subject", sa.String(255), nullable=False),
        sa.Column("client_id", sa.String(255), sa.ForeignKey("oauth_clients.client_id"), nullable=False),
        sa.Column("scope", sa.Text, nullable=False),
        sa.Column("resource", sa.Text, nullable=True),
        sa.Column("granted_at", sa.DateTime, nullable=False),
        sa.Column("expires_at", sa.DateTime, nullable=True),
        sa.UniqueConstraint("subject", "client_id", "resource", name="uq_consent_subject_client_resource"),
    )

    # --- token_blocklist ---
    op.create_table(
        "token_blocklist",
        sa.Column("jti", sa.String(255), primary_key=True),
        sa.Column("expires_at", sa.DateTime, nullable=False),
        sa.Column("revoked_at", sa.DateTime, nullable=False),
        sa.Column("reason", sa.String(50), nullable=True),
    )
    op.create_index("ix_token_blocklist_expires_at", "token_blocklist", ["expires_at"])

    # --- audit_log ---
    op.create_table(
        "audit_log",
        sa.Column("id", sa.String(26), primary_key=True),
        sa.Column("timestamp", sa.DateTime, nullable=False),
        sa.Column("action", sa.String(50), nullable=False),
        sa.Column("actor", sa.String(255), nullable=True),
        sa.Column("subject", sa.String(255), nullable=True),
        sa.Column("client_id", sa.String(255), nullable=True),
        sa.Column("ip_address", sa.String(45), nullable=True),
        sa.Column("trace_id", sa.String(64), nullable=True),
        sa.Column("span_id", sa.String(32), nullable=True),
        sa.Column("metadata", sa.JSON, nullable=True),
    )
    op.create_index("ix_audit_log_action", "audit_log", ["action"])
    op.create_index("ix_audit_log_timestamp", "audit_log", ["timestamp"])

    # --- delegation_receipts ---
    op.create_table(
        "delegation_receipts",
        sa.Column("id", sa.String(26), primary_key=True),
        sa.Column("token_jti", sa.String(255), nullable=False),
        sa.Column("parent_token_jti", sa.String(255), nullable=False),
        sa.Column("actor_id", sa.String(255), nullable=False),
        sa.Column("receipt_jwt", sa.Text, nullable=False),
        sa.Column("chain_hash", sa.String(255), nullable=False),
        sa.Column("created_at", sa.DateTime, nullable=False),
    )
    op.create_index("ix_delegation_receipts_token_jti", "delegation_receipts", ["token_jti"])

    # --- stepup_requests ---
    op.create_table(
        "stepup_requests",
        sa.Column("id", sa.String(26), primary_key=True),
        sa.Column("agent_id", sa.String(255), nullable=False),
        sa.Column("action", sa.String(255), nullable=False),
        sa.Column("scope", sa.Text, nullable=False),
        sa.Column("resource", sa.String(255), nullable=True),
        sa.Column("delegation_chain_snapshot", sa.JSON, nullable=True),
        sa.Column("status", sa.String(20), server_default="pending", nullable=False),
        sa.Column("approved_by", sa.String(255), nullable=True),
        sa.Column("approved_at", sa.DateTime, nullable=True),
        sa.Column("expires_at", sa.DateTime, nullable=False),
        sa.Column("metadata", sa.JSON, nullable=True),
        sa.Column("created_at", sa.DateTime, nullable=False),
    )

    # --- users ---
    op.create_table(
        "users",
        sa.Column("id", sa.String(26), primary_key=True),
        sa.Column("username", sa.String(255), unique=True, nullable=False),
        sa.Column("password_hash", sa.String(512), nullable=False),
        sa.Column("email", sa.String(255), nullable=True),
        sa.Column("status", sa.String(20), server_default="active", nullable=False),
        sa.Column("failed_attempts", sa.Integer, server_default="0", nullable=False),
        sa.Column("locked_until", sa.DateTime, nullable=True),
        sa.Column("created_at", sa.DateTime, nullable=False),
        sa.Column("updated_at", sa.DateTime, nullable=False),
    )


def downgrade() -> None:
    op.drop_table("users")
    op.drop_table("stepup_requests")
    op.drop_index("ix_delegation_receipts_token_jti", table_name="delegation_receipts")
    op.drop_table("delegation_receipts")
    op.drop_index("ix_audit_log_timestamp", table_name="audit_log")
    op.drop_index("ix_audit_log_action", table_name="audit_log")
    op.drop_table("audit_log")
    op.drop_index("ix_token_blocklist_expires_at", table_name="token_blocklist")
    op.drop_table("token_blocklist")
    op.drop_table("consents")
    op.drop_table("device_codes")
    op.drop_index("ix_refresh_tokens_family_id", table_name="refresh_tokens")
    op.drop_table("refresh_tokens")
    op.drop_table("authorization_codes")
    op.drop_table("oauth_clients")
    op.drop_table("agents")
    op.drop_table("signing_keys")
