"""Pydantic Settings — all config via AUTHGENT_* environment variables."""

from __future__ import annotations

import secrets
from functools import cached_property
from typing import Literal

from pydantic import AliasChoices, Field
from pydantic_settings import BaseSettings, SettingsConfigDict

from authgent_server.crypto import derive_subkey


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="AUTHGENT_",
        env_file=".env",
        env_file_encoding="utf-8",
    )

    # Core
    secret_key: str = Field(default_factory=lambda: secrets.token_hex(32))
    database_url: str = "sqlite+aiosqlite:///./authgent.db"
    host: str = "0.0.0.0"
    port: int = 8000
    debug: bool = False
    server_url: str = "http://localhost:8000"

    # Token TTLs
    access_token_ttl: int = 900
    refresh_token_ttl: int = 86400
    exchange_token_ttl: int = 300
    authorization_code_ttl: int = 600
    client_credentials_ttl: int | None = None
    auth_code_access_ttl: int | None = None

    # Crypto
    signing_algorithm: str = "ES256"
    jwks_rotation_days: int = 90
    jwks_auto_rotate: bool = True

    # Policy
    registration_policy: Literal["open", "token", "admin"] = "open"
    registration_token: str | None = None  # RFC 7591 initial_access_token for policy=token
    consent_mode: Literal["ui", "headless", "auto_approve"] = "auto_approve"
    max_delegation_depth: int = 5
    delegation_scope_reduction: bool = True
    require_dpop: bool = False
    dpop_chain_policy: Literal["strict", "audit", "permissive"] = "strict"

    # Provider failure timeout
    provider_timeout: int = 10

    # RFC 8707 resource matching
    resource_match: Literal["exact", "origin"] = "exact"

    # Security
    cors_origins: list[str] = Field(default_factory=list)
    hitl_timeout: int = 300
    hitl_scopes: list[str] = Field(default_factory=list)

    # Rate limiting
    token_rate_limit: int = 100
    register_rate_limit: int = 10
    # Per-IP per-minute caps on the public scanner endpoints. The scanner
    # makes outbound HTTP, so an unrate-limited /api/scan endpoint is the
    # easiest way to saturate the event loop with slow targets. Badge
    # endpoint is cheaper (cached SVG) so it gets a higher cap to keep
    # README-embedded badges responsive.
    scan_rate_limit: int = 30
    badge_rate_limit: int = 120

    # Optional shared cache for multi-worker / multi-replica deployments.
    # When set, scanner caches use Redis. When unset, scanner caches
    # fall back to in-process dicts (fine for single-worker dev / CI).
    # Reads AUTHGENT_REDIS_URL first, then plain REDIS_URL so the
    # standard 12-factor convention used by the deploy infrastructure
    # works without an extra alias step.
    redis_url: str | None = Field(
        default=None,
        validation_alias=AliasChoices("AUTHGENT_REDIS_URL", "REDIS_URL"),
    )
    # Default TTL for shared scan-result entries. Same value the in-process
    # registry cache uses today (1 hour). Tunable for ops.
    scan_cache_ttl_seconds: int = 3600

    # Public-demo housekeeping. When true, the cleanup loop also prunes
    # OAuth clients older than `demo_client_retention_seconds` whose
    # client_name matches one of the well-known demo / probe patterns
    # (audit-test, lint-probe, registration-tester, etc). Production
    # deployments (where every registered client is a real customer)
    # MUST leave this off. Default off so a misread env var never
    # destroys real client records.
    demo_cleanup_enabled: bool = False
    demo_client_retention_seconds: int = 86400  # 24h

    # Webhook delivery (HITL step-up notifications)
    webhook_url: str | None = None
    webhook_hmac_secret: str | None = None
    webhook_retries: int = 3
    webhook_backoff: str = "1,5,30"

    # CAEP (OpenID Continuous Access Evaluation Profile 1.0) SET push delivery.
    # Prototype scope: session-revoked events only, delivered via a fixed,
    # comma-separated receiver list (RFC 8935 push semantics). This is NOT a
    # full SSF stream-management implementation — no registration API, no
    # poll-based delivery, no per-stream aud negotiation. See
    # docs/security-advisories/2026-08-caep-transmitter-prototype.md.
    caep_receiver_urls: str | None = None
    caep_hmac_secret: str | None = None
    caep_retries: int = 3
    caep_backoff: str = "1,5,30"
    caep_timeout: float = 10.0
    # Scope required to call POST /security/tokens/compromise. Always
    # enforced (unlike registration_policy, this is not switchable to "open")
    # because compromise-flagging both blocklists a token and pushes an
    # external notification — a materially more consequential action than
    # routine client self-revocation.
    caep_operator_scope: str = "admin:security"

    @property
    def caep_receiver_url_list(self) -> list[str]:
        """Parsed, whitespace-trimmed receiver URL list."""
        if not self.caep_receiver_urls:
            return []
        return [u.strip() for u in self.caep_receiver_urls.split(",") if u.strip()]

    # Advertised scopes for discovery metadata (RFC 8414)
    scopes_supported: list[str] = Field(default_factory=list)

    # Scope mappings for cross-audience token exchange
    scope_mappings: str | None = None

    # Custom grant type handlers
    custom_grant_handlers: dict[str, str] | None = None

    # Human auth mode
    human_auth_mode: Literal["builtin", "external_oidc", "api_key"] = "builtin"

    # External OIDC trust for id_token exchange (§4.7)
    trusted_oidc_issuers: list[str] = Field(default_factory=list)
    trusted_oidc_audience: str | None = None

    # Identity Chaining Across Domains (draft-ietf-oauth-identity-chaining-14)
    # When this server acts as Domain A: ASes we are allowed to mint chaining grants for
    trusted_chaining_targets: list[str] = Field(default_factory=list)
    # When this server acts as Domain B: ASes whose chaining grants we accept
    trusted_chaining_issuers: list[str] = Field(default_factory=list)
    # Short-lived per §5.5; default 60s
    chaining_grant_ttl: int = 60
    # "preserve_sub" copies parent sub through; "minimize" only carries idp_iss/idp_sub
    chaining_claims_policy: Literal["preserve_sub", "minimize"] = "preserve_sub"

    # Transaction Tokens (draft-ietf-oauth-transaction-tokens-08)
    # Trust Domain identifier emitted in the `aud` claim of issued Txn-Tokens.
    # If empty, defaults to server_url at issuance time.
    txn_token_trust_domain: str | None = None
    # Spec §7: tokens are short-lived "on the order of minutes or less". Default 120s.
    txn_token_ttl: int = 120

    # Providers (dotted import paths, None = use default)
    attestation_provider: str | None = None
    policy_provider: str | None = None
    hitl_provider: str | None = None
    key_provider: str | None = None
    event_emitter: str | None = None
    claim_enricher: str | None = None

    @cached_property
    def _master_key(self) -> bytes:
        return self.secret_key.encode()

    @cached_property
    def _dpop_key(self) -> bytes:
        return derive_subkey(self._master_key, "dpop-nonce")

    @cached_property
    def _csrf_key(self) -> bytes:
        return derive_subkey(self._master_key, "csrf")

    @cached_property
    def _session_key(self) -> bytes:
        return derive_subkey(self._master_key, "session")

    @cached_property
    def _kek_key(self) -> bytes:
        """Key-encryption-key for signing_keys at rest."""
        return derive_subkey(self._master_key, "kek")


_settings: Settings | None = None


def get_settings() -> Settings:
    global _settings
    if _settings is None:
        _settings = Settings()
    return _settings


def reset_settings() -> None:
    """Reset cached settings — for testing only."""
    global _settings
    _settings = None
