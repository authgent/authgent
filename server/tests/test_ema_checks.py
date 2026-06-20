"""Tests for MCP-EMA-001..004 (Enterprise-Managed Authorization readiness).

EMA shipped 2026-06-18 backed by Anthropic / Microsoft / Okta. The
extension uses ID-JAG (Identity Assertion JWT Authorization Grant,
draft-ietf-oauth-identity-assertion-authz-grant). These four checks
flag whether an MCP authorization server is wired for EMA, and
specifically catch the launch-day pattern where vendors advertise
ID-JAG support while still advertising the OAuth-2.1-forbidden
``plain`` PKCE method (Asana, Canva).
"""

from __future__ import annotations

from authgent_server.scanner import (
    ID_JAG_GRANT_PROFILE,
    JWT_BEARER_GRANT,
    check_ema_id_jag_profile,
    check_ema_jwks_reachable,
    check_ema_jwt_bearer_grant,
    check_ema_pkce_strict_when_id_jag,
)

# ── MCP-EMA-001 ──────────────────────────────────────────────────────────


def test_ema_id_jag_absent_emits_advisory_finding():
    out = check_ema_id_jag_profile({})
    assert len(out) == 1
    assert out[0].check_id == "MCP-EMA-001"
    assert out[0].tier == "advisory"
    assert out[0].severity == "info"


def test_ema_id_jag_present_no_finding():
    meta = {
        "authorization_grant_profiles_supported": [ID_JAG_GRANT_PROFILE],
    }
    assert check_ema_id_jag_profile(meta) == []


def test_ema_id_jag_alongside_other_profiles_no_finding():
    meta = {
        "authorization_grant_profiles_supported": [
            "urn:ietf:params:oauth:grant-profile:other",
            ID_JAG_GRANT_PROFILE,
        ],
    }
    assert check_ema_id_jag_profile(meta) == []


# ── MCP-EMA-002 ──────────────────────────────────────────────────────────


def test_ema_jwt_bearer_check_only_runs_when_id_jag_advertised():
    """A non-EMA AS without jwt-bearer is fine; the check only fires
    when id-jag is declared without the underlying grant type."""
    meta = {"grant_types_supported": ["client_credentials"]}
    assert check_ema_jwt_bearer_grant(meta) == []


def test_ema_jwt_bearer_with_id_jag_advertised_no_finding():
    meta = {
        "authorization_grant_profiles_supported": [ID_JAG_GRANT_PROFILE],
        "grant_types_supported": [JWT_BEARER_GRANT, "authorization_code"],
    }
    assert check_ema_jwt_bearer_grant(meta) == []


def test_ema_id_jag_without_jwt_bearer_fires_warning():
    """Inconsistent metadata: claims EMA support but missing the
    actual grant type that ID-JAG profiles."""
    meta = {
        "authorization_grant_profiles_supported": [ID_JAG_GRANT_PROFILE],
        "grant_types_supported": ["authorization_code"],
    }
    out = check_ema_jwt_bearer_grant(meta)
    assert len(out) == 1
    assert out[0].check_id == "MCP-EMA-002"
    assert out[0].severity == "warning"


# ── MCP-EMA-003 ──────────────────────────────────────────────────────────


def test_ema_jwks_present_no_finding():
    meta = {"jwks_uri": "https://example/.well-known/jwks.json"}
    assert check_ema_jwks_reachable(meta) == []


def test_ema_jwks_missing_fires_advisory():
    out = check_ema_jwks_reachable({})
    assert len(out) == 1
    assert out[0].check_id == "MCP-EMA-003"
    assert out[0].tier == "advisory"


# ── MCP-EMA-004 ──────────────────────────────────────────────────────────


def test_ema_pkce_strict_only_runs_when_id_jag_advertised():
    """A non-EMA AS with weak PKCE is caught by MCP-PKCE-001 already;
    this check is for the *extra-bad* case of advertising EMA + weak
    PKCE simultaneously."""
    meta = {"code_challenge_methods_supported": ["plain", "S256"]}
    assert check_ema_pkce_strict_when_id_jag(meta) == []


def test_ema_pkce_strict_id_jag_with_s256_only_no_finding():
    meta = {
        "authorization_grant_profiles_supported": [ID_JAG_GRANT_PROFILE],
        "code_challenge_methods_supported": ["S256"],
    }
    assert check_ema_pkce_strict_when_id_jag(meta) == []


def test_ema_pkce_strict_id_jag_with_plain_fires_warning():
    """The Asana / Canva launch-day pattern: declares EMA support
    while advertising PKCE 'plain' in the same metadata document."""
    meta = {
        "authorization_grant_profiles_supported": [ID_JAG_GRANT_PROFILE],
        "code_challenge_methods_supported": ["plain", "S256"],
    }
    out = check_ema_pkce_strict_when_id_jag(meta)
    assert len(out) == 1
    assert out[0].check_id == "MCP-EMA-004"
    assert out[0].severity == "warning"


def test_ema_pkce_strict_id_jag_without_s256_fires_warning():
    """An EMA server that doesn't advertise S256 at all is also
    inconsistent; PKCE is OAuth-2.1-mandatory."""
    meta = {
        "authorization_grant_profiles_supported": [ID_JAG_GRANT_PROFILE],
        "code_challenge_methods_supported": ["plain"],
    }
    out = check_ema_pkce_strict_when_id_jag(meta)
    assert len(out) == 1
    assert out[0].check_id == "MCP-EMA-004"


# ── Tier classification ─────────────────────────────────────────────────


def test_all_ema_checks_are_advisory_tier():
    """EMA checks ship as advisory only; ID-JAG is a WG draft, EMA is
    an opt-in extension. Affecting the letter grade would penalise
    legacy IdPs that predate EMA."""
    meta = {
        "authorization_grant_profiles_supported": [ID_JAG_GRANT_PROFILE],
        "code_challenge_methods_supported": ["plain"],
        "grant_types_supported": ["authorization_code"],
    }
    findings = (
        check_ema_id_jag_profile({})
        + check_ema_jwt_bearer_grant(meta)
        + check_ema_jwks_reachable({})
        + check_ema_pkce_strict_when_id_jag(meta)
    )
    assert all(f.tier == "advisory" for f in findings)
