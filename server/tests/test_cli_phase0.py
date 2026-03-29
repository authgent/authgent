"""Tests for Phase 0 CLI commands — list-agents, get-token, inspect-token, audit, status."""

from __future__ import annotations

import base64
import json
import os
from datetime import UTC, datetime

import pytest
from typer.testing import CliRunner

# Set test env vars before importing CLI
os.environ["AUTHGENT_SECRET_KEY"] = (
    "test-secret-key-for-unit-tests-only-64chars-long-padding-here!!"
)
os.environ["AUTHGENT_DATABASE_URL"] = "sqlite+aiosqlite:///:memory:"
os.environ["AUTHGENT_CONSENT_MODE"] = "auto_approve"
os.environ["AUTHGENT_REGISTRATION_POLICY"] = "open"
os.environ["AUTHGENT_SERVER_URL"] = "http://localhost:8000"

from authgent_server.cli import (
    _build_delegation_tree,
    _decode_jwt_claims,
    _relative_time,
    app,
)

runner = CliRunner()


# ── Helper function tests ────────────────────────────────────────────────


class TestDecodeJWTClaims:
    """Test JWT payload decoding (no verification)."""

    def test_valid_jwt(self) -> None:
        header = base64.urlsafe_b64encode(b'{"alg":"ES256","typ":"JWT"}').rstrip(b"=")
        payload = base64.urlsafe_b64encode(
            json.dumps(
                {"sub": "client:test", "scope": "read", "iss": "http://localhost:8000"}
            ).encode()
        ).rstrip(b"=")
        sig = base64.urlsafe_b64encode(b"fake-sig").rstrip(b"=")
        token = f"{header.decode()}.{payload.decode()}.{sig.decode()}"

        claims = _decode_jwt_claims(token)
        assert claims is not None
        assert claims["sub"] == "client:test"
        assert claims["scope"] == "read"

    def test_invalid_jwt_no_dots(self) -> None:
        assert _decode_jwt_claims("not-a-jwt") is None

    def test_invalid_jwt_bad_base64(self) -> None:
        assert _decode_jwt_claims("a.!!!invalid!!!.c") is None

    def test_empty_string(self) -> None:
        assert _decode_jwt_claims("") is None

    def test_jwt_with_act_claim(self) -> None:
        payload_data = {
            "sub": "client:orchestrator",
            "act": {"sub": "client:db-reader"},
            "scope": "db:read",
        }
        header = base64.urlsafe_b64encode(b'{"alg":"ES256"}').rstrip(b"=")
        payload = base64.urlsafe_b64encode(json.dumps(payload_data).encode()).rstrip(b"=")
        sig = base64.urlsafe_b64encode(b"sig").rstrip(b"=")
        token = f"{header.decode()}.{payload.decode()}.{sig.decode()}"

        claims = _decode_jwt_claims(token)
        assert claims is not None
        assert "act" in claims
        assert claims["act"]["sub"] == "client:db-reader"

    def test_jwt_with_nested_delegation(self) -> None:
        payload_data = {
            "sub": "user:alice",
            "act": {
                "sub": "client:orchestrator",
                "act": {
                    "sub": "client:search-agent",
                    "act": {"sub": "client:db-reader"},
                },
            },
        }
        header = base64.urlsafe_b64encode(b'{"alg":"ES256"}').rstrip(b"=")
        payload = base64.urlsafe_b64encode(json.dumps(payload_data).encode()).rstrip(b"=")
        sig = base64.urlsafe_b64encode(b"sig").rstrip(b"=")
        token = f"{header.decode()}.{payload.decode()}.{sig.decode()}"

        claims = _decode_jwt_claims(token)
        assert claims is not None
        # 3 levels of delegation
        assert claims["act"]["sub"] == "client:orchestrator"
        assert claims["act"]["act"]["sub"] == "client:search-agent"
        assert claims["act"]["act"]["act"]["sub"] == "client:db-reader"

    def test_jwt_with_dpop_cnf(self) -> None:
        payload_data = {
            "sub": "client:test",
            "cnf": {"jkt": "sha256-thumbprint-value"},
        }
        header = base64.urlsafe_b64encode(b'{"alg":"ES256"}').rstrip(b"=")
        payload = base64.urlsafe_b64encode(json.dumps(payload_data).encode()).rstrip(b"=")
        sig = base64.urlsafe_b64encode(b"sig").rstrip(b"=")
        token = f"{header.decode()}.{payload.decode()}.{sig.decode()}"

        claims = _decode_jwt_claims(token)
        assert claims is not None
        assert claims["cnf"]["jkt"] == "sha256-thumbprint-value"


class TestRelativeTime:
    """Test human-friendly relative time formatting."""

    def test_just_now(self) -> None:
        result = _relative_time(datetime.now(UTC))
        assert "s ago" in result or result == "just now"

    def test_minutes_ago(self) -> None:
        from datetime import timedelta

        dt = datetime.now(UTC) - timedelta(minutes=5)
        result = _relative_time(dt)
        assert "m ago" in result

    def test_hours_ago(self) -> None:
        from datetime import timedelta

        dt = datetime.now(UTC) - timedelta(hours=3)
        result = _relative_time(dt)
        assert "h ago" in result

    def test_days_ago(self) -> None:
        from datetime import timedelta

        dt = datetime.now(UTC) - timedelta(days=5)
        result = _relative_time(dt)
        assert "d ago" in result

    def test_yesterday(self) -> None:
        from datetime import timedelta

        dt = datetime.now(UTC) - timedelta(days=1, seconds=1)
        result = _relative_time(dt)
        assert result == "yesterday"

    def test_old_date_format(self) -> None:
        dt = datetime(2024, 1, 15, tzinfo=UTC)
        result = _relative_time(dt)
        assert "2024-01-15" in result

    def test_naive_datetime(self) -> None:
        """Naive datetimes should be treated as UTC."""
        from datetime import timedelta

        dt = datetime.now(UTC).replace(tzinfo=None) - timedelta(minutes=10)
        result = _relative_time(dt)
        assert "m ago" in result


class TestBuildDelegationTree:
    """Test delegation chain tree building."""

    def test_single_hop(self) -> None:
        act = {"sub": "client:orchestrator"}
        tree = _build_delegation_tree(act)
        assert tree is not None
        # Tree label should contain the subject
        assert "orchestrator" in str(tree.label)

    def test_nested_hops(self) -> None:
        act = {
            "sub": "client:orchestrator",
            "act": {"sub": "client:db-reader"},
        }
        tree = _build_delegation_tree(act)
        assert tree is not None
        # Should have children
        assert len(tree.children) > 0

    def test_deeply_nested(self) -> None:
        act = {
            "sub": "client:a",
            "act": {
                "sub": "client:b",
                "act": {
                    "sub": "client:c",
                    "act": {"sub": "client:d"},
                },
            },
        }
        tree = _build_delegation_tree(act)
        assert tree is not None


# ── CLI command tests ────────────────────────────────────────────────────


class TestInspectTokenCommand:
    """Test the inspect-token CLI command."""

    def _make_token(self, claims: dict) -> str:
        header = base64.urlsafe_b64encode(b'{"alg":"ES256","typ":"JWT"}').rstrip(b"=")
        payload = base64.urlsafe_b64encode(json.dumps(claims).encode()).rstrip(b"=")
        sig = base64.urlsafe_b64encode(b"fake-signature").rstrip(b"=")
        return f"{header.decode()}.{payload.decode()}.{sig.decode()}"

    def test_inspect_basic_token(self) -> None:
        token = self._make_token(
            {
                "iss": "http://localhost:8000",
                "sub": "client:test-agent",
                "scope": "read write",
                "iat": 1711400000,
                "exp": 1711403600,
                "jti": "tok_abc123",
            }
        )
        result = runner.invoke(app, ["inspect-token", token])
        assert result.exit_code == 0
        assert "client:test-agent" in result.output
        assert "read write" in result.output
        assert "tok_abc123" in result.output

    def test_inspect_token_with_delegation(self) -> None:
        token = self._make_token(
            {
                "sub": "client:orchestrator",
                "scope": "db:read",
                "act": {"sub": "client:db-reader"},
                "iat": 1711400000,
                "exp": 1711403600,
            }
        )
        result = runner.invoke(app, ["inspect-token", token])
        assert result.exit_code == 0
        assert "Delegation Chain" in result.output
        assert "client:orchestrator" in result.output
        assert "client:db-reader" in result.output
        assert "1 hop" in result.output

    def test_inspect_token_with_deep_delegation(self) -> None:
        token = self._make_token(
            {
                "sub": "user:alice",
                "scope": "db:read",
                "act": {
                    "sub": "client:orchestrator",
                    "act": {"sub": "client:db-reader"},
                },
                "iat": 1711400000,
                "exp": 1711403600,
            }
        )
        result = runner.invoke(app, ["inspect-token", token])
        assert result.exit_code == 0
        assert "2 hops" in result.output

    def test_inspect_token_no_delegation(self) -> None:
        token = self._make_token(
            {
                "sub": "client:standalone",
                "scope": "read",
                "iat": 1711400000,
                "exp": 1711403600,
            }
        )
        result = runner.invoke(app, ["inspect-token", token])
        assert result.exit_code == 0
        assert "No delegation chain" in result.output

    def test_inspect_token_with_dpop(self) -> None:
        token = self._make_token(
            {
                "sub": "client:dpop-agent",
                "cnf": {"jkt": "sha256-thumb-abc123"},
                "iat": 1711400000,
                "exp": 1711403600,
            }
        )
        result = runner.invoke(app, ["inspect-token", token])
        assert result.exit_code == 0
        assert "DPoP-bound" in result.output
        assert "sha256-thumb-abc123" in result.output

    def test_inspect_token_expired(self) -> None:
        token = self._make_token(
            {
                "sub": "client:expired",
                "iat": 1000000000,
                "exp": 1000003600,  # Way in the past
            }
        )
        result = runner.invoke(app, ["inspect-token", token])
        assert result.exit_code == 0
        assert "EXPIRED" in result.output

    def test_inspect_invalid_token(self) -> None:
        result = runner.invoke(app, ["inspect-token", "not-a-jwt"])
        assert result.exit_code == 1

    def test_inspect_shows_raw_json(self) -> None:
        token = self._make_token({"sub": "client:test", "custom_claim": "hello"})
        result = runner.invoke(app, ["inspect-token", token])
        assert result.exit_code == 0
        assert "custom_claim" in result.output
        assert "hello" in result.output


class TestNoArgsShowsHelp:
    """Test that running with no args shows help."""

    def test_no_args_shows_help(self) -> None:
        result = runner.invoke(app, [])
        # Typer no_args_is_help=True exits with code 0 in some versions, 2 in others
        assert result.exit_code in (0, 2)
        assert "authgent" in result.output.lower()


class TestHelpText:
    """Verify all commands are registered and show help."""

    @pytest.mark.parametrize(
        "command",
        [
            "init",
            "run",
            "create-agent",
            "list-agents",
            "get-token",
            "inspect-token",
            "audit",
            "status",
            "rotate-keys",
            "create-user",
            "openapi",
            "migrate",
            "quickstart",
        ],
    )
    def test_command_help(self, command: str) -> None:
        result = runner.invoke(app, [command, "--help"])
        assert result.exit_code == 0
        assert "--help" not in result.output or "Usage" in result.output
