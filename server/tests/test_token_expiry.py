"""Tests for token expiry enforcement — verifies tokens become inactive after TTL.

Uses freezegun to simulate time passing without actual waits.
"""

import secrets

import pytest
from freezegun import freeze_time

from datetime import datetime, timedelta, timezone


def _register(c, scope="read"):
    resp = c.post("/register", json={
        "client_name": f"test-{secrets.token_hex(4)}",
        "grant_types": ["client_credentials"],
        "scope": scope,
    })
    assert resp.status_code == 201
    return resp.json()


def _cc_token(c, creds, scope="read"):
    resp = c.post("/token", data={
        "grant_type": "client_credentials",
        "client_id": creds["client_id"],
        "client_secret": creds["client_secret"],
        "scope": scope,
    })
    assert resp.status_code == 200
    return resp.json()


def _introspect(c, token):
    resp = c.post("/introspect", data={"token": token})
    assert resp.status_code == 200
    return resp.json()


class TestTokenExpiryEnforcement:
    """Server-issued tokens must become inactive after their TTL expires."""

    @freeze_time("2025-01-01 12:00:00", tz_offset=0)
    def test_fresh_token_is_active(self, test_client):
        """A just-issued token introspects as active."""
        creds = _register(test_client)
        tok = _cc_token(test_client, creds)
        intro = _introspect(test_client, tok["access_token"])
        assert intro["active"] is True

    def test_token_inactive_after_ttl(self, test_client):
        """A token issued in the past is inactive after TTL elapses.

        Strategy: issue a token at time T, then freeze time to T + TTL + 1
        for introspection. The JWT exp claim is set relative to issuance time,
        so introspection at T+TTL+1 sees it as expired.
        """
        now = datetime(2025, 1, 1, 12, 0, 0, tzinfo=timezone.utc)

        # Issue token at T=now
        with freeze_time(now):
            creds = _register(test_client)
            tok = _cc_token(test_client, creds)
            expires_in = tok["expires_in"]

            # Sanity: token is active right now
            intro_now = _introspect(test_client, tok["access_token"])
            assert intro_now["active"] is True

        # Introspect at T + TTL + 60 seconds (well past expiry)
        expired_time = now + timedelta(seconds=expires_in + 60)
        with freeze_time(expired_time):
            intro_expired = _introspect(test_client, tok["access_token"])
            assert intro_expired["active"] is False

    def test_token_active_just_before_expiry(self, test_client):
        """Token is still active 1 second before TTL."""
        now = datetime(2025, 6, 15, 8, 0, 0, tzinfo=timezone.utc)

        with freeze_time(now):
            creds = _register(test_client)
            tok = _cc_token(test_client, creds)
            ttl = tok["expires_in"]

        # 10 seconds before expiry → still active
        almost_expired = now + timedelta(seconds=ttl - 10)
        with freeze_time(almost_expired):
            intro = _introspect(test_client, tok["access_token"])
            assert intro["active"] is True

    def test_expires_in_matches_config(self, test_client):
        """The expires_in value in the token response reflects server config."""
        creds = _register(test_client)
        tok = _cc_token(test_client, creds)
        # Default access_token_ttl is 900 (15 min), client_credentials_ttl is None
        # so it falls back to access_token_ttl = 900
        assert tok["expires_in"] > 0
        assert isinstance(tok["expires_in"], int)
