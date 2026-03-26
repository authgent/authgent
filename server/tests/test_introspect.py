"""Tests for POST /introspect — Token Introspection (RFC 7662)."""

import pytest


@pytest.mark.asyncio
async def test_introspect_valid_token(test_client):
    """Introspecting a valid token returns active=true with claims."""
    reg = test_client.post(
        "/register",
        json={
            "client_name": "introspect-test",
            "grant_types": ["client_credentials"],
            "scope": "read write",
        },
    )
    creds = reg.json()

    tok = test_client.post(
        "/token",
        data={
            "grant_type": "client_credentials",
            "client_id": creds["client_id"],
            "client_secret": creds["client_secret"],
            "scope": "read",
        },
    )
    access_token = tok.json()["access_token"]

    resp = test_client.post("/introspect", data={"token": access_token})
    assert resp.status_code == 200
    body = resp.json()
    assert body["active"] is True
    assert body["scope"] == "read"
    assert body["client_id"] == creds["client_id"]
    assert body["sub"] == f"client:{creds['client_id']}"
    assert body["jti"] is not None
    assert body["iss"] is not None
    assert body["exp"] is not None
    assert body["iat"] is not None


@pytest.mark.asyncio
async def test_introspect_revoked_token(test_client):
    """Introspecting a revoked token returns active=false."""
    reg = test_client.post(
        "/register",
        json={
            "client_name": "revoke-introspect",
            "grant_types": ["client_credentials"],
            "scope": "read",
        },
    )
    creds = reg.json()

    tok = test_client.post(
        "/token",
        data={
            "grant_type": "client_credentials",
            "client_id": creds["client_id"],
            "client_secret": creds["client_secret"],
        },
    )
    access_token = tok.json()["access_token"]

    test_client.post(
        "/revoke",
        data={
            "token": access_token,
            "client_id": creds["client_id"],
        },
    )

    resp = test_client.post("/introspect", data={"token": access_token})
    assert resp.status_code == 200
    assert resp.json()["active"] is False


@pytest.mark.asyncio
async def test_introspect_invalid_token(test_client):
    """Introspecting a garbage token returns active=false."""
    resp = test_client.post("/introspect", data={"token": "not.a.valid.jwt"})
    assert resp.status_code == 200
    assert resp.json()["active"] is False


@pytest.mark.asyncio
async def test_introspect_missing_token(test_client):
    """Missing token parameter returns 400."""
    resp = test_client.post("/introspect", data={})
    assert resp.status_code == 400
