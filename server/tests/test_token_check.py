"""Tests for POST /token/check — dry-run permission pre-check for token exchange."""

import secrets

from fastapi.testclient import TestClient


def _create_agent(tc: TestClient, scopes=None, exchange_targets=None):
    payload: dict = {"name": f"agent-{secrets.token_hex(4)}"}
    if scopes:
        payload["allowed_scopes"] = scopes
    if exchange_targets:
        payload["allowed_exchange_targets"] = exchange_targets
    resp = tc.post("/agents", json=payload)
    assert resp.status_code == 201, resp.text
    return resp.json()


def _register_client(tc: TestClient, *, grant_types=None, scope="read write"):
    resp = tc.post(
        "/register",
        json={
            "client_name": f"client-{secrets.token_hex(4)}",
            "grant_types": grant_types or ["client_credentials"],
            "scope": scope,
        },
    )
    assert resp.status_code == 201
    return resp.json()


def _get_token(tc: TestClient, creds, scope="read"):
    resp = tc.post(
        "/token",
        data={
            "grant_type": "client_credentials",
            "client_id": creds["client_id"],
            "client_secret": creds["client_secret"],
            "scope": scope,
        },
    )
    assert resp.status_code == 200
    return resp.json()


def test_token_check_allowed(test_client: TestClient) -> None:
    """Pre-check should return allowed=True when exchange would succeed."""
    agent = _create_agent(test_client, scopes=["read"])
    parent = _register_client(test_client, scope="read")
    parent_token = _get_token(test_client, parent, scope="read")

    resp = test_client.post(
        "/token/check",
        json={
            "subject_token": parent_token["access_token"],
            "audience": "https://target.example.com",
            "client_id": agent["client_id"],
            "scope": "read",
        },
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["allowed"] is True
    assert "read" in data["effective_scopes"]
    assert data["delegation_depth"] == 0
    assert len(data["reasons"]) == 0


def test_token_check_rejects_scope_escalation(test_client: TestClient) -> None:
    """Pre-check should report scope escalation."""
    agent = _create_agent(test_client, scopes=["read", "write", "admin"])
    parent = _register_client(test_client, scope="read")
    parent_token = _get_token(test_client, parent, scope="read")

    resp = test_client.post(
        "/token/check",
        json={
            "subject_token": parent_token["access_token"],
            "audience": "https://target.example.com",
            "client_id": agent["client_id"],
            "scope": "read admin",
        },
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["allowed"] is False
    assert any("escalation" in r.lower() or "admin" in r for r in data["reasons"])


def test_token_check_rejects_unauthorized_audience(test_client: TestClient) -> None:
    """Pre-check should reject audience not in allowed_exchange_targets."""
    agent = _create_agent(
        test_client,
        scopes=["read"],
        exchange_targets=["https://only-this.example.com"],
    )
    parent = _register_client(test_client, scope="read")
    parent_token = _get_token(test_client, parent, scope="read")

    resp = test_client.post(
        "/token/check",
        json={
            "subject_token": parent_token["access_token"],
            "audience": "https://wrong-target.example.com",
            "client_id": agent["client_id"],
            "scope": "read",
        },
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["allowed"] is False
    assert any("allowed_exchange_targets" in r for r in data["reasons"])


def test_token_check_rejects_invalid_token(test_client: TestClient) -> None:
    """Pre-check should report invalid subject token."""
    agent = _create_agent(test_client, scopes=["read"])

    resp = test_client.post(
        "/token/check",
        json={
            "subject_token": "invalid.jwt.token",
            "audience": "https://target.example.com",
            "client_id": agent["client_id"],
            "scope": "read",
        },
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["allowed"] is False
    assert any("invalid" in r.lower() for r in data["reasons"])


def test_token_check_missing_grant_type(test_client: TestClient) -> None:
    """Pre-check should flag client without token-exchange grant type."""
    creds = _register_client(test_client, grant_types=["client_credentials"], scope="read")
    parent = _register_client(test_client, scope="read")
    parent_token = _get_token(test_client, parent, scope="read")

    resp = test_client.post(
        "/token/check",
        json={
            "subject_token": parent_token["access_token"],
            "audience": "https://target.example.com",
            "client_id": creds["client_id"],
            "scope": "read",
        },
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["allowed"] is False
    assert any("grant type" in r.lower() or "token-exchange" in r for r in data["reasons"])
