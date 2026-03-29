"""Tests for GET /tokens/inspect — JWT decode and delegation chain visualization."""

import base64
import json

from fastapi.testclient import TestClient


def _make_token(claims: dict) -> str:
    """Build a fake JWT with the given claims (no real signature)."""
    header = base64.urlsafe_b64encode(b'{"alg":"ES256","typ":"JWT"}').rstrip(b"=")
    payload = base64.urlsafe_b64encode(json.dumps(claims).encode()).rstrip(b"=")
    sig = base64.urlsafe_b64encode(b"fake-signature-bytes").rstrip(b"=")
    return f"{header.decode()}.{payload.decode()}.{sig.decode()}"


def test_inspect_basic_token(test_client: TestClient) -> None:
    """Inspect a basic client_credentials token."""
    token = _make_token(
        {
            "iss": "http://localhost:8000",
            "sub": "client:orchestrator",
            "scope": "read write",
            "iat": 1711400000,
            "exp": 9999999999,  # Far future
            "jti": "tok_abc123",
            "client_id": "agnt_test",
        }
    )
    resp = test_client.get("/tokens/inspect", params={"token": token})
    assert resp.status_code == 200
    data = resp.json()
    assert data["valid"] is True
    assert data["claims"]["sub"] == "client:orchestrator"
    assert data["claims"]["scope"] == "read write"
    assert data["expired"] is False
    assert data["time_remaining_seconds"] is not None
    assert data["time_remaining_seconds"] > 0
    assert data["delegation_chain"] is None  # No act claim
    assert data["dpop_bound"] is False


def test_inspect_token_with_delegation(test_client: TestClient) -> None:
    """Inspect a token with a single-hop delegation chain."""
    token = _make_token(
        {
            "sub": "client:orchestrator",
            "scope": "search:execute",
            "act": {"sub": "client:search-agent"},
            "iat": 1711400000,
            "exp": 9999999999,
        }
    )
    resp = test_client.get("/tokens/inspect", params={"token": token})
    assert resp.status_code == 200
    data = resp.json()
    assert data["valid"] is True
    chain = data["delegation_chain"]
    assert chain is not None
    assert chain["depth"] == 1
    assert chain["actors"] == ["client:search-agent"]
    assert chain["human_root"] is False


def test_inspect_token_with_deep_delegation(test_client: TestClient) -> None:
    """Inspect a token with 3-hop delegation chain and human root."""
    token = _make_token(
        {
            "sub": "user:alice",
            "scope": "db:read",
            "act": {
                "sub": "client:orchestrator",
                "act": {
                    "sub": "client:search-agent",
                    "act": {"sub": "client:db-reader"},
                },
            },
            "iat": 1711400000,
            "exp": 9999999999,
        }
    )
    resp = test_client.get("/tokens/inspect", params={"token": token})
    assert resp.status_code == 200
    data = resp.json()
    chain = data["delegation_chain"]
    assert chain["depth"] == 3
    assert chain["actors"] == [
        "client:orchestrator",
        "client:search-agent",
        "client:db-reader",
    ]
    assert chain["human_root"] is True


def test_inspect_expired_token(test_client: TestClient) -> None:
    """Inspect an expired token — should still decode and show expired=True."""
    token = _make_token(
        {
            "sub": "client:test",
            "iat": 1000000000,
            "exp": 1000003600,  # 2001 — way in the past
        }
    )
    resp = test_client.get("/tokens/inspect", params={"token": token})
    assert resp.status_code == 200
    data = resp.json()
    assert data["valid"] is True
    assert data["expired"] is True
    assert data["time_remaining_seconds"] is None


def test_inspect_dpop_bound_token(test_client: TestClient) -> None:
    """Inspect a DPoP-bound token."""
    token = _make_token(
        {
            "sub": "client:dpop-agent",
            "cnf": {"jkt": "sha256-thumbprint-abc123"},
            "iat": 1711400000,
            "exp": 9999999999,
        }
    )
    resp = test_client.get("/tokens/inspect", params={"token": token})
    assert resp.status_code == 200
    data = resp.json()
    assert data["dpop_bound"] is True
    assert data["dpop_jkt"] == "sha256-thumbprint-abc123"


def test_inspect_invalid_token(test_client: TestClient) -> None:
    """Inspect a non-JWT string."""
    resp = test_client.get("/tokens/inspect", params={"token": "not-a-jwt"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["valid"] is False
    assert data["error"] is not None
    assert data["claims"] is None


def test_inspect_real_issued_token(test_client: TestClient) -> None:
    """Issue a real token via POST /token, then inspect it via GET /tokens/inspect."""
    # Create agent
    agent_resp = test_client.post(
        "/agents",
        json={"name": "inspect-test-agent", "allowed_scopes": ["read"]},
    )
    creds = agent_resp.json()

    # Issue token
    token_resp = test_client.post(
        "/token",
        data={
            "grant_type": "client_credentials",
            "client_id": creds["client_id"],
            "client_secret": creds["client_secret"],
            "scope": "read",
        },
    )
    access_token = token_resp.json()["access_token"]

    # Inspect it
    inspect_resp = test_client.get("/tokens/inspect", params={"token": access_token})
    assert inspect_resp.status_code == 200
    data = inspect_resp.json()
    assert data["valid"] is True
    assert data["expired"] is False
    assert data["claims"]["scope"] == "read"
    assert data["claims"]["client_id"] == creds["client_id"]
    assert data["issued_at"] is not None
    assert data["expires_at"] is not None


def test_inspect_token_after_exchange(test_client: TestClient) -> None:
    """Issue + exchange a token, then inspect the delegated token to see the chain."""
    # Create two agents
    orch = test_client.post(
        "/agents",
        json={"name": "inspect-orch", "allowed_scopes": ["read", "search"]},
    ).json()

    # Register a client for exchange
    exchanger = test_client.post(
        "/register",
        json={
            "client_name": "inspect-exchanger",
            "grant_types": [
                "client_credentials",
                "urn:ietf:params:oauth:grant-type:token-exchange",
            ],
            "scope": "search",
        },
    ).json()

    # Orchestrator gets token
    orch_token = test_client.post(
        "/token",
        data={
            "grant_type": "client_credentials",
            "client_id": orch["client_id"],
            "client_secret": orch["client_secret"],
            "scope": "read search",
        },
    ).json()["access_token"]

    # Exchange for narrower token
    exchanged = test_client.post(
        "/token",
        data={
            "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
            "subject_token": orch_token,
            "client_id": exchanger["client_id"],
            "client_secret": exchanger["client_secret"],
            "audience": "https://search.example.com",
            "scope": "search",
        },
    ).json()["access_token"]

    # Inspect the delegated token
    resp = test_client.get("/tokens/inspect", params={"token": exchanged})
    assert resp.status_code == 200
    data = resp.json()
    assert data["valid"] is True
    chain = data["delegation_chain"]
    assert chain is not None
    assert chain["depth"] >= 1
    assert data["claims"]["scope"] == "search"


def test_inspect_missing_token_param(test_client: TestClient) -> None:
    """GET /tokens/inspect without token param returns 422."""
    resp = test_client.get("/tokens/inspect")
    assert resp.status_code == 422


def test_inspect_timestamps_are_iso8601(test_client: TestClient) -> None:
    """Verify that timestamps are returned in ISO 8601 format."""
    token = _make_token(
        {
            "sub": "client:test",
            "iat": 1711400000,
            "exp": 9999999999,
        }
    )
    resp = test_client.get("/tokens/inspect", params={"token": token})
    data = resp.json()
    # ISO 8601 contains T separator and timezone
    assert "T" in data["issued_at"]
    assert "T" in data["expires_at"]
