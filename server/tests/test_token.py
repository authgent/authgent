"""Tests for POST /token — OAuth 2.1 Token Endpoint."""

from fastapi.testclient import TestClient


def _register_client(client: TestClient, **kwargs) -> dict:
    """Helper: register a client and return credentials."""
    payload = {
        "client_name": "test-agent",
        "grant_types": ["client_credentials"],
        "scope": "tools:execute search:read",
        **kwargs,
    }
    resp = client.post("/register", json=payload)
    assert resp.status_code == 201
    return resp.json()


def test_client_credentials_grant(test_client: TestClient) -> None:
    creds = _register_client(test_client)

    resp = test_client.post(
        "/token",
        data={
            "grant_type": "client_credentials",
            "client_id": creds["client_id"],
            "client_secret": creds["client_secret"],
            "scope": "tools:execute",
        },
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )

    assert resp.status_code == 200
    data = resp.json()
    assert "access_token" in data
    assert data["token_type"] == "Bearer"
    assert data["expires_in"] > 0
    assert data["scope"] == "tools:execute"


def test_client_credentials_invalid_secret(test_client: TestClient) -> None:
    creds = _register_client(test_client)

    resp = test_client.post(
        "/token",
        data={
            "grant_type": "client_credentials",
            "client_id": creds["client_id"],
            "client_secret": "wrong_secret",
        },
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )

    assert resp.status_code == 401


def test_token_wrong_content_type(test_client: TestClient) -> None:
    resp = test_client.post(
        "/token",
        json={
            "grant_type": "client_credentials",
            "client_id": "test",
            "client_secret": "test",
        },
    )
    assert resp.status_code == 400


def test_unsupported_grant_type(test_client: TestClient) -> None:
    creds = _register_client(test_client)

    resp = test_client.post(
        "/token",
        data={
            "grant_type": "password",
            "client_id": creds["client_id"],
            "client_secret": creds["client_secret"],
        },
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )

    assert resp.status_code == 400


def test_missing_grant_type(test_client: TestClient) -> None:
    resp = test_client.post(
        "/token",
        data={
            "client_id": "test",
        },
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )

    assert resp.status_code == 400
