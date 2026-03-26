"""Tests for POST /register — Dynamic Client Registration."""

from fastapi.testclient import TestClient


def test_register_client_success(test_client: TestClient) -> None:
    resp = test_client.post(
        "/register",
        json={
            "client_name": "test-agent",
            "grant_types": ["client_credentials"],
            "scope": "tools:execute",
        },
    )
    assert resp.status_code == 201
    data = resp.json()
    assert "client_id" in data
    assert "client_secret" in data
    assert data["client_name"] == "test-agent"
    assert data["grant_types"] == ["client_credentials"]
    assert data["scope"] == "tools:execute"
    assert data["client_id"].startswith("agnt_")
    assert data["client_secret"].startswith("sec_")


def test_register_client_with_redirect_uris(test_client: TestClient) -> None:
    resp = test_client.post(
        "/register",
        json={
            "client_name": "mcp-client",
            "grant_types": ["authorization_code"],
            "redirect_uris": ["http://localhost:3000/callback"],
            "scope": "read write",
        },
    )
    assert resp.status_code == 201
    data = resp.json()
    assert data["redirect_uris"] == ["http://localhost:3000/callback"]


def test_register_client_invalid_grant_type(test_client: TestClient) -> None:
    resp = test_client.post(
        "/register",
        json={
            "client_name": "bad-client",
            "grant_types": ["invalid_grant"],
        },
    )
    assert resp.status_code == 422


def test_register_client_invalid_scope_chars(test_client: TestClient) -> None:
    resp = test_client.post(
        "/register",
        json={
            "client_name": "bad-scope",
            "scope": "valid:scope <script>alert(1)</script>",
        },
    )
    assert resp.status_code == 422
