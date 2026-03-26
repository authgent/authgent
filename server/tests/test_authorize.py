"""Tests for GET/POST /authorize — Authorization Code + PKCE flow."""

import hashlib
import base64
import secrets

from fastapi.testclient import TestClient


def _register_auth_code_client(client: TestClient) -> dict:
    resp = client.post("/register", json={
        "client_name": "mcp-app",
        "grant_types": ["authorization_code", "refresh_token"],
        "redirect_uris": ["http://localhost:3000/callback"],
        "scope": "read write",
    })
    assert resp.status_code == 201
    return resp.json()


def _generate_pkce() -> tuple[str, str]:
    """Generate PKCE code_verifier and code_challenge (S256)."""
    verifier = secrets.token_urlsafe(43)
    challenge = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode()).digest()
    ).rstrip(b"=").decode()
    return verifier, challenge


def test_authorize_auto_approve_and_token_exchange(test_client: TestClient) -> None:
    """Full auth code + PKCE flow in auto_approve mode."""
    creds = _register_auth_code_client(test_client)
    verifier, challenge = _generate_pkce()

    # Step 1: GET /authorize — should auto-approve and redirect with code
    resp = test_client.get("/authorize", params={
        "response_type": "code",
        "client_id": creds["client_id"],
        "redirect_uri": "http://localhost:3000/callback",
        "scope": "read",
        "state": "xyz",
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    }, follow_redirects=False)

    assert resp.status_code == 302
    location = resp.headers["location"]
    assert "code=" in location
    assert "state=xyz" in location

    # Extract code from redirect
    from urllib.parse import parse_qs, urlparse
    parsed = urlparse(location)
    code = parse_qs(parsed.query)["code"][0]

    # Step 2: POST /token — exchange code for tokens
    token_resp = test_client.post("/token", data={
        "grant_type": "authorization_code",
        "client_id": creds["client_id"],
        "client_secret": creds["client_secret"],
        "code": code,
        "code_verifier": verifier,
        "redirect_uri": "http://localhost:3000/callback",
    }, headers={"Content-Type": "application/x-www-form-urlencoded"})

    assert token_resp.status_code == 200
    token_data = token_resp.json()
    assert "access_token" in token_data
    assert "refresh_token" in token_data
    assert token_data["token_type"] == "Bearer"


def test_authorize_missing_pkce(test_client: TestClient) -> None:
    creds = _register_auth_code_client(test_client)

    resp = test_client.get("/authorize", params={
        "response_type": "code",
        "client_id": creds["client_id"],
        "redirect_uri": "http://localhost:3000/callback",
        "scope": "read",
    })
    assert resp.status_code == 400


def test_authorize_wrong_response_type(test_client: TestClient) -> None:
    resp = test_client.get("/authorize", params={
        "response_type": "token",
        "client_id": "test",
        "redirect_uri": "http://localhost:3000/callback",
        "code_challenge": "abc",
    })
    assert resp.status_code == 400
