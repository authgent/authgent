"""Tests for POST /revoke — Token Revocation."""

from fastapi.testclient import TestClient


def test_revoke_token(test_client: TestClient) -> None:
    # Register and get a token
    reg = test_client.post(
        "/register",
        json={
            "client_name": "revoke-test",
            "grant_types": ["client_credentials"],
            "scope": "test:scope",
        },
    ).json()

    token_resp = test_client.post(
        "/token",
        data={
            "grant_type": "client_credentials",
            "client_id": reg["client_id"],
            "client_secret": reg["client_secret"],
            "scope": "test:scope",
        },
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )

    token = token_resp.json()["access_token"]

    # Revoke it
    resp = test_client.post(
        "/revoke",
        data={
            "token": token,
            "client_id": reg["client_id"],
        },
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )

    assert resp.status_code == 200


def test_revoke_invalid_token(test_client: TestClient) -> None:
    """RFC 7009: revoking invalid tokens should not error."""
    resp = test_client.post(
        "/revoke",
        data={
            "token": "not.a.real.token",
            "client_id": "test",
        },
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )

    assert resp.status_code == 200
