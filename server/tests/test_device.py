"""Tests for Device Authorization Grant endpoints (RFC 8628)."""

import pytest


@pytest.mark.asyncio
async def test_device_authorization_flow(test_client):
    """Full device auth flow: request code, approve, poll for token."""
    # Register a client
    reg = test_client.post("/register", json={
        "client_name": "device-test",
        "grant_types": ["client_credentials", "urn:ietf:params:oauth:grant-type:device_code"],
        "scope": "read write",
    })
    creds = reg.json()

    # 1. Request device code
    resp = test_client.post("/device/authorize", data={
        "client_id": creds["client_id"],
        "scope": "read",
    })
    assert resp.status_code == 200
    body = resp.json()
    assert "device_code" in body
    assert "user_code" in body
    assert len(body["user_code"]) == 8
    assert "verification_uri" in body
    assert "verification_uri_complete" in body
    assert body["expires_in"] > 0
    assert body["interval"] > 0

    device_code = body["device_code"]
    user_code = body["user_code"]

    # 2. Poll before approval — should get authorization_pending
    poll = test_client.post("/device/token", data={
        "device_code": device_code,
        "client_id": creds["client_id"],
    })
    assert poll.status_code == 400
    assert poll.json()["error"] == "authorization_pending"

    # 3. Human approves
    approve = test_client.post("/device/complete", json={
        "user_code": user_code,
        "subject": "user:alice",
        "action": "approve",
    })
    assert approve.status_code == 200
    assert approve.json()["status"] == "approved"

    # 4. Poll again — should get token
    token_resp = test_client.post("/device/token", data={
        "device_code": device_code,
        "client_id": creds["client_id"],
    })
    assert token_resp.status_code == 200
    token_body = token_resp.json()
    assert "access_token" in token_body
    assert token_body["token_type"] == "Bearer"


@pytest.mark.asyncio
async def test_device_deny_flow(test_client):
    """Device auth flow with denial."""
    reg = test_client.post("/register", json={
        "client_name": "device-deny-test",
        "grant_types": ["client_credentials", "urn:ietf:params:oauth:grant-type:device_code"],
    })
    creds = reg.json()

    resp = test_client.post("/device/authorize", data={
        "client_id": creds["client_id"],
    })
    user_code = resp.json()["user_code"]
    device_code = resp.json()["device_code"]

    # Human denies
    deny = test_client.post("/device/complete", json={
        "user_code": user_code,
        "subject": "user:alice",
        "action": "deny",
    })
    assert deny.status_code == 200
    assert deny.json()["status"] == "denied"

    # Poll should get error
    poll = test_client.post("/device/token", data={
        "device_code": device_code,
        "client_id": creds["client_id"],
    })
    assert poll.status_code in (400, 401)


@pytest.mark.asyncio
async def test_device_unknown_code(test_client):
    """Polling with unknown device code returns error."""
    reg = test_client.post("/register", json={
        "client_name": "device-unknown",
        "grant_types": ["client_credentials"],
    })
    creds = reg.json()

    resp = test_client.post("/device/token", data={
        "device_code": "nonexistent_code",
        "client_id": creds["client_id"],
    })
    assert resp.status_code in (400, 401)


@pytest.mark.asyncio
async def test_device_invalid_user_code(test_client):
    """Approving with invalid user code returns error."""
    resp = test_client.post("/device/complete", json={
        "user_code": "BADCODE1",
        "subject": "user:alice",
    })
    assert resp.status_code == 400
