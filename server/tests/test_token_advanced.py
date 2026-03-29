"""Advanced token tests — token exchange with blocklist, refresh rotation, auth code + PKCE."""

import base64
import hashlib
import secrets

import pytest


def _pkce_pair() -> tuple[str, str]:
    """Generate PKCE code_verifier and code_challenge (S256)."""
    verifier = secrets.token_urlsafe(32)
    digest = hashlib.sha256(verifier.encode()).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
    return verifier, challenge


def _register_client(test_client, *, grant_types=None, scope="read write"):
    """Helper to register a client and return creds."""
    resp = test_client.post(
        "/register",
        json={
            "client_name": f"test-{secrets.token_hex(4)}",
            "grant_types": grant_types or ["client_credentials"],
            "scope": scope,
        },
    )
    assert resp.status_code == 201
    return resp.json()


def _get_token(test_client, creds, scope="read"):
    """Helper to get a client_credentials token."""
    resp = test_client.post(
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


@pytest.mark.asyncio
async def test_token_exchange_with_revoked_subject_token(test_client):
    """Token exchange must fail if the subject_token has been revoked."""
    # Register two clients: parent (token holder) and child (exchanger)
    parent = _register_client(test_client, scope="read write")
    child = _register_client(
        test_client,
        grant_types=["client_credentials", "urn:ietf:params:oauth:grant-type:token-exchange"],
        scope="read",
    )

    # Parent gets a token
    parent_token = _get_token(test_client, parent, scope="read write")
    access_token = parent_token["access_token"]

    # Revoke the parent token
    test_client.post(
        "/revoke",
        data={
            "token": access_token,
            "client_id": parent["client_id"],
        },
    )

    # Child tries to exchange the revoked token — should fail
    exchange_resp = test_client.post(
        "/token",
        data={
            "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
            "client_id": child["client_id"],
            "client_secret": child["client_secret"],
            "subject_token": access_token,
            "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
            "audience": "https://api.example.com",
            "scope": "read",
        },
    )
    # Should be rejected (400 or 401) because the subject token is revoked
    assert exchange_resp.status_code in (400, 401), (
        f"Expected error for revoked subject_token, "
        f"got {exchange_resp.status_code}: {exchange_resp.json()}"
    )


@pytest.mark.asyncio
async def test_token_exchange_success(test_client):
    """Successful token exchange produces a new token with delegation chain."""
    parent = _register_client(test_client, scope="read write")
    child = _register_client(
        test_client,
        grant_types=["client_credentials", "urn:ietf:params:oauth:grant-type:token-exchange"],
        scope="read",
    )

    parent_token = _get_token(test_client, parent, scope="read write")

    exchange_resp = test_client.post(
        "/token",
        data={
            "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
            "client_id": child["client_id"],
            "client_secret": child["client_secret"],
            "subject_token": parent_token["access_token"],
            "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
            "audience": "https://api.example.com",
            "scope": "read",
        },
    )
    assert exchange_resp.status_code == 200
    body = exchange_resp.json()
    assert "access_token" in body
    assert body["issued_token_type"] == "urn:ietf:params:oauth:token-type:access_token"


@pytest.mark.asyncio
async def test_auth_code_pkce_full_flow(test_client):
    """Full authorization code flow with PKCE — authorize, exchange code for token."""
    creds = _register_client(
        test_client,
        grant_types=["authorization_code", "client_credentials"],
        scope="read write",
    )

    verifier, challenge = _pkce_pair()

    # Step 1: GET /authorize with PKCE
    auth_resp = test_client.get(
        "/authorize",
        params={
            "response_type": "code",
            "client_id": creds["client_id"],
            "redirect_uri": "http://localhost:3000/callback",
            "scope": "read",
            "state": "test_state_123",
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        },
        follow_redirects=False,
    )
    assert auth_resp.status_code == 302

    # Extract code from redirect
    location = auth_resp.headers["location"]
    assert "code=" in location
    code = location.split("code=")[1].split("&")[0]
    assert "state=test_state_123" in location

    # Step 2: Exchange code for token
    token_resp = test_client.post(
        "/token",
        data={
            "grant_type": "authorization_code",
            "client_id": creds["client_id"],
            "client_secret": creds["client_secret"],
            "code": code,
            "redirect_uri": "http://localhost:3000/callback",
            "code_verifier": verifier,
        },
    )
    assert token_resp.status_code == 200
    body = token_resp.json()
    assert "access_token" in body
    assert "refresh_token" in body
    assert body["token_type"] == "Bearer"


@pytest.mark.asyncio
async def test_auth_code_wrong_verifier_fails(test_client):
    """PKCE verification fails with wrong code_verifier."""
    creds = _register_client(
        test_client,
        grant_types=["authorization_code", "client_credentials"],
        scope="read",
    )

    verifier, challenge = _pkce_pair()

    auth_resp = test_client.get(
        "/authorize",
        params={
            "response_type": "code",
            "client_id": creds["client_id"],
            "redirect_uri": "http://localhost:3000/callback",
            "scope": "read",
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        },
        follow_redirects=False,
    )
    code = auth_resp.headers["location"].split("code=")[1].split("&")[0]

    # Use wrong verifier
    token_resp = test_client.post(
        "/token",
        data={
            "grant_type": "authorization_code",
            "client_id": creds["client_id"],
            "client_secret": creds["client_secret"],
            "code": code,
            "redirect_uri": "http://localhost:3000/callback",
            "code_verifier": "wrong_verifier_value",
        },
    )
    assert token_resp.status_code == 400
    assert token_resp.json()["error"] == "invalid_grant"


@pytest.mark.asyncio
async def test_auth_code_replay_fails(test_client):
    """Authorization code can only be used once."""
    creds = _register_client(
        test_client,
        grant_types=["authorization_code", "client_credentials"],
        scope="read",
    )

    verifier, challenge = _pkce_pair()

    auth_resp = test_client.get(
        "/authorize",
        params={
            "response_type": "code",
            "client_id": creds["client_id"],
            "redirect_uri": "http://localhost:3000/callback",
            "scope": "read",
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        },
        follow_redirects=False,
    )
    code = auth_resp.headers["location"].split("code=")[1].split("&")[0]

    # First use: success
    token_resp = test_client.post(
        "/token",
        data={
            "grant_type": "authorization_code",
            "client_id": creds["client_id"],
            "client_secret": creds["client_secret"],
            "code": code,
            "redirect_uri": "http://localhost:3000/callback",
            "code_verifier": verifier,
        },
    )
    assert token_resp.status_code == 200

    # Second use: must fail
    replay_resp = test_client.post(
        "/token",
        data={
            "grant_type": "authorization_code",
            "client_id": creds["client_id"],
            "client_secret": creds["client_secret"],
            "code": code,
            "redirect_uri": "http://localhost:3000/callback",
            "code_verifier": verifier,
        },
    )
    assert replay_resp.status_code == 400
    assert replay_resp.json()["error"] == "invalid_grant"


@pytest.mark.asyncio
async def test_refresh_token_rotation(test_client):
    """Refresh token rotation: old token invalidated, new one issued."""
    creds = _register_client(
        test_client,
        grant_types=["authorization_code", "client_credentials", "refresh_token"],
        scope="read write",
    )

    verifier, challenge = _pkce_pair()

    auth_resp = test_client.get(
        "/authorize",
        params={
            "response_type": "code",
            "client_id": creds["client_id"],
            "redirect_uri": "http://localhost:3000/callback",
            "scope": "read",
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        },
        follow_redirects=False,
    )
    code = auth_resp.headers["location"].split("code=")[1].split("&")[0]

    # Get initial tokens
    token_resp = test_client.post(
        "/token",
        data={
            "grant_type": "authorization_code",
            "client_id": creds["client_id"],
            "client_secret": creds["client_secret"],
            "code": code,
            "redirect_uri": "http://localhost:3000/callback",
            "code_verifier": verifier,
        },
    )
    assert token_resp.status_code == 200
    refresh_token_1 = token_resp.json()["refresh_token"]

    # Refresh: should get new tokens
    refresh_resp = test_client.post(
        "/token",
        data={
            "grant_type": "refresh_token",
            "client_id": creds["client_id"],
            "client_secret": creds["client_secret"],
            "refresh_token": refresh_token_1,
        },
    )
    assert refresh_resp.status_code == 200
    body = refresh_resp.json()
    assert "access_token" in body
    assert "refresh_token" in body
    refresh_token_2 = body["refresh_token"]
    assert refresh_token_2 != refresh_token_1

    # Old refresh token should be invalid now (reuse detection)
    reuse_resp = test_client.post(
        "/token",
        data={
            "grant_type": "refresh_token",
            "client_id": creds["client_id"],
            "client_secret": creds["client_secret"],
            "refresh_token": refresh_token_1,
        },
    )
    assert reuse_resp.status_code == 400


@pytest.mark.asyncio
async def test_token_exchange_creates_delegation_receipt(test_client, db_session):
    """Token exchange should create a delegation receipt in the DB."""
    parent = _register_client(test_client, scope="read")
    child = _register_client(
        test_client,
        grant_types=["client_credentials", "urn:ietf:params:oauth:grant-type:token-exchange"],
        scope="read",
    )
    parent_token = _get_token(test_client, parent, scope="read")

    resp = test_client.post(
        "/token",
        data={
            "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
            "client_id": child["client_id"],
            "client_secret": child["client_secret"],
            "subject_token": parent_token["access_token"],
            "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
            "audience": "https://target.example.com",
            "scope": "read",
        },
    )
    assert resp.status_code == 200

    from sqlalchemy import func, select

    from authgent_server.models.delegation_receipt import DelegationReceipt

    result = await db_session.execute(select(func.count()).select_from(DelegationReceipt))
    count = result.scalar()
    assert count >= 1, "Expected at least 1 delegation receipt after token exchange"

    result2 = await db_session.execute(select(DelegationReceipt))
    receipt = result2.scalar_one()
    assert receipt.token_jti, "Receipt should have token_jti"
    assert receipt.parent_token_jti, "Receipt should have parent_token_jti"
    assert receipt.actor_id.startswith("client:"), "Receipt actor should be client:xxx"
    assert receipt.chain_hash, "Receipt should have chain_hash"
    assert receipt.receipt_jwt, "Receipt should have signed receipt_jwt"


@pytest.mark.asyncio
async def test_introspect_after_exchange(test_client):
    """Introspecting an exchanged token shows delegation metadata."""
    parent = _register_client(test_client, scope="read write")
    child = _register_client(
        test_client,
        grant_types=["client_credentials", "urn:ietf:params:oauth:grant-type:token-exchange"],
        scope="read",
    )

    parent_token = _get_token(test_client, parent, scope="read write")

    exchange = test_client.post(
        "/token",
        data={
            "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
            "client_id": child["client_id"],
            "client_secret": child["client_secret"],
            "subject_token": parent_token["access_token"],
            "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
            "audience": "https://api.example.com",
            "scope": "read",
        },
    )
    assert exchange.status_code == 200
    exchanged_token = exchange.json()["access_token"]

    # Introspect the exchanged token
    introspect = test_client.post("/introspect", data={"token": exchanged_token})
    assert introspect.status_code == 200
    body = introspect.json()
    assert body["active"] is True
    assert body["iss"] is not None
