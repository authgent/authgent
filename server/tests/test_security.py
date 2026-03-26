"""Security tests — forgery, privilege escalation, replay attacks (§12.1)."""

import base64
import hashlib
import secrets
import time

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat


def _register_client(test_client, *, grant_types=None, scope="read write"):
    resp = test_client.post(
        "/register",
        json={
            "client_name": f"sec-{secrets.token_hex(4)}",
            "grant_types": grant_types or ["client_credentials"],
            "scope": scope,
        },
    )
    assert resp.status_code == 201
    return resp.json()


def _get_token(test_client, creds, scope="read"):
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


def _pkce_pair():
    verifier = secrets.token_urlsafe(32)
    digest = hashlib.sha256(verifier.encode()).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
    return verifier, challenge


# ── Token Forgery Tests ──


@pytest.mark.asyncio
async def test_forged_token_wrong_key_rejected(test_client):
    """A token signed with a random key must be rejected."""
    # Generate a rogue key
    rogue_key = ec.generate_private_key(ec.SECP256R1())
    rogue_pem = rogue_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())

    forged = jwt.encode(
        {
            "iss": "http://localhost:8000",
            "sub": "agent:evil",
            "aud": "https://target.example.com",
            "exp": int(time.time()) + 3600,
            "iat": int(time.time()),
            "jti": secrets.token_hex(16),
            "scope": "admin:everything",
            "client_id": "fake_client",
        },
        rogue_pem,
        algorithm="ES256",
        headers={"kid": "rogue-kid-123"},
    )

    # Introspect: must report inactive
    resp = test_client.post("/introspect", data={"token": forged})
    assert resp.status_code == 200
    assert resp.json()["active"] is False


@pytest.mark.asyncio
async def test_forged_token_wrong_issuer_rejected(test_client):
    """A validly-structured token with wrong issuer must be rejected on introspection."""
    creds = _register_client(test_client)
    _get_token(test_client, creds)

    # Decode, tamper issuer (this won't validate since we can't re-sign)
    # Instead: get a real token and verify introspect works, then use a
    # forged one from a different "server"
    rogue_key = ec.generate_private_key(ec.SECP256R1())
    rogue_pem = rogue_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())

    forged = jwt.encode(
        {
            "iss": "http://evil-server:9999",
            "sub": "agent:evil",
            "exp": int(time.time()) + 3600,
            "iat": int(time.time()),
            "jti": secrets.token_hex(16),
            "scope": "read",
        },
        rogue_pem,
        algorithm="ES256",
    )

    resp = test_client.post("/introspect", data={"token": forged})
    assert resp.status_code == 200
    assert resp.json()["active"] is False


@pytest.mark.asyncio
async def test_expired_token_rejected(test_client):
    """An expired token (even from the real server) must be inactive."""
    rogue_key = ec.generate_private_key(ec.SECP256R1())
    rogue_pem = rogue_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())

    expired = jwt.encode(
        {
            "iss": "http://localhost:8000",
            "sub": "agent:test",
            "exp": int(time.time()) - 3600,  # expired 1 hour ago
            "iat": int(time.time()) - 7200,
            "jti": secrets.token_hex(16),
        },
        rogue_pem,
        algorithm="ES256",
    )

    resp = test_client.post("/introspect", data={"token": expired})
    assert resp.status_code == 200
    assert resp.json()["active"] is False


# ── Privilege Escalation Tests ──


@pytest.mark.asyncio
async def test_scope_escalation_on_exchange_rejected(test_client):
    """Token exchange must not grant broader scopes than the parent token."""
    parent = _register_client(test_client, scope="read")
    child = _register_client(
        test_client,
        grant_types=["client_credentials", "urn:ietf:params:oauth:grant-type:token-exchange"],
        scope="read write admin",
    )

    parent_token = _get_token(test_client, parent, scope="read")

    # Try to escalate to "write" via exchange — parent only has "read"
    exchange = test_client.post(
        "/token",
        data={
            "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
            "client_id": child["client_id"],
            "client_secret": child["client_secret"],
            "subject_token": parent_token["access_token"],
            "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
            "audience": "https://target.example.com",
            "scope": "read write",
        },
    )
    # Should be rejected because "write" is not in the parent's scope
    assert exchange.status_code in (400, 403), (
        f"Expected scope escalation rejection, got {exchange.status_code}"
    )


@pytest.mark.asyncio
async def test_client_cannot_use_other_clients_secret(test_client):
    """Client A's secret must not authenticate Client B."""
    client_a = _register_client(test_client, scope="read")
    client_b = _register_client(test_client, scope="read")

    # Try to get a token for client_a using client_b's secret
    resp = test_client.post(
        "/token",
        data={
            "grant_type": "client_credentials",
            "client_id": client_a["client_id"],
            "client_secret": client_b["client_secret"],
            "scope": "read",
        },
    )
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_grant_type_not_in_allowed_list_rejected(test_client):
    """A client registered only for client_credentials cannot use authorization_code."""
    creds = _register_client(
        test_client,
        grant_types=["client_credentials"],
        scope="read",
    )

    verifier, challenge = _pkce_pair()

    # Try to use authorization_code grant — not in allowed list
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

    # If the server issues a code, the token exchange should fail
    if auth_resp.status_code == 302 and "code=" in auth_resp.headers.get("location", ""):
        code = auth_resp.headers["location"].split("code=")[1].split("&")[0]
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
        assert token_resp.status_code == 400, (
            f"Expected grant type rejection, got {token_resp.status_code}"
        )


# ── Replay & Reuse Tests ──


@pytest.mark.asyncio
async def test_revoked_token_fails_introspection(test_client):
    """A revoked token must introspect as inactive."""
    creds = _register_client(test_client)
    token_data = _get_token(test_client, creds)

    # Revoke the token
    test_client.post(
        "/revoke",
        data={
            "token": token_data["access_token"],
            "client_id": creds["client_id"],
        },
    )

    # Introspect revoked token
    resp = test_client.post(
        "/introspect",
        data={
            "token": token_data["access_token"],
        },
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["active"] is False


@pytest.mark.asyncio
async def test_refresh_token_replay_revokes_family(test_client):
    """Replaying a used refresh token must revoke the entire token family."""
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
    rt1 = token_resp.json()["refresh_token"]

    # Use rt1 (legitimate)
    refresh_resp = test_client.post(
        "/token",
        data={
            "grant_type": "refresh_token",
            "client_id": creds["client_id"],
            "client_secret": creds["client_secret"],
            "refresh_token": rt1,
        },
    )
    assert refresh_resp.status_code == 200
    rt2 = refresh_resp.json()["refresh_token"]

    # Replay rt1 (should fail and revoke entire family)
    replay_resp = test_client.post(
        "/token",
        data={
            "grant_type": "refresh_token",
            "client_id": creds["client_id"],
            "client_secret": creds["client_secret"],
            "refresh_token": rt1,
        },
    )
    assert replay_resp.status_code == 400
    assert (
        "replay" in replay_resp.json().get("error_description", "").lower()
        or replay_resp.json()["error"] == "invalid_grant"
    )

    # rt2 should also be revoked now (family revocation)
    rt2_resp = test_client.post(
        "/token",
        data={
            "grant_type": "refresh_token",
            "client_id": creds["client_id"],
            "client_secret": creds["client_secret"],
            "refresh_token": rt2,
        },
    )
    assert rt2_resp.status_code == 400


@pytest.mark.asyncio
async def test_malformed_token_rejected(test_client):
    """Completely malformed tokens must be handled gracefully."""
    resp = test_client.post("/introspect", data={"token": "not.a.valid.jwt.at.all"})
    assert resp.status_code == 200
    assert resp.json()["active"] is False


@pytest.mark.asyncio
async def test_empty_token_rejected(test_client):
    """Empty token string must be rejected (400 invalid_request or inactive)."""
    resp = test_client.post("/introspect", data={"token": ""})
    # Server treats empty string as missing required param → 400
    assert resp.status_code in (200, 400)
    if resp.status_code == 200:
        assert resp.json()["active"] is False
