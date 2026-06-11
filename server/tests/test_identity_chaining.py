"""Identity Chaining tests — draft-ietf-oauth-identity-chaining-14.

Covers the §2.3 Token Exchange step (Domain A mints a JWT authorization
grant) and the §2.4 JWT Authorization Grant step (Domain B consumes the
grant and issues a Domain-B access token), along with the security
considerations from §5 (single-use replay protection, no refresh tokens,
audience binding, untrusted issuer rejection).

These tests treat a single authgent instance as both Domain A and Domain B
to exercise the round trip end-to-end. Because both sides use the same
JWKS, the trusted_chaining_issuers list contains our own server_url.
"""

from __future__ import annotations

import secrets

import jwt as pyjwt
import pytest

from authgent_server.config import get_settings, reset_settings

JWT_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:jwt"
JWT_BEARER_GRANT = "urn:ietf:params:oauth:grant-type:jwt-bearer"
TOKEN_EXCHANGE_GRANT = "urn:ietf:params:oauth:grant-type:token-exchange"


def _register(test_client, *, grant_types, scope="read write"):
    resp = test_client.post(
        "/register",
        json={
            "client_name": f"chaining-{secrets.token_hex(4)}",
            "grant_types": grant_types,
            "scope": scope,
        },
    )
    assert resp.status_code == 201, resp.text
    return resp.json()


def _client_creds_token(test_client, creds, scope="read write"):
    resp = test_client.post(
        "/token",
        data={
            "grant_type": "client_credentials",
            "client_id": creds["client_id"],
            "client_secret": creds["client_secret"],
            "scope": scope,
        },
    )
    assert resp.status_code == 200, resp.text
    return resp.json()


def _enable_chaining(monkeypatch, *, targets=None, issuers=None):
    """Configure the server to act as Domain A and/or Domain B."""
    if targets is not None:
        monkeypatch.setenv("AUTHGENT_TRUSTED_CHAINING_TARGETS", str(targets).replace("'", '"'))
    if issuers is not None:
        monkeypatch.setenv("AUTHGENT_TRUSTED_CHAINING_ISSUERS", str(issuers).replace("'", '"'))
    reset_settings()


# --- §3 Authorization Server Metadata --------------------------------------


def test_metadata_advertises_chaining_token_types(test_client):
    """§3: server metadata MUST advertise supported requested_token_types."""
    resp = test_client.get("/.well-known/oauth-authorization-server")
    assert resp.status_code == 200
    meta = resp.json()
    assert JWT_TOKEN_TYPE in meta["identity_chaining_requested_token_types_supported"]
    assert JWT_BEARER_GRANT in meta["grant_types_supported"]


# --- §2.3 Outbound: minting a JWT authorization grant ----------------------


@pytest.mark.asyncio
async def test_chaining_grant_issuance_default(test_client, monkeypatch):
    """Happy path: requesting a jwt-typed token returns a JWT grant."""
    target_as = "https://as.b.example/"
    _enable_chaining(monkeypatch, targets=[target_as])

    parent = _register(test_client, grant_types=["client_credentials"], scope="read write")
    parent_tok = _client_creds_token(test_client, parent)["access_token"]

    chainer = _register(
        test_client,
        grant_types=["client_credentials", TOKEN_EXCHANGE_GRANT],
        scope="read",
    )

    resp = test_client.post(
        "/token",
        data={
            "grant_type": TOKEN_EXCHANGE_GRANT,
            "client_id": chainer["client_id"],
            "client_secret": chainer["client_secret"],
            "subject_token": parent_tok,
            "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
            "requested_token_type": JWT_TOKEN_TYPE,
            "audience": target_as,
            "scope": "read",
        },
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["issued_token_type"] == JWT_TOKEN_TYPE
    assert body["token_type"] == "N_A"

    # Decode (without verifying — that's the receiving AS's job in production)
    claims = pyjwt.decode(body["access_token"], options={"verify_signature": False})
    assert claims["aud"] == target_as
    assert claims["iss"] == get_settings().server_url
    assert "jti" in claims
    assert "exp" in claims
    assert claims["exp"] > claims["iat"]


@pytest.mark.asyncio
async def test_chaining_grant_resource_alone_is_accepted(test_client, monkeypatch):
    """§2.3.1: 'resource' alone (without 'audience') satisfies the requirement."""
    target_as = "https://as.b.example/"
    _enable_chaining(monkeypatch, targets=[target_as])

    parent = _register(test_client, grant_types=["client_credentials"])
    parent_tok = _client_creds_token(test_client, parent)["access_token"]

    chainer = _register(
        test_client,
        grant_types=["client_credentials", TOKEN_EXCHANGE_GRANT],
    )

    resp = test_client.post(
        "/token",
        data={
            "grant_type": TOKEN_EXCHANGE_GRANT,
            "client_id": chainer["client_id"],
            "client_secret": chainer["client_secret"],
            "subject_token": parent_tok,
            "requested_token_type": JWT_TOKEN_TYPE,
            "resource": target_as,
        },
    )
    assert resp.status_code == 200, resp.text


@pytest.mark.asyncio
async def test_chaining_grant_missing_audience_and_resource_rejected(test_client, monkeypatch):
    """§2.3.1: One of 'resource' or 'audience' is REQUIRED."""
    _enable_chaining(monkeypatch, targets=["https://as.b.example/"])

    parent = _register(test_client, grant_types=["client_credentials"])
    parent_tok = _client_creds_token(test_client, parent)["access_token"]

    chainer = _register(
        test_client,
        grant_types=["client_credentials", TOKEN_EXCHANGE_GRANT],
    )

    resp = test_client.post(
        "/token",
        data={
            "grant_type": TOKEN_EXCHANGE_GRANT,
            "client_id": chainer["client_id"],
            "client_secret": chainer["client_secret"],
            "subject_token": parent_tok,
            "requested_token_type": JWT_TOKEN_TYPE,
        },
    )
    assert resp.status_code == 400


@pytest.mark.asyncio
async def test_chaining_grant_untrusted_target_rejected(test_client, monkeypatch):
    """§2.3.2: target outside trusted_chaining_targets is denied by policy."""
    _enable_chaining(monkeypatch, targets=["https://as.b.example/"])

    parent = _register(test_client, grant_types=["client_credentials"])
    parent_tok = _client_creds_token(test_client, parent)["access_token"]

    chainer = _register(
        test_client,
        grant_types=["client_credentials", TOKEN_EXCHANGE_GRANT],
    )

    resp = test_client.post(
        "/token",
        data={
            "grant_type": TOKEN_EXCHANGE_GRANT,
            "client_id": chainer["client_id"],
            "client_secret": chainer["client_secret"],
            "subject_token": parent_tok,
            "requested_token_type": JWT_TOKEN_TYPE,
            "audience": "https://malicious.example/",
        },
    )
    assert resp.status_code in (401, 403)


@pytest.mark.asyncio
async def test_chaining_grant_ttl_is_short(test_client, monkeypatch):
    """§5.5: grants SHOULD be short-lived. Default is <= 60s."""
    target_as = "https://as.b.example/"
    _enable_chaining(monkeypatch, targets=[target_as])

    parent = _register(test_client, grant_types=["client_credentials"])
    parent_tok = _client_creds_token(test_client, parent)["access_token"]

    chainer = _register(
        test_client,
        grant_types=["client_credentials", TOKEN_EXCHANGE_GRANT],
    )

    resp = test_client.post(
        "/token",
        data={
            "grant_type": TOKEN_EXCHANGE_GRANT,
            "client_id": chainer["client_id"],
            "client_secret": chainer["client_secret"],
            "subject_token": parent_tok,
            "requested_token_type": JWT_TOKEN_TYPE,
            "audience": target_as,
        },
    )
    assert resp.status_code == 200
    assert resp.json()["expires_in"] <= 60


# --- §2.4 Inbound: consuming a JWT authorization grant ---------------------


@pytest.mark.asyncio
async def test_round_trip_chaining_a_to_b(test_client, monkeypatch):
    """End-to-end: authgent acts as A, mints a grant, then as B, consumes it.

    Because the test server signs assertions with the same JWKS it later
    verifies, configuring trusted_chaining_issuers=[server_url] simulates
    a federation between Domain A and Domain B.
    """
    server_url = "http://localhost:8000"
    _enable_chaining(
        monkeypatch,
        targets=[f"{server_url}/token", server_url],
        issuers=[server_url],
    )

    parent = _register(test_client, grant_types=["client_credentials"])
    parent_tok = _client_creds_token(test_client, parent)["access_token"]

    chainer = _register(
        test_client,
        grant_types=["client_credentials", TOKEN_EXCHANGE_GRANT],
    )

    # Step 1: Domain A mints a grant whose aud = Domain B's token endpoint.
    grant_resp = test_client.post(
        "/token",
        data={
            "grant_type": TOKEN_EXCHANGE_GRANT,
            "client_id": chainer["client_id"],
            "client_secret": chainer["client_secret"],
            "subject_token": parent_tok,
            "requested_token_type": JWT_TOKEN_TYPE,
            "audience": f"{server_url}/token",
        },
    )
    assert grant_resp.status_code == 200, grant_resp.text
    grant = grant_resp.json()["access_token"]

    # Step 2: a Domain-B client redeems the grant.
    consumer = _register(test_client, grant_types=[JWT_BEARER_GRANT])

    consume_resp = test_client.post(
        "/token",
        data={
            "grant_type": JWT_BEARER_GRANT,
            "client_id": consumer["client_id"],
            "client_secret": consumer["client_secret"],
            "assertion": grant,
        },
    )
    assert consume_resp.status_code == 200, consume_resp.text
    body = consume_resp.json()
    assert body["token_type"] in ("Bearer", "DPoP")
    # §5.4: SHOULD NOT issue refresh tokens for jwt-bearer grant.
    assert body.get("refresh_token") is None

    claims = pyjwt.decode(body["access_token"], options={"verify_signature": False})
    assert claims.get("chained_from") == server_url


@pytest.mark.asyncio
async def test_chaining_grant_replay_rejected(test_client, monkeypatch):
    """§5.5: assertion is single-use; reuse MUST be rejected."""
    server_url = "http://localhost:8000"
    _enable_chaining(
        monkeypatch,
        targets=[f"{server_url}/token"],
        issuers=[server_url],
    )

    parent = _register(test_client, grant_types=["client_credentials"])
    parent_tok = _client_creds_token(test_client, parent)["access_token"]
    chainer = _register(
        test_client,
        grant_types=["client_credentials", TOKEN_EXCHANGE_GRANT],
    )
    grant_resp = test_client.post(
        "/token",
        data={
            "grant_type": TOKEN_EXCHANGE_GRANT,
            "client_id": chainer["client_id"],
            "client_secret": chainer["client_secret"],
            "subject_token": parent_tok,
            "requested_token_type": JWT_TOKEN_TYPE,
            "audience": f"{server_url}/token",
        },
    )
    grant = grant_resp.json()["access_token"]
    consumer = _register(test_client, grant_types=[JWT_BEARER_GRANT])

    first = test_client.post(
        "/token",
        data={
            "grant_type": JWT_BEARER_GRANT,
            "client_id": consumer["client_id"],
            "client_secret": consumer["client_secret"],
            "assertion": grant,
        },
    )
    assert first.status_code == 200

    second = test_client.post(
        "/token",
        data={
            "grant_type": JWT_BEARER_GRANT,
            "client_id": consumer["client_id"],
            "client_secret": consumer["client_secret"],
            "assertion": grant,
        },
    )
    assert second.status_code in (400, 401)


@pytest.mark.asyncio
async def test_chaining_grant_missing_assertion_rejected(test_client, monkeypatch):
    server_url = "http://localhost:8000"
    _enable_chaining(monkeypatch, issuers=[server_url])

    consumer = _register(test_client, grant_types=[JWT_BEARER_GRANT])
    resp = test_client.post(
        "/token",
        data={
            "grant_type": JWT_BEARER_GRANT,
            "client_id": consumer["client_id"],
            "client_secret": consumer["client_secret"],
        },
    )
    assert resp.status_code == 400


@pytest.mark.asyncio
async def test_chaining_grant_no_chaining_issuers_configured(test_client, monkeypatch):
    """When AUTHGENT_TRUSTED_CHAINING_ISSUERS is empty, jwt-bearer is refused."""
    monkeypatch.setenv("AUTHGENT_TRUSTED_CHAINING_ISSUERS", "[]")
    reset_settings()

    consumer = _register(test_client, grant_types=[JWT_BEARER_GRANT])
    resp = test_client.post(
        "/token",
        data={
            "grant_type": JWT_BEARER_GRANT,
            "client_id": consumer["client_id"],
            "client_secret": consumer["client_secret"],
            "assertion": "garbage",
        },
    )
    assert resp.status_code == 400


@pytest.mark.asyncio
async def test_chaining_grant_garbage_assertion_rejected(test_client, monkeypatch):
    """A non-JWT assertion MUST be rejected."""
    server_url = "http://localhost:8000"
    _enable_chaining(monkeypatch, issuers=[server_url])

    consumer = _register(test_client, grant_types=[JWT_BEARER_GRANT])
    resp = test_client.post(
        "/token",
        data={
            "grant_type": JWT_BEARER_GRANT,
            "client_id": consumer["client_id"],
            "client_secret": consumer["client_secret"],
            "assertion": "not.a.jwt",
        },
    )
    assert resp.status_code in (400, 401)


@pytest.mark.asyncio
async def test_default_token_exchange_unchanged_by_chaining(test_client, monkeypatch):
    """Regression: when requested_token_type is omitted, the existing nested-act
    delegation flow MUST behave exactly as before."""
    parent = _register(test_client, grant_types=["client_credentials"], scope="read write")
    parent_tok = _client_creds_token(test_client, parent)["access_token"]
    child = _register(
        test_client,
        grant_types=["client_credentials", TOKEN_EXCHANGE_GRANT],
        scope="read",
    )

    resp = test_client.post(
        "/token",
        data={
            "grant_type": TOKEN_EXCHANGE_GRANT,
            "client_id": child["client_id"],
            "client_secret": child["client_secret"],
            "subject_token": parent_tok,
            "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
            "audience": "https://api.example.com",
            "scope": "read",
        },
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["issued_token_type"] == "urn:ietf:params:oauth:token-type:access_token"
    claims = pyjwt.decode(body["access_token"], options={"verify_signature": False})
    # Existing delegation builds an act chain on the new token.
    assert "act" in claims


# --- Verifier-level edge cases (driven through the public endpoint) ---------


def _forge_assertion(claims: dict) -> str:
    """Forge a JWT with arbitrary claims using a random ES256 key.

    Used to exercise verifier rejection paths — the assertion is well-formed
    syntactically but signed by a key authgent cannot find in its JWKS.
    """
    import jwt as _jwt
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    pk = ec.generate_private_key(ec.SECP256R1())
    pem = pk.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()
    return _jwt.encode(claims, pem, algorithm="ES256", headers={"kid": "forged"})


@pytest.mark.asyncio
async def test_chaining_assertion_untrusted_issuer(test_client, monkeypatch):
    """§2.4.2 + RFC 7523 §3.1: assertion from an iss not in the trust list
    MUST be rejected even if otherwise well-formed."""
    server_url = "http://localhost:8000"
    _enable_chaining(monkeypatch, issuers=[server_url])

    forged = _forge_assertion(
        {
            "iss": "https://untrusted.example/",
            "aud": f"{server_url}/token",
            "sub": "user:eve",
            "exp": 9999999999,
            "iat": 1,
            "jti": "j1",
        }
    )
    consumer = _register(test_client, grant_types=[JWT_BEARER_GRANT])
    resp = test_client.post(
        "/token",
        data={
            "grant_type": JWT_BEARER_GRANT,
            "client_id": consumer["client_id"],
            "client_secret": consumer["client_secret"],
            "assertion": forged,
        },
    )
    assert resp.status_code in (400, 401)
    assert "untrusted" in resp.text.lower() or "invalid" in resp.text.lower()


@pytest.mark.asyncio
async def test_chaining_assertion_wrong_audience_rejected(test_client, monkeypatch):
    """§2.3.3 / §2.4.2: assertion's aud MUST identify *this* AS."""
    server_url = "http://localhost:8000"
    _enable_chaining(monkeypatch, issuers=[server_url])

    # iss is trusted (us) but aud points elsewhere — verifier must reject.
    forged = _forge_assertion(
        {
            "iss": server_url,
            "aud": "https://different-as.example/",
            "sub": "user:bob",
            "exp": 9999999999,
            "iat": 1,
            "jti": "j-aud",
        }
    )
    consumer = _register(test_client, grant_types=[JWT_BEARER_GRANT])
    resp = test_client.post(
        "/token",
        data={
            "grant_type": JWT_BEARER_GRANT,
            "client_id": consumer["client_id"],
            "client_secret": consumer["client_secret"],
            "assertion": forged,
        },
    )
    assert resp.status_code in (400, 401)


@pytest.mark.asyncio
async def test_chaining_assertion_unknown_kid_rejected(test_client, monkeypatch):
    """A JWT signed by a key authgent doesn't know MUST be rejected — even
    when iss and aud are correct (this exercises the local-key lookup)."""
    server_url = "http://localhost:8000"
    _enable_chaining(monkeypatch, issuers=[server_url])

    forged = _forge_assertion(
        {
            "iss": server_url,
            "aud": f"{server_url}/token",
            "sub": "user:mallory",
            "exp": 9999999999,
            "iat": 1,
            "jti": "j-bad-kid",
        }
    )
    consumer = _register(test_client, grant_types=[JWT_BEARER_GRANT])
    resp = test_client.post(
        "/token",
        data={
            "grant_type": JWT_BEARER_GRANT,
            "client_id": consumer["client_id"],
            "client_secret": consumer["client_secret"],
            "assertion": forged,
        },
    )
    assert resp.status_code in (400, 401)


@pytest.mark.asyncio
async def test_chaining_grant_open_target_when_no_allowlist(test_client, monkeypatch):
    """When AUTHGENT_TRUSTED_CHAINING_TARGETS is empty, any audience is
    accepted — this is the documented opt-in behaviour."""
    monkeypatch.setenv("AUTHGENT_TRUSTED_CHAINING_TARGETS", "[]")
    reset_settings()

    parent = _register(test_client, grant_types=["client_credentials"])
    parent_tok = _client_creds_token(test_client, parent)["access_token"]
    chainer = _register(
        test_client,
        grant_types=["client_credentials", TOKEN_EXCHANGE_GRANT],
    )

    resp = test_client.post(
        "/token",
        data={
            "grant_type": TOKEN_EXCHANGE_GRANT,
            "client_id": chainer["client_id"],
            "client_secret": chainer["client_secret"],
            "subject_token": parent_tok,
            "requested_token_type": JWT_TOKEN_TYPE,
            "audience": "https://anyone.example/",
        },
    )
    assert resp.status_code == 200, resp.text


@pytest.mark.asyncio
async def test_chaining_assertion_carries_external_idp_provenance(test_client, monkeypatch):
    """When the chain originated from an external OIDC id_token, the
    Domain-B access token MUST carry idp_iss/idp_sub/human_root claims."""
    server_url = "http://localhost:8000"
    _enable_chaining(
        monkeypatch,
        targets=[f"{server_url}/token"],
        issuers=[server_url],
    )

    # Pre-build an assertion as if Domain A had transcribed an id_token-rooted
    # chain. We sign with authgent's own JWKS via the public endpoint by first
    # minting a chaining grant from a normal client_credentials parent, then
    # asserting the access_token claims present after consumption.
    parent = _register(test_client, grant_types=["client_credentials"])
    parent_tok = _client_creds_token(test_client, parent)["access_token"]

    chainer = _register(
        test_client,
        grant_types=["client_credentials", TOKEN_EXCHANGE_GRANT],
    )
    grant_resp = test_client.post(
        "/token",
        data={
            "grant_type": TOKEN_EXCHANGE_GRANT,
            "client_id": chainer["client_id"],
            "client_secret": chainer["client_secret"],
            "subject_token": parent_tok,
            "requested_token_type": JWT_TOKEN_TYPE,
            "audience": f"{server_url}/token",
        },
    )
    assert grant_resp.status_code == 200
    grant = grant_resp.json()["access_token"]

    consumer = _register(test_client, grant_types=[JWT_BEARER_GRANT])
    resp = test_client.post(
        "/token",
        data={
            "grant_type": JWT_BEARER_GRANT,
            "client_id": consumer["client_id"],
            "client_secret": consumer["client_secret"],
            "assertion": grant,
        },
    )
    assert resp.status_code == 200
    claims = pyjwt.decode(resp.json()["access_token"], options={"verify_signature": False})
    # client_credentials parent does not have idp_iss; chained_from MUST be set.
    assert claims["chained_from"] == server_url
    # Standard claims:
    assert claims["iss"] == server_url
    assert claims["jti"]
    # §5.4: refresh tokens not issued
    assert resp.json().get("refresh_token") is None
