"""Transaction Tokens tests — draft-ietf-oauth-transaction-tokens-08.

The Txn-Token spec describes a Transaction Token Service (TTS) that mints
short-lived, audience-bound tokens carrying transaction context (`tctx`),
requester context (`rctx`), and a unique transaction id (`txn`).

These tests cover:
- §3 request shape and required claims (iat, aud, exp, txn, sub, scope, req_wl)
- §3 typ header `txntoken+jwt`
- §3 optional tctx / rctx
- §7 short TTL
- §7.2 scope MUST NOT exceed subject_token's scope
- §11 no refresh tokens
"""

from __future__ import annotations

import json
import secrets

import jwt as pyjwt
import pytest

TXN_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:txn_token"
TOKEN_EXCHANGE_GRANT = "urn:ietf:params:oauth:grant-type:token-exchange"


def _register(test_client, *, grant_types, scope="trade.stocks read write"):
    resp = test_client.post(
        "/register",
        json={
            "client_name": f"txn-{secrets.token_hex(4)}",
            "grant_types": grant_types,
            "scope": scope,
        },
    )
    assert resp.status_code == 201, resp.text
    return resp.json()


def _client_creds_token(test_client, creds, scope="trade.stocks"):
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


def _decode(jwt_str: str) -> tuple[dict, dict]:
    header = pyjwt.get_unverified_header(jwt_str)
    payload = pyjwt.decode(jwt_str, options={"verify_signature": False})
    return header, payload


# --- §3 happy path --------------------------------------------------------


@pytest.mark.asyncio
async def test_txn_token_issuance_required_claims(test_client):
    """Issued Txn-Token MUST include iat, aud, exp, txn, sub, scope, req_wl."""
    parent = _register(test_client, grant_types=["client_credentials"])
    parent_tok = _client_creds_token(test_client, parent)["access_token"]

    tts_caller = _register(
        test_client,
        grant_types=["client_credentials", TOKEN_EXCHANGE_GRANT],
    )

    resp = test_client.post(
        "/token",
        data={
            "grant_type": TOKEN_EXCHANGE_GRANT,
            "client_id": tts_caller["client_id"],
            "client_secret": tts_caller["client_secret"],
            "subject_token": parent_tok,
            "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
            "requested_token_type": TXN_TOKEN_TYPE,
            "audience": "https://trust-domain.example/",
            "scope": "trade.stocks",
        },
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["issued_token_type"] == TXN_TOKEN_TYPE
    assert body["token_type"] == "N_A"
    assert body.get("refresh_token") is None  # §11

    header, claims = _decode(body["access_token"])
    # §3 typ header
    assert header["typ"] == "txntoken+jwt"
    # §3 required claims
    for required in ("iat", "aud", "exp", "txn", "sub", "scope", "req_wl"):
        assert required in claims, f"Missing required claim: {required}"
    assert claims["aud"] == "https://trust-domain.example/"
    assert claims["scope"] == "trade.stocks"
    assert claims["req_wl"] == f"client:{tts_caller['client_id']}"


@pytest.mark.asyncio
async def test_txn_token_carries_tctx_and_rctx(test_client):
    """§3: request_details → tctx; request_context → rctx (with auto req_ip/authn)."""
    parent = _register(test_client, grant_types=["client_credentials"])
    parent_tok = _client_creds_token(test_client, parent)["access_token"]

    tts_caller = _register(
        test_client,
        grant_types=["client_credentials", TOKEN_EXCHANGE_GRANT],
    )

    tctx = {
        "action": "BUY",
        "ticker": "MSFT",
        "quantity": "100",
        "customer_type": {"geo": "US", "level": "VIP"},
    }
    rctx = {"channel": "mobile"}

    resp = test_client.post(
        "/token",
        data={
            "grant_type": TOKEN_EXCHANGE_GRANT,
            "client_id": tts_caller["client_id"],
            "client_secret": tts_caller["client_secret"],
            "subject_token": parent_tok,
            "requested_token_type": TXN_TOKEN_TYPE,
            "audience": "https://trust-domain.example/",
            "scope": "trade.stocks",
            "request_details": json.dumps(tctx),
            "request_context": json.dumps(rctx),
        },
    )
    assert resp.status_code == 200, resp.text
    _, claims = _decode(resp.json()["access_token"])
    # §3 tctx is the spec name for request_details
    assert claims["tctx"] == tctx
    # §3 rctx is the spec name for request_context, augmented with auto fields
    assert claims["rctx"]["channel"] == "mobile"
    assert "authn" in claims["rctx"]


# --- §7 lifetime ---------------------------------------------------------


@pytest.mark.asyncio
async def test_txn_token_short_lived(test_client):
    """§7: 'on the order of minutes or less'. Default authgent TTL is 120s."""
    parent = _register(test_client, grant_types=["client_credentials"])
    parent_tok = _client_creds_token(test_client, parent)["access_token"]

    tts_caller = _register(
        test_client,
        grant_types=["client_credentials", TOKEN_EXCHANGE_GRANT],
    )
    resp = test_client.post(
        "/token",
        data={
            "grant_type": TOKEN_EXCHANGE_GRANT,
            "client_id": tts_caller["client_id"],
            "client_secret": tts_caller["client_secret"],
            "subject_token": parent_tok,
            "requested_token_type": TXN_TOKEN_TYPE,
            "audience": "https://trust-domain.example/",
            "scope": "trade.stocks",
        },
    )
    assert resp.status_code == 200
    expires_in = resp.json()["expires_in"]
    assert 1 <= expires_in <= 600  # minutes-or-less per §7


# --- §7.2 scope policy ---------------------------------------------------


@pytest.mark.asyncio
async def test_txn_token_scope_escalation_rejected(test_client):
    """§7.2: TTS MUST ensure requested scope ⊆ subject_token scope."""
    # Parent has only 'read'; child requests 'trade.stocks' → must be denied.
    parent = _register(test_client, grant_types=["client_credentials"], scope="read")
    parent_tok = _client_creds_token(test_client, parent, scope="read")["access_token"]

    tts_caller = _register(
        test_client,
        grant_types=["client_credentials", TOKEN_EXCHANGE_GRANT],
        scope="read trade.stocks",
    )
    resp = test_client.post(
        "/token",
        data={
            "grant_type": TOKEN_EXCHANGE_GRANT,
            "client_id": tts_caller["client_id"],
            "client_secret": tts_caller["client_secret"],
            "subject_token": parent_tok,
            "requested_token_type": TXN_TOKEN_TYPE,
            "audience": "https://trust-domain.example/",
            "scope": "trade.stocks",
        },
    )
    assert resp.status_code in (401, 403)


@pytest.mark.asyncio
async def test_txn_token_scope_subset_allowed(test_client):
    """§7.2: equal-or-less scope is fine."""
    parent = _register(
        test_client,
        grant_types=["client_credentials"],
        scope="trade.stocks read",
    )
    parent_tok = _client_creds_token(test_client, parent, scope="trade.stocks read")["access_token"]

    tts_caller = _register(
        test_client,
        grant_types=["client_credentials", TOKEN_EXCHANGE_GRANT],
        scope="trade.stocks read",
    )
    resp = test_client.post(
        "/token",
        data={
            "grant_type": TOKEN_EXCHANGE_GRANT,
            "client_id": tts_caller["client_id"],
            "client_secret": tts_caller["client_secret"],
            "subject_token": parent_tok,
            "requested_token_type": TXN_TOKEN_TYPE,
            "audience": "https://trust-domain.example/",
            "scope": "trade.stocks",
        },
    )
    assert resp.status_code == 200, resp.text


# --- §11 no refresh tokens -----------------------------------------------


@pytest.mark.asyncio
async def test_txn_token_no_refresh_token(test_client):
    """§11: Txn-Token responses MUST NOT include refresh_token."""
    parent = _register(test_client, grant_types=["client_credentials"])
    parent_tok = _client_creds_token(test_client, parent)["access_token"]

    tts_caller = _register(
        test_client,
        grant_types=["client_credentials", TOKEN_EXCHANGE_GRANT],
    )
    resp = test_client.post(
        "/token",
        data={
            "grant_type": TOKEN_EXCHANGE_GRANT,
            "client_id": tts_caller["client_id"],
            "client_secret": tts_caller["client_secret"],
            "subject_token": parent_tok,
            "requested_token_type": TXN_TOKEN_TYPE,
            "audience": "https://trust-domain.example/",
            "scope": "trade.stocks",
        },
    )
    assert resp.status_code == 200
    assert "refresh_token" not in resp.json() or resp.json()["refresh_token"] is None


# --- Discovery ------------------------------------------------------------


def test_metadata_advertises_txn_token_type(test_client):
    """authgent advertises both jwt (chaining) and txn_token requested types."""
    meta = test_client.get("/.well-known/oauth-authorization-server").json()
    assert TXN_TOKEN_TYPE in meta["token_exchange_requested_token_types_supported"]


# --- Uniqueness of txn ----------------------------------------------------


@pytest.mark.asyncio
async def test_txn_claim_is_unique_across_issuances(test_client):
    """§3: txn is a unique transaction identifier — two issuances differ."""
    parent = _register(test_client, grant_types=["client_credentials"])
    parent_tok = _client_creds_token(test_client, parent)["access_token"]
    tts_caller = _register(
        test_client,
        grant_types=["client_credentials", TOKEN_EXCHANGE_GRANT],
    )

    txns = set()
    for _ in range(3):
        resp = test_client.post(
            "/token",
            data={
                "grant_type": TOKEN_EXCHANGE_GRANT,
                "client_id": tts_caller["client_id"],
                "client_secret": tts_caller["client_secret"],
                "subject_token": parent_tok,
                "requested_token_type": TXN_TOKEN_TYPE,
                "audience": "https://trust-domain.example/",
                "scope": "trade.stocks",
            },
        )
        assert resp.status_code == 200
        _, claims = _decode(resp.json()["access_token"])
        txns.add(claims["txn"])
    assert len(txns) == 3
