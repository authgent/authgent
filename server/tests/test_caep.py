"""Tests for CAEP session-revoked SET construction, signing, delivery, and
the flag_compromised trigger path.

Covers:
  - build_session_revoked_set: RFC 8417 SET shape + CAEP event-type URI +
    RFC 9493-style subject identifier.
  - CAEPTransmitter.transmit_session_revoked: signs with the real JWKS
    signing key, delivers via HTTP POST, retries on failure, gives up after
    exhausting retries, and skips cleanly when no receivers are configured.
  - TokenService.flag_compromised: blocklists the jti, cascades to
    descendants, and invokes the CAEP transmitter — while leaving routine
    RFC 7009 revoke_token() untouched (no CAEP transmission there).
"""

from __future__ import annotations

import secrets
from unittest.mock import patch

import httpx
import jwt
import pytest

from authgent_server.config import Settings
from authgent_server.providers.caep import (
    SESSION_REVOKED_EVENT_TYPE,
    CAEPTransmitter,
    build_session_revoked_set,
)
from authgent_server.services.jwks_service import JWKSService

# ── build_session_revoked_set ──


def test_build_session_revoked_set_shape():
    claims = build_session_revoked_set(
        issuer="https://authgent.example.com",
        audience="https://receiver.example.com",
        actor_id="agnt_compromised",
        client_id="client_abc123",
        jti="tok_xyz",
        reason="detected_exfiltration",
    )

    assert claims["iss"] == "https://authgent.example.com"
    assert claims["aud"] == "https://receiver.example.com"
    assert claims["jti"].startswith("set_")
    assert isinstance(claims["iat"], int)

    events = claims["events"]
    assert SESSION_REVOKED_EVENT_TYPE in events
    event = events[SESSION_REVOKED_EVENT_TYPE]
    assert event["reason"] == "detected_exfiltration"
    assert event["subject"]["actor_id"] == "agnt_compromised"
    assert event["subject"]["client_id"] == "client_abc123"
    assert event["subject"]["jti"] == "tok_xyz"
    assert event["subject"]["format"] == "opaque"
    assert isinstance(event["event_timestamp"], int)


def test_build_session_revoked_set_unique_jti_per_call():
    """Each SET gets a fresh jti (RFC 8417 §2 replay-detection requirement)."""
    c1 = build_session_revoked_set(
        issuer="https://x", audience="https://y", actor_id="a", client_id="c", jti="t", reason="r"
    )
    c2 = build_session_revoked_set(
        issuer="https://x", audience="https://y", actor_id="a", client_id="c", jti="t", reason="r"
    )
    assert c1["jti"] != c2["jti"]


# ── CAEPTransmitter: signing + delivery ──


@pytest.mark.asyncio
async def test_transmitter_signs_with_real_jwks_key(db_session):
    """The SET is signed with the server's actual active signing key, and
    verifies against the corresponding JWKS public key."""
    settings = Settings(
        secret_key="test-secret-key-for-unit-tests-only-64chars-long-padding!!",
        server_url="https://authgent.example.com",
        caep_receiver_urls="https://receiver.example.com/ssf",
        caep_hmac_secret="test-hmac",
        caep_retries=0,
    )
    jwks = JWKSService(settings)

    captured: dict = {}

    async def fake_post(self, url, content=None, headers=None):
        captured["url"] = url
        captured["body"] = content
        captured["headers"] = headers
        return httpx.Response(200)

    with patch("httpx.AsyncClient.post", fake_post):
        transmitter = CAEPTransmitter(jwks, settings)
        results = await transmitter.transmit_session_revoked(
            db_session,
            actor_id="agnt_1",
            client_id="client_1",
            jti="tok_1",
            reason="compromised",
        )

    assert len(results) == 1
    assert results[0].delivered is True
    assert results[0].status_code == 200

    # Verify the delivered SET against the real JWKS document.
    set_jwt = captured["body"].decode()
    header = jwt.get_unverified_header(set_jwt)
    assert header["typ"] == "secevent+jwt"
    assert header["alg"] == "ES256"

    jwks_doc = await jwks.get_jwks_document(db_session)
    kid = header["kid"]
    matching = [k for k in jwks_doc["keys"] if k["kid"] == kid]
    assert len(matching) == 1

    # JWKSService.verify_jwt is shaped for access tokens (requires exp,
    # which RFC 8417 SETs do not carry), so verify the SET's signature
    # directly against the matching public JWK instead.
    import base64

    from cryptography.hazmat.primitives.asymmetric import ec

    jwk = matching[0]
    x = base64.urlsafe_b64decode(jwk["x"] + "==")
    y = base64.urlsafe_b64decode(jwk["y"] + "==")
    numbers = ec.EllipticCurvePublicNumbers(
        x=int.from_bytes(x, "big"), y=int.from_bytes(y, "big"), curve=ec.SECP256R1()
    )
    public_key = numbers.public_key()

    claims = jwt.decode(
        set_jwt, public_key, algorithms=["ES256"], options={"verify_aud": False}
    )
    assert SESSION_REVOKED_EVENT_TYPE in claims["events"]
    assert claims["events"][SESSION_REVOKED_EVENT_TYPE]["subject"]["jti"] == "tok_1"


@pytest.mark.asyncio
async def test_transmitter_hmac_signs_delivery_body(db_session):
    """The push-delivery HTTP body carries an HMAC signature header computed
    with caep_hmac_secret, independent of the SET's own JWS signature."""
    settings = Settings(
        secret_key="test-secret-key-for-unit-tests-only-64chars-long-padding!!",
        server_url="https://authgent.example.com",
        caep_receiver_urls="https://receiver.example.com/ssf",
        caep_hmac_secret="shared-secret",
        caep_retries=0,
    )
    jwks = JWKSService(settings)
    captured: dict = {}

    async def fake_post(self, url, content=None, headers=None):
        captured["headers"] = headers
        captured["body"] = content
        return httpx.Response(200)

    with patch("httpx.AsyncClient.post", fake_post):
        transmitter = CAEPTransmitter(jwks, settings)
        await transmitter.transmit_session_revoked(
            db_session, actor_id="a", client_id="c", jti="t", reason="r"
        )

    sig_header = captured["headers"]["X-Authgent-Signature-256"]
    assert sig_header.startswith("sha256=")

    import hashlib
    import hmac

    expected = hmac.new(b"shared-secret", captured["body"], hashlib.sha256).hexdigest()
    assert sig_header == f"sha256={expected}"


@pytest.mark.asyncio
async def test_transmitter_no_receivers_configured_returns_empty(db_session):
    """With no caep_receiver_urls configured, transmission is a documented
    no-op rather than an error (mirrors WebhookHITLProvider's log-only mode)."""
    settings = Settings(
        secret_key="test-secret-key-for-unit-tests-only-64chars-long-padding!!",
        server_url="https://authgent.example.com",
        caep_receiver_urls=None,
    )
    jwks = JWKSService(settings)
    transmitter = CAEPTransmitter(jwks, settings)

    results = await transmitter.transmit_session_revoked(
        db_session, actor_id="a", client_id="c", jti="t", reason="r"
    )
    assert results == []


@pytest.mark.asyncio
async def test_transmitter_retries_then_succeeds(db_session):
    """A receiver that fails twice then succeeds on the third attempt is
    still recorded as delivered, with attempts=3."""
    settings = Settings(
        secret_key="test-secret-key-for-unit-tests-only-64chars-long-padding!!",
        server_url="https://authgent.example.com",
        caep_receiver_urls="https://receiver.example.com/ssf",
        caep_retries=3,
        caep_backoff="0.001,0.001,0.001",
    )
    jwks = JWKSService(settings)

    call_count = {"n": 0}

    async def flaky_post(self, url, content=None, headers=None):
        call_count["n"] += 1
        if call_count["n"] < 3:
            return httpx.Response(503)
        return httpx.Response(200)

    with patch("httpx.AsyncClient.post", flaky_post):
        transmitter = CAEPTransmitter(jwks, settings)
        results = await transmitter.transmit_session_revoked(
            db_session, actor_id="a", client_id="c", jti="t", reason="r"
        )

    assert len(results) == 1
    assert results[0].delivered is True
    assert results[0].attempts == 3
    assert call_count["n"] == 3


@pytest.mark.asyncio
async def test_transmitter_exhausts_retries_and_reports_failure(db_session):
    """A receiver that always fails is reported as not delivered, with the
    full retry budget consumed and the last error captured."""
    settings = Settings(
        secret_key="test-secret-key-for-unit-tests-only-64chars-long-padding!!",
        server_url="https://authgent.example.com",
        caep_receiver_urls="https://receiver.example.com/ssf",
        caep_retries=2,
        caep_backoff="0.001,0.001",
    )
    jwks = JWKSService(settings)

    async def always_fail(self, url, content=None, headers=None):
        return httpx.Response(500, text="internal error")

    with patch("httpx.AsyncClient.post", always_fail):
        transmitter = CAEPTransmitter(jwks, settings)
        results = await transmitter.transmit_session_revoked(
            db_session, actor_id="a", client_id="c", jti="t", reason="r"
        )

    assert len(results) == 1
    assert results[0].delivered is False
    assert results[0].attempts == 3  # initial + 2 retries
    assert "500" in results[0].error


@pytest.mark.asyncio
async def test_transmitter_delivers_independently_to_multiple_receivers(db_session):
    """A slow/failing receiver must not block delivery to the others."""
    settings = Settings(
        secret_key="test-secret-key-for-unit-tests-only-64chars-long-padding!!",
        server_url="https://authgent.example.com",
        caep_receiver_urls="https://good.example.com/ssf,https://bad.example.com/ssf",
        caep_retries=1,
        caep_backoff="0.001",
    )
    jwks = JWKSService(settings)

    async def selective_post(self, url, content=None, headers=None):
        if "bad" in url:
            return httpx.Response(500)
        return httpx.Response(200)

    with patch("httpx.AsyncClient.post", selective_post):
        transmitter = CAEPTransmitter(jwks, settings)
        results = await transmitter.transmit_session_revoked(
            db_session, actor_id="a", client_id="c", jti="t", reason="r"
        )

    by_url = {r.receiver_url: r for r in results}
    assert by_url["https://good.example.com/ssf"].delivered is True
    assert by_url["https://bad.example.com/ssf"].delivered is False


# ── TokenService.flag_compromised ──


def _register_client(test_client, *, grant_types=None, scope="read write"):
    resp = test_client.post(
        "/register",
        json={
            "client_name": f"caep-{secrets.token_hex(4)}",
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
    return resp.json()["access_token"]


def _active(test_client, token):
    resp = test_client.post("/introspect", data={"token": token})
    assert resp.status_code == 200
    return resp.json()["active"]


async def _grant_operator_scope_out_of_band(db_session, client_id, scope="admin:security"):
    """Simulate an operator being granted a privileged scope out-of-band.

    Registration itself now refuses this scope at self-registration time
    (see ClientService.register_client and
    test_register_rejects_self_granted_operator_scope below), so tests that
    need a genuine operator caller must grant it directly against the row,
    the same way a real deployment would need an out-of-band admin action
    since this prototype defines no in-band elevation path."""
    from sqlalchemy import select

    from authgent_server.models.oauth_client import OAuthClient

    stmt = select(OAuthClient).where(OAuthClient.client_id == client_id)
    result = await db_session.execute(stmt)
    client = result.scalar_one()
    client.scope = scope
    await db_session.commit()


async def _sign_test_token(jwks, settings, db_session, *, jti, sub, client_id, ttl=900):
    """Build and sign a real access token, for tests that need
    flag_compromised to verify a genuine, previously-issued token rather
    than a bare jti string."""
    from datetime import UTC, datetime, timedelta

    now = datetime.now(UTC)
    claims = {
        "iss": settings.server_url,
        "sub": sub,
        "aud": settings.server_url,
        "exp": int((now + timedelta(seconds=ttl)).timestamp()),
        "iat": int(now.timestamp()),
        "jti": jti,
        "scope": "read",
        "client_id": client_id,
    }
    return await jwks.sign_jwt(db_session, claims)


@pytest.mark.asyncio
async def test_flag_compromised_via_service_blocklists_and_transmits(db_session, monkeypatch):
    """Direct service-level test: flag_compromised verifies the real token,
    blocklists its jti, cascades to descendants (none here), logs audit
    events, and calls the CAEP transmitter exactly once with subject fields
    read from the token's own verified claims (not caller-supplied ones)."""
    from authgent_server.services.audit_service import AuditService
    from authgent_server.services.delegation_service import DelegationService
    from authgent_server.services.jwks_service import JWKSService
    from authgent_server.services.token_service import TokenService

    settings = Settings(
        secret_key="test-secret-key-for-unit-tests-only-64chars-long-padding!!",
        server_url="https://authgent.example.com",
        caep_receiver_urls="https://receiver.example.com/ssf",
    )
    jwks = JWKSService(settings)
    delegation = DelegationService(settings)
    audit = AuditService()
    token_service = TokenService(settings=settings, jwks=jwks, delegation=delegation, audit=audit)

    captured_calls = []

    async def fake_transmit(self, db, *, actor_id, client_id, jti, reason):
        captured_calls.append(
            {"actor_id": actor_id, "client_id": client_id, "jti": jti, "reason": reason}
        )
        return []

    monkeypatch.setattr(
        "authgent_server.providers.caep.CAEPTransmitter.transmit_session_revoked",
        fake_transmit,
    )

    token = await _sign_test_token(
        jwks, settings, db_session,
        jti="tok_compromise_test", sub="client:agnt_compromised", client_id="agnt_compromised",
    )

    assert await token_service.is_token_revoked(db_session, "tok_compromise_test") is False

    await token_service.flag_compromised(
        db_session,
        token,
        "detected_exfiltration",
        operator_client_id="client_operator",
    )

    assert await token_service.is_token_revoked(db_session, "tok_compromise_test") is True
    assert len(captured_calls) == 1
    assert captured_calls[0]["jti"] == "tok_compromise_test"
    assert captured_calls[0]["actor_id"] == "client:agnt_compromised"
    assert captured_calls[0]["client_id"] == "agnt_compromised"
    assert captured_calls[0]["reason"] == "detected_exfiltration"


@pytest.mark.asyncio
async def test_flag_compromised_rejects_fabricated_token(db_session, monkeypatch):
    """A string with no corresponding real, signed token must be rejected
    before any blocklisting or CAEP transmission — closes the gap an
    earlier version of this method had (bare jti argument, no proof the
    token was ever issued by this server)."""
    from authgent_server.services.audit_service import AuditService
    from authgent_server.services.delegation_service import DelegationService
    from authgent_server.services.jwks_service import JWKSService
    from authgent_server.services.token_service import TokenService

    settings = Settings(
        secret_key="test-secret-key-for-unit-tests-only-64chars-long-padding!!",
        server_url="https://authgent.example.com",
        caep_receiver_urls="https://receiver.example.com/ssf",
    )
    jwks = JWKSService(settings)
    delegation = DelegationService(settings)
    audit = AuditService()
    token_service = TokenService(settings=settings, jwks=jwks, delegation=delegation, audit=audit)

    transmit_calls = []

    async def spy_transmit(self, db, **kwargs):
        transmit_calls.append(kwargs)
        return []

    monkeypatch.setattr(
        "authgent_server.providers.caep.CAEPTransmitter.transmit_session_revoked",
        spy_transmit,
    )

    with pytest.raises(Exception):
        await token_service.flag_compromised(
            db_session,
            "not-a-real-jwt-just-a-string",
            "fabricated",
            operator_client_id="attacker",
        )

    assert transmit_calls == []
    assert await token_service.is_token_revoked(db_session, "not-a-real-jwt-just-a-string") is False


@pytest.mark.asyncio
async def test_flag_compromised_cascades_to_descendants(db_session, monkeypatch):
    """A token exchanged from the flagged root must also end up blocklisted,
    reusing the same _cascade_revoke_descendants path revoke_token uses."""
    from authgent_server.models.delegation_receipt import DelegationReceipt
    from authgent_server.services.audit_service import AuditService
    from authgent_server.services.delegation_service import DelegationService
    from authgent_server.services.jwks_service import JWKSService
    from authgent_server.services.token_service import TokenService

    settings = Settings(
        secret_key="test-secret-key-for-unit-tests-only-64chars-long-padding!!",
        server_url="https://authgent.example.com",
        caep_receiver_urls=None,  # no transmission needed for this test
    )
    jwks = JWKSService(settings)
    delegation = DelegationService(settings)
    audit = AuditService()
    token_service = TokenService(settings=settings, jwks=jwks, delegation=delegation, audit=audit)

    db_session.add(
        DelegationReceipt(
            token_jti="tok_child",
            parent_token_jti="tok_root",
            actor_id="client:child",
            receipt_jwt="unused",
            chain_hash="unused",
        )
    )
    await db_session.commit()

    root_token = await _sign_test_token(
        jwks, settings, db_session, jti="tok_root", sub="client:agnt", client_id="agnt",
    )
    await token_service.flag_compromised(
        db_session, root_token, "compromised", operator_client_id="op",
    )

    assert await token_service.is_token_revoked(db_session, "tok_root") is True
    assert await token_service.is_token_revoked(db_session, "tok_child") is True


@pytest.mark.asyncio
async def test_flag_compromised_is_idempotent(db_session, monkeypatch):
    """Calling flag_compromised twice on the same token must not raise."""
    from authgent_server.services.audit_service import AuditService
    from authgent_server.services.delegation_service import DelegationService
    from authgent_server.services.jwks_service import JWKSService
    from authgent_server.services.token_service import TokenService

    settings = Settings(
        secret_key="test-secret-key-for-unit-tests-only-64chars-long-padding!!",
        server_url="https://authgent.example.com",
        caep_receiver_urls=None,
    )
    jwks = JWKSService(settings)
    delegation = DelegationService(settings)
    audit = AuditService()
    token_service = TokenService(settings=settings, jwks=jwks, delegation=delegation, audit=audit)

    dup_token = await _sign_test_token(
        jwks, settings, db_session, jti="tok_dup", sub="client:agnt", client_id="agnt",
    )
    await token_service.flag_compromised(
        db_session, dup_token, "first", operator_client_id="op",
    )
    await token_service.flag_compromised(
        db_session, dup_token, "second", operator_client_id="op",
    )
    assert await token_service.is_token_revoked(db_session, "tok_dup") is True


# ── POST /security/tokens/compromise endpoint ──


@pytest.mark.asyncio
async def test_compromise_endpoint_requires_bearer_token(test_client):
    resp = test_client.post("/security/tokens/compromise", json={"token": "tok_x"})
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_compromise_endpoint_requires_operator_scope(test_client):
    """A valid token WITHOUT admin:security scope must be rejected."""
    creds = _register_client(test_client, scope="read write")
    token = _get_token(test_client, creds, scope="read write")

    resp = test_client.post(
        "/security/tokens/compromise",
        json={"token": "tok_x"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_register_rejects_self_granted_operator_scope(test_client):
    """A client cannot self-register with admin:security (or admin:register):
    RFC 7591 self-registration under registration_policy=open proves only
    that the caller can reach the endpoint, never authority to hold a
    privileged scope. Closes the gap where any anonymous caller could
    self-grant admin:security and immediately act as a CAEP operator."""
    resp = test_client.post(
        "/register",
        json={
            "client_name": "self-granted-operator",
            "grant_types": ["client_credentials"],
            "scope": "admin:security",
        },
    )
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_compromise_endpoint_flags_token_with_operator_scope(test_client, db_session):
    """A caller genuinely holding admin:security (granted out-of-band, since
    self-registration with this scope is now rejected) can flag another
    agent's real, previously-issued token; the victim token becomes
    inactive afterward and the CAEP subject reflects the victim, not the
    operator."""
    victim_creds = _register_client(test_client, scope="read write")
    victim_token = _get_token(test_client, victim_creds, scope="read write")
    assert _active(test_client, victim_token) is True

    operator_creds = _register_client(test_client, scope="read write")
    await _grant_operator_scope_out_of_band(db_session, operator_creds["client_id"])
    operator_token = _get_token(test_client, operator_creds, scope="admin:security")

    resp = test_client.post(
        "/security/tokens/compromise",
        json={"token": victim_token, "reason": "detected_exfiltration"},
        headers={"Authorization": f"Bearer {operator_token}"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["caep_deliveries"] == []  # no receivers configured in tests

    assert _active(test_client, victim_token) is False


@pytest.mark.asyncio
async def test_compromise_endpoint_rejects_fabricated_token(test_client, db_session):
    """An operator holding admin:security still cannot flag a fabricated,
    never-issued token string — flag_compromised's own verify_jwt call
    rejects it before any blocklisting or CAEP transmission."""
    operator_creds = _register_client(test_client, scope="read write")
    await _grant_operator_scope_out_of_band(db_session, operator_creds["client_id"])
    operator_token = _get_token(test_client, operator_creds, scope="admin:security")

    resp = test_client.post(
        "/security/tokens/compromise",
        json={"token": "not-a-real-jwt", "reason": "fabricated"},
        headers={"Authorization": f"Bearer {operator_token}"},
    )
    assert resp.status_code >= 400


@pytest.mark.asyncio
async def test_revoke_token_does_not_transmit_caep(db_session, monkeypatch):
    """Regression guard: routine RFC 7009 self-revocation (revoke_token)
    must NOT trigger CAEP transmission. Only flag_compromised does. This
    protects the design decision documented on flag_compromised (routine
    revocation stays a purely local, unbroadcast bookkeeping change)."""
    from authgent_server.services.audit_service import AuditService
    from authgent_server.services.delegation_service import DelegationService
    from authgent_server.services.jwks_service import JWKSService
    from authgent_server.services.token_service import TokenService

    settings = Settings(
        secret_key="test-secret-key-for-unit-tests-only-64chars-long-padding!!",
        server_url="https://authgent.example.com",
        caep_receiver_urls="https://receiver.example.com/ssf",
    )
    jwks = JWKSService(settings)
    delegation = DelegationService(settings)
    audit = AuditService()
    token_service = TokenService(settings=settings, jwks=jwks, delegation=delegation, audit=audit)

    transmit_calls = []

    async def spy_transmit(self, db, **kwargs):
        transmit_calls.append(kwargs)
        return []

    monkeypatch.setattr(
        "authgent_server.providers.caep.CAEPTransmitter.transmit_session_revoked",
        spy_transmit,
    )

    from datetime import UTC, datetime, timedelta

    now = datetime.now(UTC)
    claims = {
        "iss": settings.server_url,
        "sub": "client:revoke-test",
        "aud": settings.server_url,
        "exp": int((now + timedelta(seconds=900)).timestamp()),
        "iat": int(now.timestamp()),
        "jti": "tok_revoke_regression",
        "scope": "read",
        "client_id": "revoke-test-client",
    }
    token = await jwks.sign_jwt(db_session, claims)

    await token_service.revoke_token(db_session, token, "revoke-test-client")

    assert await token_service.is_token_revoked(db_session, "tok_revoke_regression") is True
    assert transmit_calls == []
