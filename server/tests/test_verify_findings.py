"""Regression tests for two findings from adversarial review of the CAEP
transmitter prototype (see docs/security-advisories/
2026-08-caep-transmitter-prototype.md). Originally written as
proof-of-concept files demonstrating the bugs (asserting the *broken*
behavior succeeded); updated in place to assert the fixed behavior, since
that's the regression coverage worth keeping. See test_caep.py for the
equivalent, more complete coverage — these are kept as an independent
record that the exact scenarios the reviewer used are now closed."""

import pytest
from sqlalchemy import select

from authgent_server.models.oauth_client import OAuthClient


def _register(tc, scope):
    resp = tc.post("/register", json={"client_name": "x", "grant_types": ["client_credentials"], "scope": scope})
    return resp


def _token(tc, creds, scope):
    resp = tc.post("/token", data={"grant_type": "client_credentials", "client_id": creds["client_id"], "client_secret": creds["client_secret"], "scope": scope})
    assert resp.status_code == 200, resp.text
    return resp.json()["access_token"]


@pytest.mark.asyncio
async def test_subject_identity_bug_fixed(test_client, db_session):
    """Was: the CAEP SET's subject was populated from the operator's own
    identity, not the victim's. Now: flag_compromised derives actor_id/
    client_id from the verified victim token's own claims."""
    victim_resp = _register(test_client, "read write")
    assert victim_resp.status_code == 201
    victim = victim_resp.json()
    victim_tok = _token(test_client, victim, "read write")

    operator_resp = _register(test_client, "read write")
    assert operator_resp.status_code == 201
    operator = operator_resp.json()
    stmt = select(OAuthClient).where(OAuthClient.client_id == operator["client_id"])
    result = await db_session.execute(stmt)
    row = result.scalar_one()
    row.scope = "admin:security"
    await db_session.commit()
    operator_tok = _token(test_client, operator, "admin:security")

    import authgent_server.providers.caep as caep_mod
    captured = {}
    orig = caep_mod.CAEPTransmitter.transmit_session_revoked

    async def spy(self, db, **kwargs):
        captured.update(kwargs)
        return []

    caep_mod.CAEPTransmitter.transmit_session_revoked = spy
    try:
        resp = test_client.post(
            "/security/tokens/compromise",
            json={"token": victim_tok, "reason": "test"},
            headers={"Authorization": f"Bearer {operator_tok}"},
        )
        assert resp.status_code == 200
    finally:
        caep_mod.CAEPTransmitter.transmit_session_revoked = orig

    assert captured["client_id"] == victim["client_id"]
    assert captured["client_id"] != operator["client_id"]


def test_self_grant_admin_scope_under_open_policy_fixed(test_client):
    """Was: any anonymous caller could self-register with admin:security
    under registration_policy=open and immediately act as a CAEP operator.
    Now: registration itself rejects the privileged scope, independent of
    registration_policy."""
    resp = _register(test_client, "admin:security")
    assert resp.status_code == 403
