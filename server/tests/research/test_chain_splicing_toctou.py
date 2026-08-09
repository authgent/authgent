"""TOCTOU race test: does revocation still hold if the eager cascade
has NOT yet reached a descendant?

The adversarial review (2026-08-08, see publications repo README) found
a genuine race in the original eager-only fix: _cascade_revoke_descendants
walks the delegation_receipts graph downward from a newly-revoked root,
so a concurrent token-exchange that mints a new descendant after the
downward walk has already passed that level escapes the cascade
permanently. The lazy fix (_first_revoked_ancestor, checked on every
token use via verify_and_check_blocklist) closes this by walking UPWARD
from the token being checked at the moment of use, so it does not
depend on the eager cascade having reached that node.

This test simulates the race directly rather than using real threads
(the shared test-client session is synchronous, see conftest.py): it
revokes the root's jti in the blocklist WITHOUT running the eager
cascade at all, mints a new descendant token from a mid-chain token
(exactly what a concurrent request racing the cascade would do), and
confirms the descendant is still correctly rejected, because the lazy
ancestor check does not depend on cascade progress.
"""

import secrets

import pytest

from authgent_server.models.token_blocklist import TokenBlocklist


def _register_client(test_client, *, grant_types=None, scope="read write"):
    resp = test_client.post(
        "/register",
        json={
            "client_name": f"toctou-{secrets.token_hex(4)}",
            "grant_types": grant_types or ["client_credentials"],
            "scope": scope,
        },
    )
    assert resp.status_code == 201
    return resp.json()


def _agent(test_client, scope="read write"):
    return _register_client(
        test_client,
        grant_types=["client_credentials", "urn:ietf:params:oauth:grant-type:token-exchange"],
        scope=scope,
    )


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


def _exchange(
    test_client, child_creds, subject_token, scope="read", audience="https://t.example.com"
):
    resp = test_client.post(
        "/token",
        data={
            "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
            "client_id": child_creds["client_id"],
            "client_secret": child_creds["client_secret"],
            "subject_token": subject_token,
            "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
            "audience": audience,
            "scope": scope,
        },
    )
    return resp


def _decode_jti(token_service, token):
    import jwt as pyjwt

    return pyjwt.decode(token, options={"verify_signature": False}).get("jti")


@pytest.mark.asyncio
async def test_lazy_check_catches_descendant_the_eager_cascade_missed(
    test_client, db_session, monkeypatch
):
    """Simulate the race: blocklist the root directly, skip the cascade
    entirely, then confirm a brand-new descendant minted from a
    mid-chain token is still rejected because of the lazy ancestor walk.
    """
    from authgent_server.services import token_service as token_service_module

    async def _noop_cascade(self, db, root_jti):
        return None

    monkeypatch.setattr(
        token_service_module.TokenService, "_cascade_revoke_descendants", _noop_cascade
    )

    agent_a, agent_b, _agent_c, agent_d = (
        _agent(test_client),
        _agent(test_client),
        _agent(test_client),
        _agent(test_client),
    )
    token_a = _get_token(test_client, agent_a, scope="read write")
    token_b = _exchange(test_client, agent_b, token_a, scope="read write").json()["access_token"]
    token_c = _exchange(test_client, agent_b, token_b, scope="read").json()["access_token"]

    # Revoke the root. The eager cascade is a no-op (simulating "lost the
    # race" / hasn't run yet), so only token_a's own jti is blocklisted;
    # token_b and token_c are NOT directly blocklisted by this call.
    resp = test_client.post(
        "/revoke",
        data={
            "token": token_a,
            "client_id": agent_a["client_id"],
            "client_secret": agent_a["client_secret"],
        },
    )
    assert resp.status_code == 200

    # Sanity: with the cascade disabled, token_b's own jti is NOT blocklisted.
    import jwt as pyjwt

    token_b_jti = pyjwt.decode(token_b, options={"verify_signature": False})["jti"]
    stmt_check = TokenBlocklist.__table__.select().where(TokenBlocklist.jti == token_b_jti)
    result = await db_session.execute(stmt_check)
    assert result.first() is None, (
        "sanity check failed: token_b should NOT be directly blocklisted "
        "when the eager cascade is disabled"
    )

    # The race: attempt to mint a brand-new descendant token_d from
    # token_c, exactly as a concurrent request would while the (disabled,
    # in this simulation) cascade was still working through the tree.
    resp_d = _exchange(test_client, agent_d, token_c, scope="read")

    assert resp_d.status_code in (400, 401, 403), (
        "TOCTOU regression: a new descendant was mintable from a chain "
        "whose root is revoked, even though the eager cascade never "
        "reached this node. Expected the lazy ancestor check "
        f"(_first_revoked_ancestor) to reject this exchange, got "
        f"{resp_d.status_code}: {resp_d.text}"
    )
