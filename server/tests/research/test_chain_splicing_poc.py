"""Non-cascading revocation PoC (originally mislabeled "chain splicing").

Research artifact, not a production regression test (kept out of the
default suite path — see tests/research/README.md).

Terminology note: this demonstrates non-cascading revocation — revoking
a token in the middle of an RFC 8693 delegation chain does not propagate
to already-issued downstream tokens. This is distinct from the "chain
splicing" attack authgent's SECURITY.md/ARCHITECTURE.md/docs/DIAGRAMS.md
describe (replaying/grafting a token into a *different* chain, defended
by a rolling chain_hash). That chain_hash is written at issuance but
never verified anywhere in the codebase — a separate, still-open gap,
not addressed by the fix this file now exercises.

This test now asserts the FIXED (protected) behavior, since
_cascade_revoke_descendants (token_service.py) closes this specific gap.
See test_chain_splicing_measurement.py for the full baseline-vs-protected
measurement across 6 scenarios.
"""

import secrets

import pytest


def _register_client(test_client, *, grant_types=None, scope="read write"):
    resp = test_client.post(
        "/register",
        json={
            "client_name": f"splice-{secrets.token_hex(4)}",
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


def _exchange_token(
    test_client, child_creds, subject_token, scope="read", audience="https://target.example.com"
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
    assert resp.status_code == 200, resp.text
    return resp.json()


def _introspect(test_client, token):
    resp = test_client.post("/introspect", data={"token": token})
    assert resp.status_code == 200
    return resp.json()


def _revoke(test_client, token, creds):
    resp = test_client.post(
        "/revoke",
        data={
            "token": token,
            "client_id": creds["client_id"],
            "client_secret": creds["client_secret"],
        },
    )
    assert resp.status_code == 200
    return resp


@pytest.mark.asyncio
async def test_revoking_root_cascades_to_delegated_descendants(test_client):
    """Root-of-chain revocation must kill the whole chain — verifies the fix.

    Chain: agent_a (root, human-facing token) -> agent_b -> agent_c.
    agent_a's token is revoked immediately after the chain is built.
    agent_b's and agent_c's descendant tokens must become unusable, since
    their authority derives entirely from agent_a's now-revoked grant,
    and agent_c must not be able to exchange its token for a further
    hop. Before the fix (_cascade_revoke_descendants), this test failed:
    descendants stayed active and could keep extending the chain.
    """
    agent_a = _register_client(test_client, scope="read write")
    agent_b = _register_client(
        test_client,
        grant_types=["client_credentials", "urn:ietf:params:oauth:grant-type:token-exchange"],
        scope="read write",
    )
    agent_c = _register_client(
        test_client,
        grant_types=["client_credentials", "urn:ietf:params:oauth:grant-type:token-exchange"],
        scope="read",
    )
    agent_d = _register_client(
        test_client,
        grant_types=["client_credentials", "urn:ietf:params:oauth:grant-type:token-exchange"],
        scope="read",
    )

    token_a = _get_token(test_client, agent_a, scope="read write")["access_token"]
    token_b = _exchange_token(test_client, agent_b, token_a, scope="read write")["access_token"]
    token_c = _exchange_token(test_client, agent_c, token_b, scope="read")["access_token"]

    # Sanity: chain is live before revocation.
    assert _introspect(test_client, token_a)["active"] is True
    assert _introspect(test_client, token_b)["active"] is True
    assert _introspect(test_client, token_c)["active"] is True

    # Revoke the root of the chain.
    _revoke(test_client, token_a, agent_a)
    assert _introspect(test_client, token_a)["active"] is False, (
        "sanity check: root token itself must introspect as revoked"
    )

    # FIX VERIFICATION: descendants issued from the now-revoked root must die too.
    introspect_b = _introspect(test_client, token_b)
    introspect_c = _introspect(test_client, token_c)
    assert introspect_b["active"] is False, (
        "regression: descendant token_b remained active despite root "
        "revocation (cascade not enforced)"
    )
    assert introspect_c["active"] is False, (
        "regression: descendant token_c remained active despite root "
        "revocation (cascade not enforced)"
    )

    # FIX VERIFICATION, further: the dead chain must not be extendable.
    # agent_c attempting to exchange its now-revoked token for a token
    # scoped to a brand new downstream agent_d must be rejected.
    resp = test_client.post(
        "/token",
        data={
            "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
            "client_id": agent_d["client_id"],
            "client_secret": agent_d["client_secret"],
            "subject_token": token_c,
            "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
            "audience": "https://target-d.example.com",
            "scope": "read",
        },
    )
    assert resp.status_code in (400, 401, 403), (
        "regression: agent_d minted a fresh hop from a chain descending "
        "from a revoked root; expected the exchange to be rejected, got "
        f"{resp.status_code}"
    )
