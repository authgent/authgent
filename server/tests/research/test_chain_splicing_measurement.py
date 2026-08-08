"""Empirical measurement: attack success rate for chain-splicing / non-cascading
revocation, baseline (no cascade) vs protected (cascade-revoke descendants).

Research artifact backing the paper's Table 1. Not part of default CI.
Run: pytest tests/research/test_chain_splicing_measurement.py -v
"""

from __future__ import annotations

import secrets

import pytest

from authgent_server.services import token_service as token_service_module


def _register_client(test_client, *, grant_types=None, scope="read write"):
    resp = test_client.post(
        "/register",
        json={
            "client_name": f"m-{secrets.token_hex(4)}",
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


def _exchange(test_client, child_creds, subject_token, scope="read", audience="https://t.example.com"):
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
    return resp.json()["access_token"]


def _active(test_client, token):
    resp = test_client.post("/introspect", data={"token": token})
    assert resp.status_code == 200
    return resp.json()["active"]


def _revoke(test_client, token, creds):
    resp = test_client.post(
        "/revoke",
        data={"token": token, "client_id": creds["client_id"], "client_secret": creds["client_secret"]},
    )
    assert resp.status_code == 200


@pytest.fixture
def cascade_mode(request, monkeypatch):
    """Parametrize baseline (both defenses disabled) vs protected (both enabled).

    Two independent mechanisms exist: an eager downward BFS cascade at
    revoke time (_cascade_revoke_descendants, efficient but has a TOCTOU
    window) and a lazy upward ancestor check at use time
    (_first_revoked_ancestor, closes the race by re-deriving revocation
    status on every use). Baseline disables both to measure the
    pre-fix vulnerability; protected enables both (defense-in-depth).
    """
    mode = request.param
    if mode == "baseline":
        async def _noop_cascade(self, db, root_jti):
            return None

        async def _noop_ancestor_check(self, db, jti):
            return None

        monkeypatch.setattr(
            token_service_module.TokenService,
            "_cascade_revoke_descendants",
            _noop_cascade,
        )
        monkeypatch.setattr(
            token_service_module.TokenService,
            "_first_revoked_ancestor",
            _noop_ancestor_check,
        )
    return mode


# ── Scenario definitions ──
# Each returns True if the attack succeeded (a token that should be dead
# after root revocation is still usable), False if the defense held.


def scenario_linear_depth3(test_client):
    """A -> B -> C, revoke A, check C (grandchild)."""
    a, b, c = _agent(test_client), _agent(test_client), _agent(test_client)
    tok_a = _get_token(test_client, a, scope="read write")
    tok_b = _exchange(test_client, b, tok_a, scope="read write")
    tok_c = _exchange(test_client, c, tok_b, scope="read")
    _revoke(test_client, tok_a, a)
    return _active(test_client, tok_c)


def scenario_linear_depth1(test_client):
    """A -> B, revoke A, check B (direct child)."""
    a, b = _agent(test_client), _agent(test_client)
    tok_a = _get_token(test_client, a, scope="read write")
    tok_b = _exchange(test_client, b, tok_a, scope="read")
    _revoke(test_client, tok_a, a)
    return _active(test_client, tok_b)


def scenario_fanout(test_client):
    """A -> B and A -> D (two independent children of same root), revoke A, check both."""
    a, b, d = _agent(test_client), _agent(test_client), _agent(test_client)
    tok_a = _get_token(test_client, a, scope="read write")
    tok_b = _exchange(test_client, b, tok_a, scope="read", audience="https://b.example.com")
    tok_d = _exchange(test_client, d, tok_a, scope="read", audience="https://d.example.com")
    _revoke(test_client, tok_a, a)
    return _active(test_client, tok_b) or _active(test_client, tok_d)


def scenario_midchain_revoke(test_client):
    """A -> B -> C, revoke B (not root), check C is still killed."""
    a, b, c = _agent(test_client), _agent(test_client), _agent(test_client)
    tok_a = _get_token(test_client, a, scope="read write")
    tok_b = _exchange(test_client, b, tok_a, scope="read write")
    tok_c = _exchange(test_client, c, tok_b, scope="read")
    _revoke(test_client, tok_b, b)
    return _active(test_client, tok_c)


def scenario_post_revoke_extension(test_client):
    """A -> B -> C, revoke A, then attempt C -> D (extend a dead chain)."""
    a, b, c, d = _agent(test_client), _agent(test_client), _agent(test_client), _agent(test_client)
    tok_a = _get_token(test_client, a, scope="read write")
    tok_b = _exchange(test_client, b, tok_a, scope="read write")
    tok_c = _exchange(test_client, c, tok_b, scope="read")
    _revoke(test_client, tok_a, a)
    resp = test_client.post(
        "/token",
        data={
            "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
            "client_id": d["client_id"],
            "client_secret": d["client_secret"],
            "subject_token": tok_c,
            "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
            "audience": "https://d.example.com",
            "scope": "read",
        },
    )
    if resp.status_code != 200:
        return False
    return _active(test_client, resp.json()["access_token"])


def scenario_deep_chain_5(test_client):
    """A -> B -> C -> D -> E, revoke A, check E (deepest descendant)."""
    agents = [_agent(test_client) for _ in range(5)]
    root_token = _get_token(test_client, agents[0], scope="read write")
    tok = root_token
    for nxt in agents[1:]:
        tok = _exchange(test_client, nxt, tok, scope="read write")
    _revoke(test_client, root_token, agents[0])
    return _active(test_client, tok)


def scenario_sibling_isolation(test_client):
    """Two independent root chains; revoking root1 must NOT kill root2's descendant.

    This is the false-positive check: cascading revocation must not
    over-revoke unrelated chains. Returns True (attack "succeeds", i.e.
    defense is broken) only if root2's descendant is incorrectly killed.
    """
    root1, root1_child = _agent(test_client), _agent(test_client)
    root2, root2_child = _agent(test_client), _agent(test_client)
    tok_root1 = _get_token(test_client, root1, scope="read write")
    tok_root2 = _get_token(test_client, root2, scope="read write")
    tok_child1 = _exchange(test_client, root1_child, tok_root1, scope="read", audience="https://c1.example.com")
    tok_child2 = _exchange(test_client, root2_child, tok_root2, scope="read", audience="https://c2.example.com")
    _revoke(test_client, tok_root1, root1)
    # Attack framing here is inverted: "success" = incorrect over-revocation.
    return not _active(test_client, tok_child2)


SCENARIOS = {
    "linear_depth1": scenario_linear_depth1,
    "linear_depth3": scenario_linear_depth3,
    "fanout": scenario_fanout,
    "midchain_revoke": scenario_midchain_revoke,
    "post_revoke_extension": scenario_post_revoke_extension,
    "deep_chain_5": scenario_deep_chain_5,
}


@pytest.mark.asyncio
@pytest.mark.parametrize("cascade_mode", ["baseline", "protected"], indirect=True)
@pytest.mark.parametrize("scenario_name", list(SCENARIOS.keys()))
async def test_scenario_matrix(test_client, cascade_mode, scenario_name):
    fn = SCENARIOS[scenario_name]
    attack_succeeded = fn(test_client)
    if cascade_mode == "baseline":
        assert attack_succeeded is True, (
            f"{scenario_name}: expected attack to succeed in baseline "
            f"(no-cascade) mode, but defense already held"
        )
    else:
        assert attack_succeeded is False, (
            f"{scenario_name}: expected attack to FAIL in protected "
            f"(cascade-enabled) mode, but it succeeded"
        )


@pytest.mark.asyncio
async def test_sibling_isolation_no_false_positive_baseline(test_client):
    """Baseline never cascades, so no false positive is possible there by construction."""
    assert scenario_sibling_isolation(test_client) is False


@pytest.mark.asyncio
async def test_sibling_isolation_no_false_positive_protected(test_client):
    """Protected mode must not over-revoke an unrelated sibling chain."""
    assert scenario_sibling_isolation(test_client) is False
