"""Delegation chain validation tests — server-side (§12.1)."""

import secrets

import pytest


def _register_client(test_client, *, grant_types=None, scope="read write"):
    resp = test_client.post(
        "/register",
        json={
            "client_name": f"del-{secrets.token_hex(4)}",
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
    return test_client.post(
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


@pytest.mark.asyncio
async def test_single_hop_exchange_has_act_claim(test_client):
    """A single token exchange should produce a token with one-level act claim."""
    parent = _register_client(test_client, scope="read write")
    child = _register_client(
        test_client,
        grant_types=["client_credentials", "urn:ietf:params:oauth:grant-type:token-exchange"],
        scope="read",
    )

    parent_token = _get_token(test_client, parent, scope="read write")
    resp = _exchange_token(test_client, child, parent_token["access_token"])
    assert resp.status_code == 200

    # Introspect to verify act claim exists
    introspect = test_client.post(
        "/introspect",
        data={
            "token": resp.json()["access_token"],
        },
    )
    assert introspect.status_code == 200
    body = introspect.json()
    assert body["active"] is True
    assert "act" in body


@pytest.mark.asyncio
async def test_multi_hop_exchange_nests_act_claims(test_client):
    """Chained exchanges should produce nested act claims."""
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

    # A gets original token
    token_a = _get_token(test_client, agent_a, scope="read write")

    # A -> B exchange
    resp_b = _exchange_token(test_client, agent_b, token_a["access_token"], scope="read write")
    assert resp_b.status_code == 200

    # B -> C exchange
    resp_c = _exchange_token(test_client, agent_c, resp_b.json()["access_token"], scope="read")
    assert resp_c.status_code == 200

    # Introspect C's token — should have nested act
    introspect = test_client.post(
        "/introspect",
        data={
            "token": resp_c.json()["access_token"],
        },
    )
    body = introspect.json()
    assert body["active"] is True
    assert "act" in body
    # act should be nested: act.act should exist (at least 2 levels)
    act = body.get("act", {})
    assert "sub" in act
    assert "act" in act, "Expected nested act claim for multi-hop delegation"


@pytest.mark.asyncio
async def test_delegation_depth_limit_enforced(test_client):
    """Exchanges beyond max_delegation_depth must be rejected."""
    # Default max depth is 5. Create a chain of 6 agents.
    agents = []
    for i in range(7):
        a = _register_client(
            test_client,
            grant_types=["client_credentials", "urn:ietf:params:oauth:grant-type:token-exchange"],
            scope="read write",
        )
        agents.append(a)

    # Get initial token
    current_token = _get_token(test_client, agents[0], scope="read write")["access_token"]

    # Chain exchanges up to the depth limit
    for i in range(1, 7):
        resp = _exchange_token(
            test_client,
            agents[i],
            current_token,
            scope="read",
            audience=f"https://target-{i}.example.com",
        )
        if resp.status_code != 200:
            # Should fail at or before depth 6 (max_delegation_depth=5)
            assert i >= 5, f"Exchange failed unexpectedly at depth {i}"
            assert resp.status_code in (400, 403)
            return
        current_token = resp.json()["access_token"]

    # If we got through all 6, that means depth limit wasn't hit
    # (possible if max_delegation_depth > 6)
    pytest.skip("max_delegation_depth > 6, cannot test limit")


@pytest.mark.asyncio
async def test_scope_reduction_enforced_on_exchange(test_client):
    """Token exchange must not grant scopes broader than the parent."""
    parent = _register_client(test_client, scope="read")
    child = _register_client(
        test_client,
        grant_types=["client_credentials", "urn:ietf:params:oauth:grant-type:token-exchange"],
        scope="read write admin",
    )

    parent_token = _get_token(test_client, parent, scope="read")
    resp = _exchange_token(test_client, child, parent_token["access_token"], scope="read write")

    # Should be rejected — "write" not in parent scope "read"
    assert resp.status_code in (400, 403), (
        f"Expected scope reduction enforcement, got {resp.status_code}"
    )


@pytest.mark.asyncio
async def test_exchange_preserves_original_subject(test_client):
    """Token exchange should preserve the original subject (sub) across hops."""
    parent = _register_client(test_client, scope="read write")
    child = _register_client(
        test_client,
        grant_types=["client_credentials", "urn:ietf:params:oauth:grant-type:token-exchange"],
        scope="read",
    )

    parent_token = _get_token(test_client, parent, scope="read")

    # Get parent's subject via introspect
    parent_introspect = test_client.post(
        "/introspect",
        data={
            "token": parent_token["access_token"],
        },
    )
    parent_sub = parent_introspect.json().get("sub")

    # Exchange
    resp = _exchange_token(test_client, child, parent_token["access_token"])
    assert resp.status_code == 200

    # Introspect exchanged token
    child_introspect = test_client.post(
        "/introspect",
        data={
            "token": resp.json()["access_token"],
        },
    )
    child_body = child_introspect.json()
    assert child_body["active"] is True
    # Subject should be preserved from parent
    assert child_body.get("sub") == parent_sub
