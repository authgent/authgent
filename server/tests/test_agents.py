"""Tests for CRUD /agents — Agent Identity Registry."""

from fastapi.testclient import TestClient


def test_create_agent(test_client: TestClient) -> None:
    resp = test_client.post(
        "/agents",
        json={
            "name": "search-bot",
            "owner": "dhruv",
            "allowed_scopes": ["search:execute"],
            "capabilities": ["search", "summarize"],
        },
    )
    assert resp.status_code == 201
    data = resp.json()
    assert data["name"] == "search-bot"
    assert data["owner"] == "dhruv"
    assert data["status"] == "active"
    assert "client_id" in data
    assert "client_secret" in data
    assert data["client_id"].startswith("agnt_")


def test_list_agents(test_client: TestClient) -> None:
    # Create some agents
    test_client.post("/agents", json={"name": "agent-1"})
    test_client.post("/agents", json={"name": "agent-2"})

    resp = test_client.get("/agents")
    assert resp.status_code == 200
    data = resp.json()
    assert "items" in data
    assert "total" in data
    assert data["total"] >= 2


def test_get_agent(test_client: TestClient) -> None:
    create_resp = test_client.post("/agents", json={"name": "get-me"})
    agent_id = create_resp.json()["id"]

    resp = test_client.get(f"/agents/{agent_id}")
    assert resp.status_code == 200
    assert resp.json()["name"] == "get-me"


def test_update_agent(test_client: TestClient) -> None:
    create_resp = test_client.post("/agents", json={"name": "update-me"})
    agent_id = create_resp.json()["id"]

    resp = test_client.patch(
        f"/agents/{agent_id}",
        json={
            "description": "Updated description",
            "allowed_scopes": ["new:scope"],
        },
    )
    assert resp.status_code == 200
    assert resp.json()["description"] == "Updated description"


def test_deactivate_agent(test_client: TestClient) -> None:
    create_resp = test_client.post("/agents", json={"name": "deactivate-me"})
    agent_id = create_resp.json()["id"]

    resp = test_client.delete(f"/agents/{agent_id}")
    assert resp.status_code == 200
    assert resp.json()["status"] == "inactive"


def test_deactivated_agent_cannot_get_new_tokens(test_client: TestClient) -> None:
    """Deactivating an agent must prevent its OAuth client from obtaining new tokens."""
    # Create agent and get credentials
    create_resp = test_client.post(
        "/agents",
        json={
            "name": "soon-deactivated",
            "allowed_scopes": ["read"],
        },
    )
    assert create_resp.status_code == 201
    data = create_resp.json()
    agent_id = data["id"]
    client_id = data["client_id"]
    client_secret = data["client_secret"]

    # Token works while agent is active
    token_resp = test_client.post(
        "/token",
        data={
            "grant_type": "client_credentials",
            "client_id": client_id,
            "client_secret": client_secret,
            "scope": "read",
        },
    )
    assert token_resp.status_code == 200
    assert "access_token" in token_resp.json()

    # Deactivate the agent
    deactivate_resp = test_client.delete(f"/agents/{agent_id}")
    assert deactivate_resp.status_code == 200
    assert deactivate_resp.json()["status"] == "inactive"

    # Token request must now fail
    token_resp2 = test_client.post(
        "/token",
        data={
            "grant_type": "client_credentials",
            "client_id": client_id,
            "client_secret": client_secret,
            "scope": "read",
        },
    )
    assert token_resp2.status_code == 401
    assert "deactivated" in token_resp2.json().get("error_description", "").lower()


def test_deactivated_agent_token_still_introspects(test_client: TestClient) -> None:
    """Tokens issued before deactivation are still valid (until they expire or are revoked)."""
    create_resp = test_client.post(
        "/agents",
        json={
            "name": "pre-deactivation-token",
            "allowed_scopes": ["read"],
        },
    )
    data = create_resp.json()
    agent_id = data["id"]
    client_id = data["client_id"]
    client_secret = data["client_secret"]

    # Get a token while active
    token_resp = test_client.post(
        "/token",
        data={
            "grant_type": "client_credentials",
            "client_id": client_id,
            "client_secret": client_secret,
            "scope": "read",
        },
    )
    access_token = token_resp.json()["access_token"]

    # Deactivate
    test_client.delete(f"/agents/{agent_id}")

    # Previously issued token is still active (bearer tokens are stateless)
    intro_resp = test_client.post("/introspect", data={"token": access_token})
    assert intro_resp.status_code == 200
    assert intro_resp.json()["active"] is True


def test_get_nonexistent_agent(test_client: TestClient) -> None:
    resp = test_client.get("/agents/nonexistent_id")
    assert resp.status_code == 404


def test_agent_gets_token_exchange_grant_type(test_client: TestClient) -> None:
    """Agents created via POST /agents should have token-exchange in their grant_types."""
    create_resp = test_client.post(
        "/agents",
        json={"name": "exchange-capable", "allowed_scopes": ["read"]},
    )
    assert create_resp.status_code == 201
    data = create_resp.json()
    client_id = data["client_id"]
    client_secret = data["client_secret"]

    # Get a parent token from a separate client
    parent = test_client.post(
        "/register",
        json={"client_name": "parent", "grant_types": ["client_credentials"], "scope": "read"},
    ).json()
    parent_token = test_client.post(
        "/token",
        data={
            "grant_type": "client_credentials",
            "client_id": parent["client_id"],
            "client_secret": parent["client_secret"],
            "scope": "read",
        },
    ).json()

    # The agent's client should be able to do token exchange
    exchange_resp = test_client.post(
        "/token",
        data={
            "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
            "client_id": client_id,
            "client_secret": client_secret,
            "subject_token": parent_token["access_token"],
            "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
            "audience": "https://downstream.example.com",
            "scope": "read",
        },
    )
    assert exchange_resp.status_code == 200, (
        f"Agent should have token-exchange grant, got "
        f"{exchange_resp.status_code}: {exchange_resp.text}"
    )
    assert "access_token" in exchange_resp.json()


def test_scope_update_propagates_to_oauth_client(test_client: TestClient) -> None:
    """PATCH /agents with allowed_scopes must propagate to OAuthClient.scope.

    Regression test for privilege-persistence bug: updating Agent.allowed_scopes
    without syncing OAuthClient.scope meant old scopes were still grantable.
    """
    # Create agent with broad scopes
    create_resp = test_client.post(
        "/agents",
        json={"name": "scope-test", "allowed_scopes": ["read", "write", "admin"]},
    )
    assert create_resp.status_code == 201
    data = create_resp.json()
    agent_id = data["id"]
    client_id = data["client_id"]
    client_secret = data["client_secret"]

    # Verify agent can get admin-scoped token
    token_resp = test_client.post(
        "/token",
        data={
            "grant_type": "client_credentials",
            "client_id": client_id,
            "client_secret": client_secret,
            "scope": "admin",
        },
    )
    assert token_resp.status_code == 200, "Should get admin token before scope reduction"

    # Admin reduces scopes — removes admin
    patch_resp = test_client.patch(
        f"/agents/{agent_id}",
        json={"allowed_scopes": ["read"]},
    )
    assert patch_resp.status_code == 200
    assert patch_resp.json()["allowed_scopes"] == ["read"]

    # Now requesting admin scope should fail
    token_resp2 = test_client.post(
        "/token",
        data={
            "grant_type": "client_credentials",
            "client_id": client_id,
            "client_secret": client_secret,
            "scope": "admin",
        },
    )
    assert token_resp2.status_code in (400, 403), (
        f"Admin scope should be denied after reduction, got {token_resp2.status_code}"
    )

    # read scope should still work
    token_resp3 = test_client.post(
        "/token",
        data={
            "grant_type": "client_credentials",
            "client_id": client_id,
            "client_secret": client_secret,
            "scope": "read",
        },
    )
    assert token_resp3.status_code == 200


def test_scope_update_to_empty_revokes_all(test_client: TestClient) -> None:
    """Setting allowed_scopes to [] should clear OAuthClient.scope."""
    create_resp = test_client.post(
        "/agents",
        json={"name": "clear-scope", "allowed_scopes": ["read", "write"]},
    )
    assert create_resp.status_code == 201
    data = create_resp.json()
    agent_id = data["id"]

    patch_resp = test_client.patch(
        f"/agents/{agent_id}",
        json={"allowed_scopes": []},
    )
    assert patch_resp.status_code == 200
    assert patch_resp.json()["allowed_scopes"] == []
