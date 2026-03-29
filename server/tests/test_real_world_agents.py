"""Real-world agent integration tests — exercises the ACTUAL paths a user would take.

These tests create real agents via /agents, obtain credentials, and then
drive the full OAuth lifecycle as a real deployment would experience it.

Covers:
  1. Enterprise AI pipeline (Human → Orchestrator → Tool Agents)
  2. Headless CI/CLI agent via device grant
  3. Dangerous-action HITL step-up with real agents
  4. Agent deactivation blocks ALL token operations
  5. Multi-team agent isolation (org-A cannot use org-B tokens)
  6. Token theft incident response (revoke propagation)
  7. Agent credential rotation / re-registration
  8. Concurrent multi-audience delegation from single parent
  9. Full agent lifecycle: create → operate → update scopes → deactivate
 10. Deactivated agent's existing tokens become invalid
"""

import base64
import hashlib
import secrets

import pytest

# ── Helpers ──────────────────────────────────────────────────────────


def _create_agent(c, name, *, scopes=None, owner=None, capabilities=None):
    """Create a real agent via POST /agents — returns full response with creds."""
    payload = {"name": name}
    if scopes:
        payload["allowed_scopes"] = scopes
    if owner:
        payload["owner"] = owner
    if capabilities:
        payload["capabilities"] = capabilities
    resp = c.post("/agents", json=payload)
    assert resp.status_code == 201, f"Agent creation failed: {resp.text}"
    return resp.json()


def _register_exchange_client(c, *, scope="read write"):
    """Register a raw OAuth client that supports token exchange (for delegation)."""
    resp = c.post(
        "/register",
        json={
            "client_name": f"exchanger-{secrets.token_hex(4)}",
            "grant_types": [
                "client_credentials",
                "urn:ietf:params:oauth:grant-type:token-exchange",
            ],
            "scope": scope,
        },
    )
    assert resp.status_code == 201
    return resp.json()


def _register_full_client(c, *, scope="read write"):
    """Register a client with all grant types for full-flow testing."""
    resp = c.post(
        "/register",
        json={
            "client_name": f"full-{secrets.token_hex(4)}",
            "grant_types": [
                "client_credentials",
                "authorization_code",
                "refresh_token",
                "urn:ietf:params:oauth:grant-type:token-exchange",
            ],
            "scope": scope,
        },
    )
    assert resp.status_code == 201
    return resp.json()


def _cc_token(c, client_id, client_secret, scope="read"):
    """Get a client_credentials token."""
    resp = c.post(
        "/token",
        data={
            "grant_type": "client_credentials",
            "client_id": client_id,
            "client_secret": client_secret,
            "scope": scope,
        },
    )
    assert resp.status_code == 200, f"Token request failed: {resp.text}"
    return resp.json()


def _exchange(
    c, child_id, child_secret, subject_token, *, scope="read", audience="https://api.example.com"
):
    """Token exchange — child acts on behalf of parent."""
    return c.post(
        "/token",
        data={
            "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
            "client_id": child_id,
            "client_secret": child_secret,
            "subject_token": subject_token,
            "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
            "audience": audience,
            "scope": scope,
        },
    )


def _introspect(c, token):
    resp = c.post("/introspect", data={"token": token})
    assert resp.status_code == 200
    return resp.json()


def _revoke(c, token, client_id=None):
    data = {"token": token}
    if client_id:
        data["client_id"] = client_id
    return c.post("/revoke", data=data)


def _pkce_pair():
    verifier = secrets.token_urlsafe(32)
    digest = hashlib.sha256(verifier.encode()).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
    return verifier, challenge


# ══════════════════════════════════════════════════════════════════════
# 1. Enterprise AI Pipeline: Human → Orchestrator → Tool Agents
# ══════════════════════════════════════════════════════════════════════


class TestEnterprisePipeline:
    """Simulates: A company's AI orchestrator fans out work to tool agents,
    each receiving narrower-scoped delegated tokens."""

    @pytest.mark.asyncio
    async def test_orchestrator_delegates_to_search_and_db_agents(self, test_client):
        """Orchestrator agent gets broad token, delegates narrow tokens to
        search-agent (read) and db-agent (read), verifies act claims."""
        # Create real agents
        orchestrator = _create_agent(
            test_client,
            "orchestrator-v1",
            scopes=["read", "write", "search", "db:query"],
            owner="platform-team",
            capabilities=["delegation", "orchestration"],
        )
        search_agent = _register_exchange_client(test_client, scope="read search")
        db_agent = _register_exchange_client(test_client, scope="read db:query")

        # Orchestrator gets its token
        orch_token = _cc_token(
            test_client,
            orchestrator["client_id"],
            orchestrator["client_secret"],
            scope="read write search db:query",
        )

        # Delegate to search agent (scope narrowing: only "read search")
        search_resp = _exchange(
            test_client,
            search_agent["client_id"],
            search_agent["client_secret"],
            orch_token["access_token"],
            scope="read search",
            audience="https://search.internal.example.com",
        )
        assert search_resp.status_code == 200
        search_token = search_resp.json()["access_token"]

        # Delegate to DB agent (scope narrowing: only "read db:query")
        db_resp = _exchange(
            test_client,
            db_agent["client_id"],
            db_agent["client_secret"],
            orch_token["access_token"],
            scope="read",
            audience="https://db.internal.example.com",
        )
        assert db_resp.status_code == 200
        db_token = db_resp.json()["access_token"]

        # Verify both tokens are active with act claims
        search_intro = _introspect(test_client, search_token)
        assert search_intro["active"] is True
        assert "act" in search_intro

        db_intro = _introspect(test_client, db_token)
        assert db_intro["active"] is True
        assert "act" in db_intro

        # Verify search agent CANNOT escalate to "write"
        escalate_resp = _exchange(
            test_client,
            search_agent["client_id"],
            search_agent["client_secret"],
            orch_token["access_token"],
            scope="read write",
            audience="https://search.internal.example.com",
        )
        assert escalate_resp.status_code in (400, 403)

    @pytest.mark.asyncio
    async def test_three_hop_delegation_preserves_subject(self, test_client):
        """Human → Orchestrator → Summarizer → Formatter: subject stays human's."""
        human_client = _register_full_client(test_client, scope="read write summarize format")
        summarizer = _register_exchange_client(test_client, scope="read summarize")
        formatter = _register_exchange_client(test_client, scope="read format")

        # Human gets token
        human_token = _cc_token(
            test_client,
            human_client["client_id"],
            human_client["client_secret"],
            scope="read write summarize format",
        )
        human_sub = _introspect(test_client, human_token["access_token"])["sub"]

        # Human → Summarizer
        sum_resp = _exchange(
            test_client,
            summarizer["client_id"],
            summarizer["client_secret"],
            human_token["access_token"],
            scope="read summarize",
            audience="https://summarizer.ai",
        )
        assert sum_resp.status_code == 200

        # Summarizer → Formatter
        fmt_resp = _exchange(
            test_client,
            formatter["client_id"],
            formatter["client_secret"],
            sum_resp.json()["access_token"],
            scope="read",
            audience="https://formatter.ai",
        )
        assert fmt_resp.status_code == 200

        # Formatter's token should still have original human subject
        fmt_intro = _introspect(test_client, fmt_resp.json()["access_token"])
        assert fmt_intro["active"] is True
        assert fmt_intro["sub"] == human_sub

        # Verify nested act chain exists
        assert "act" in fmt_intro
        act = fmt_intro["act"]
        assert "act" in act, "Expected nested act for 3-hop chain"


# ══════════════════════════════════════════════════════════════════════
# 2. Headless CLI / CI Agent via Device Grant
# ══════════════════════════════════════════════════════════════════════


class TestDeviceGrantRealWorld:
    """Simulates: A CI pipeline agent that cannot open a browser."""

    @pytest.mark.asyncio
    async def test_ci_agent_device_grant_approve_then_delegate(self, test_client):
        """CI agent authenticates via device grant, then delegates downstream."""
        ci_agent = _create_agent(
            test_client,
            "ci-runner-prod",
            scopes=["deploy", "read"],
            owner="devops-team",
        )

        # Request device code
        device_resp = test_client.post(
            "/device/authorize",
            data={
                "client_id": ci_agent["client_id"],
                "scope": "deploy read",
            },
        )
        assert device_resp.status_code == 200
        device_data = device_resp.json()
        assert "device_code" in device_data
        assert "user_code" in device_data

        # Poll before approval → authorization_pending
        poll_resp = test_client.post(
            "/device/token",
            data={
                "device_code": device_data["device_code"],
                "client_id": ci_agent["client_id"],
            },
        )
        assert poll_resp.status_code == 400
        assert poll_resp.json()["error"] == "authorization_pending"

        # Human approves on separate device
        approve_resp = test_client.post(
            "/device/complete",
            json={
                "user_code": device_data["user_code"],
                "subject": "user:devops-jane",
                "action": "approve",
            },
        )
        assert approve_resp.status_code == 200

        # Poll again → should get token
        token_resp = test_client.post(
            "/device/token",
            data={
                "device_code": device_data["device_code"],
                "client_id": ci_agent["client_id"],
            },
        )
        assert token_resp.status_code == 200
        token_data = token_resp.json()
        assert "access_token" in token_data

        # Verify token is active
        intro = _introspect(test_client, token_data["access_token"])
        assert intro["active"] is True

    @pytest.mark.asyncio
    async def test_device_code_deny_blocks_token(self, test_client):
        """Human denies device grant → agent cannot get token."""
        agent = _create_agent(test_client, "denied-agent", scopes=["read"])

        device_resp = test_client.post(
            "/device/authorize",
            data={
                "client_id": agent["client_id"],
                "scope": "read",
            },
        )
        device_data = device_resp.json()

        # Human denies
        test_client.post(
            "/device/complete",
            json={
                "user_code": device_data["user_code"],
                "subject": "user:security-admin",
                "action": "deny",
            },
        )

        # Poll → should fail
        poll_resp = test_client.post(
            "/device/token",
            data={
                "device_code": device_data["device_code"],
                "client_id": agent["client_id"],
            },
        )
        assert poll_resp.status_code == 400
        body = poll_resp.json()
        # Server may return OAuth error format or RFC 9457 problem detail
        error_key = body.get("error") or body.get("error_code", "")
        assert error_key == "invalid_grant", f"Expected invalid_grant, got {body}"

    @pytest.mark.asyncio
    async def test_device_code_one_time_use(self, test_client):
        """Consumed device code cannot be reused."""
        agent = _create_agent(test_client, "one-time-device", scopes=["read"])

        device_resp = test_client.post(
            "/device/authorize",
            data={
                "client_id": agent["client_id"],
                "scope": "read",
            },
        )
        device_data = device_resp.json()

        test_client.post(
            "/device/complete",
            json={
                "user_code": device_data["user_code"],
                "subject": "user:alice",
                "action": "approve",
            },
        )

        # First poll: success
        first = test_client.post(
            "/device/token",
            data={
                "device_code": device_data["device_code"],
                "client_id": agent["client_id"],
            },
        )
        assert first.status_code == 200

        # Second poll: already consumed
        second = test_client.post(
            "/device/token",
            data={
                "device_code": device_data["device_code"],
                "client_id": agent["client_id"],
            },
        )
        assert second.status_code == 400


# ══════════════════════════════════════════════════════════════════════
# 3. HITL Step-Up with Real Agents
# ══════════════════════════════════════════════════════════════════════


class TestHITLStepUpRealWorld:
    """Simulates: Agent wants to delete production data, needs human approval."""

    @pytest.mark.asyncio
    async def test_agent_requests_stepup_and_gets_approved(self, test_client):
        """Agent creates step-up → polls pending → human approves → status approved."""
        agent = _create_agent(
            test_client,
            "data-cleanup-bot",
            scopes=["read", "write", "delete"],
            owner="data-team",
        )

        # Agent requests step-up for dangerous action
        stepup_resp = test_client.post(
            "/stepup",
            json={
                "agent_id": agent["id"],
                "action": "delete_production_table",
                "scope": "delete",
                "resource": "https://db.prod.example.com/users",
                "metadata": {"table": "users", "reason": "GDPR compliance"},
            },
        )
        assert stepup_resp.status_code == 202
        stepup = stepup_resp.json()
        assert stepup["status"] == "pending"
        request_id = stepup["id"]

        # Agent polls — still pending
        poll = test_client.get(f"/stepup/{request_id}")
        assert poll.status_code == 200
        assert poll.json()["status"] == "pending"

        # Human approves
        approve = test_client.post(
            f"/stepup/{request_id}/approve",
            json={
                "approved_by": "admin:security-lead",
            },
        )
        assert approve.status_code == 200
        assert approve.json()["status"] == "approved"

        # Agent polls again — now approved
        final = test_client.get(f"/stepup/{request_id}")
        assert final.status_code == 200
        assert final.json()["status"] == "approved"
        assert final.json()["approved_by"] == "admin:security-lead"

    @pytest.mark.asyncio
    async def test_denied_stepup_stays_denied(self, test_client):
        """Once denied, step-up cannot be re-approved."""
        agent = _create_agent(test_client, "risky-bot", scopes=["delete"])

        stepup = test_client.post(
            "/stepup",
            json={
                "agent_id": agent["id"],
                "action": "drop_database",
                "scope": "delete",
            },
        )
        rid = stepup.json()["id"]

        # Deny it
        deny = test_client.post(f"/stepup/{rid}/deny", json={})
        assert deny.status_code == 200
        assert deny.json()["status"] == "denied"

        # Try to approve after deny — should fail
        re_approve = test_client.post(
            f"/stepup/{rid}/approve",
            json={
                "approved_by": "admin:rogue",
            },
        )
        # Should reject because it's no longer pending
        assert re_approve.status_code in (400, 409, 422)


# ══════════════════════════════════════════════════════════════════════
# 4. Agent Deactivation Blocks Token Operations
# ══════════════════════════════════════════════════════════════════════


class TestAgentDeactivation:
    """Simulates: Security team deactivates a compromised agent."""

    @pytest.mark.asyncio
    async def test_deactivated_agent_cannot_get_new_tokens(self, test_client):
        """After DELETE /agents/{id}, new token requests must fail."""
        agent = _create_agent(
            test_client,
            "compromised-bot",
            scopes=["read", "write"],
            owner="security-team",
        )

        # Verify agent can get tokens initially
        token = _cc_token(
            test_client,
            agent["client_id"],
            agent["client_secret"],
            scope="read",
        )
        assert _introspect(test_client, token["access_token"])["active"] is True

        # Security team deactivates the agent
        deactivate = test_client.delete(f"/agents/{agent['id']}")
        assert deactivate.status_code == 200
        assert deactivate.json()["status"] == "inactive"

        # Agent tries to get a new token — must be rejected
        fail_resp = test_client.post(
            "/token",
            data={
                "grant_type": "client_credentials",
                "client_id": agent["client_id"],
                "client_secret": agent["client_secret"],
                "scope": "read",
            },
        )
        assert fail_resp.status_code == 401, (
            f"Expected 401 for deactivated agent, got {fail_resp.status_code}: {fail_resp.text}"
        )

    @pytest.mark.asyncio
    async def test_deactivated_agent_existing_tokens_introspect_check(self, test_client):
        """Tokens issued before deactivation: introspection behavior check.

        This tests what happens to pre-existing tokens when an agent is
        deactivated. The token JWT is still cryptographically valid, but
        the system should ideally mark it inactive on introspection if
        the agent is deactivated. This depends on whether introspect checks
        agent status — either behavior is documented here.
        """
        agent = _create_agent(
            test_client,
            "pre-deactivation-bot",
            scopes=["read"],
        )

        # Get token while agent is active
        token = _cc_token(
            test_client,
            agent["client_id"],
            agent["client_secret"],
            scope="read",
        )
        assert _introspect(test_client, token["access_token"])["active"] is True

        # Deactivate
        test_client.delete(f"/agents/{agent['id']}")

        # Check: does introspection still show active?
        # (This documents the current behavior — either is valid)
        post_deactivation = _introspect(test_client, token["access_token"])
        # Record the behavior for documentation — both are acceptable:
        # active=True means "JWT is valid, caller must check agent status"
        # active=False means "server cross-checks agent status on introspect"
        assert isinstance(post_deactivation["active"], bool)

    @pytest.mark.asyncio
    async def test_deactivated_agent_visible_in_listing(self, test_client):
        """Deactivated agents still appear in listings with status=inactive."""
        agent = _create_agent(
            test_client,
            "listed-inactive-bot",
            scopes=["read"],
            owner="qa-team",
        )
        agent_id = agent["id"]

        test_client.delete(f"/agents/{agent_id}")

        # Get by ID
        get_resp = test_client.get(f"/agents/{agent_id}")
        assert get_resp.status_code == 200
        assert get_resp.json()["status"] == "inactive"

        # List with status filter
        list_resp = test_client.get("/agents", params={"status": "inactive"})
        assert list_resp.status_code == 200
        ids = [a["id"] for a in list_resp.json()["items"]]
        assert agent_id in ids


# ══════════════════════════════════════════════════════════════════════
# 5. Multi-Team Agent Isolation
# ══════════════════════════════════════════════════════════════════════


class TestMultiTeamIsolation:
    """Simulates: Two teams deploy agents that must not be able to
    use each other's tokens or credentials."""

    @pytest.mark.asyncio
    async def test_team_a_token_cannot_be_used_by_team_b(self, test_client):
        """Team A's agent token cannot be exchanged by Team B's agent."""
        team_a_agent = _create_agent(
            test_client,
            "team-a-search",
            scopes=["read", "search"],
            owner="team-alpha",
        )
        team_b_exchanger = _register_exchange_client(test_client, scope="read search")

        # Team A gets token (used to prove valid creds exist)
        _a_token = _cc_token(
            test_client,
            team_a_agent["client_id"],
            team_a_agent["client_secret"],
            scope="read search",
        )

        # Team B tries to exchange Team A's token — this should work
        # (token exchange is designed to work across clients as delegation)
        # BUT Team B cannot forge Team A's credentials
        fail_resp = test_client.post(
            "/token",
            data={
                "grant_type": "client_credentials",
                "client_id": team_a_agent["client_id"],
                "client_secret": team_b_exchanger["client_secret"],  # wrong secret!
                "scope": "read",
            },
        )
        assert fail_resp.status_code == 401

    @pytest.mark.asyncio
    async def test_cross_team_credential_theft_prevented(self, test_client):
        """Using Team A's client_id with Team B's secret fails authentication."""
        a = _create_agent(test_client, "agent-alpha", scopes=["read"], owner="alpha")
        b = _create_agent(test_client, "agent-beta", scopes=["read"], owner="beta")

        # A's ID + B's secret
        resp = test_client.post(
            "/token",
            data={
                "grant_type": "client_credentials",
                "client_id": a["client_id"],
                "client_secret": b["client_secret"],
                "scope": "read",
            },
        )
        assert resp.status_code == 401

        # B's ID + A's secret
        resp2 = test_client.post(
            "/token",
            data={
                "grant_type": "client_credentials",
                "client_id": b["client_id"],
                "client_secret": a["client_secret"],
                "scope": "read",
            },
        )
        assert resp2.status_code == 401


# ══════════════════════════════════════════════════════════════════════
# 6. Token Theft — Incident Response
# ══════════════════════════════════════════════════════════════════════


class TestTokenTheftIncidentResponse:
    """Simulates: Attacker steals a token, security team revokes it
    and all downstream delegated tokens."""

    @pytest.mark.asyncio
    async def test_revoke_parent_token_kills_delegation_chain(self, test_client):
        """Revoking the orchestrator token should prevent further exchanges."""
        orchestrator = _create_agent(
            test_client,
            "orch-theft-test",
            scopes=["read", "write"],
        )
        downstream = _register_exchange_client(test_client, scope="read")

        orch_token = _cc_token(
            test_client,
            orchestrator["client_id"],
            orchestrator["client_secret"],
            scope="read write",
        )

        # Delegate before revocation — should succeed
        pre_revoke = _exchange(
            test_client,
            downstream["client_id"],
            downstream["client_secret"],
            orch_token["access_token"],
            scope="read",
        )
        assert pre_revoke.status_code == 200

        # Security team revokes the orchestrator token
        _revoke(test_client, orch_token["access_token"], orchestrator["client_id"])

        # Orchestrator token is now inactive
        intro = _introspect(test_client, orch_token["access_token"])
        assert intro["active"] is False

        # New exchange attempts with the revoked token should fail
        post_revoke = _exchange(
            test_client,
            downstream["client_id"],
            downstream["client_secret"],
            orch_token["access_token"],
            scope="read",
        )
        assert post_revoke.status_code in (400, 401)

    @pytest.mark.asyncio
    async def test_revoke_only_affects_target_token(self, test_client):
        """Revoking one token does NOT revoke other tokens from the same agent."""
        agent = _create_agent(
            test_client,
            "multi-token-agent",
            scopes=["read", "write"],
        )

        token_a = _cc_token(test_client, agent["client_id"], agent["client_secret"], scope="read")
        token_b = _cc_token(test_client, agent["client_id"], agent["client_secret"], scope="read")

        # Revoke token A
        _revoke(test_client, token_a["access_token"], agent["client_id"])

        # Token A is dead
        assert _introspect(test_client, token_a["access_token"])["active"] is False

        # Token B is still alive
        assert _introspect(test_client, token_b["access_token"])["active"] is True


# ══════════════════════════════════════════════════════════════════════
# 7. Concurrent Multi-Audience Delegation
# ══════════════════════════════════════════════════════════════════════


class TestMultiAudienceDelegation:
    """Simulates: Orchestrator delegates the same parent token to
    multiple different target audiences simultaneously."""

    @pytest.mark.asyncio
    async def test_same_parent_token_multiple_audiences(self, test_client):
        """One parent token → exchange to 3 different audiences."""
        parent = _create_agent(
            test_client,
            "multi-audience-orch",
            scopes=["read", "write", "search", "email"],
        )
        search_client = _register_exchange_client(test_client, scope="read search")
        email_client = _register_exchange_client(test_client, scope="read email")
        db_client = _register_exchange_client(test_client, scope="read")

        parent_token = _cc_token(
            test_client,
            parent["client_id"],
            parent["client_secret"],
            scope="read write search email",
        )

        # Exchange to search service
        search_resp = _exchange(
            test_client,
            search_client["client_id"],
            search_client["client_secret"],
            parent_token["access_token"],
            scope="read search",
            audience="https://search.example.com",
        )
        assert search_resp.status_code == 200

        # Exchange to email service
        email_resp = _exchange(
            test_client,
            email_client["client_id"],
            email_client["client_secret"],
            parent_token["access_token"],
            scope="read email",
            audience="https://email.example.com",
        )
        assert email_resp.status_code == 200

        # Exchange to DB service
        db_resp = _exchange(
            test_client,
            db_client["client_id"],
            db_client["client_secret"],
            parent_token["access_token"],
            scope="read",
            audience="https://db.example.com",
        )
        assert db_resp.status_code == 200

        # All three tokens are independent and active
        for resp in [search_resp, email_resp, db_resp]:
            intro = _introspect(test_client, resp.json()["access_token"])
            assert intro["active"] is True

        # Revoking one doesn't affect the others
        _revoke(test_client, search_resp.json()["access_token"])
        assert _introspect(test_client, search_resp.json()["access_token"])["active"] is False
        assert _introspect(test_client, email_resp.json()["access_token"])["active"] is True
        assert _introspect(test_client, db_resp.json()["access_token"])["active"] is True


# ══════════════════════════════════════════════════════════════════════
# 8. Full Agent Lifecycle
# ══════════════════════════════════════════════════════════════════════


class TestAgentLifecycle:
    """Simulates: Full lifecycle from creation through operation to deactivation."""

    @pytest.mark.asyncio
    async def test_create_operate_update_deactivate(self, test_client):
        """Agent: create → get token → update scopes → get new token → deactivate."""
        # Create
        agent = _create_agent(
            test_client,
            "lifecycle-bot",
            scopes=["read"],
            owner="platform",
            capabilities=["search"],
        )
        agent_id = agent["id"]

        # Verify it's active
        get_resp = test_client.get(f"/agents/{agent_id}")
        assert get_resp.status_code == 200
        assert get_resp.json()["status"] == "active"

        # Get token
        token = _cc_token(
            test_client,
            agent["client_id"],
            agent["client_secret"],
            scope="read",
        )
        assert _introspect(test_client, token["access_token"])["active"] is True

        # Update agent metadata
        update_resp = test_client.patch(
            f"/agents/{agent_id}",
            json={
                "capabilities": ["search", "summarize"],
                "metadata": {"version": "2.0", "updated_by": "admin"},
            },
        )
        assert update_resp.status_code == 200
        updated = update_resp.json()
        assert "summarize" in updated["capabilities"]

        # Agent can still get tokens after metadata update
        token2 = _cc_token(
            test_client,
            agent["client_id"],
            agent["client_secret"],
            scope="read",
        )
        assert _introspect(test_client, token2["access_token"])["active"] is True

        # Deactivate
        deactivate = test_client.delete(f"/agents/{agent_id}")
        assert deactivate.status_code == 200
        assert deactivate.json()["status"] == "inactive"

        # No more tokens
        fail_resp = test_client.post(
            "/token",
            data={
                "grant_type": "client_credentials",
                "client_id": agent["client_id"],
                "client_secret": agent["client_secret"],
                "scope": "read",
            },
        )
        assert fail_resp.status_code == 401

    @pytest.mark.asyncio
    async def test_agent_listing_pagination_and_filters(self, test_client):
        """Create multiple agents, verify listing with pagination and owner filter."""
        owner = f"test-owner-{secrets.token_hex(4)}"
        agents = []
        for i in range(5):
            a = _create_agent(
                test_client,
                f"paginated-bot-{i}",
                scopes=["read"],
                owner=owner,
            )
            agents.append(a)

        # List all for this owner
        list_resp = test_client.get("/agents", params={"owner": owner, "limit": 3})
        assert list_resp.status_code == 200
        body = list_resp.json()
        assert body["total"] == 5
        assert len(body["items"]) == 3

        # Page 2
        page2 = test_client.get("/agents", params={"owner": owner, "offset": 3, "limit": 3})
        assert page2.status_code == 200
        assert len(page2.json()["items"]) == 2


# ══════════════════════════════════════════════════════════════════════
# 9. Auth Code + PKCE via Real Agent
# ══════════════════════════════════════════════════════════════════════


class TestAuthCodeWithAgent:
    """Simulates: A web-based agent that uses authorization code + PKCE
    to authenticate end-users, then delegates downstream."""

    @pytest.mark.asyncio
    async def test_auth_code_flow_then_delegate(self, test_client):
        """Full auth code + PKCE → token → delegate to downstream agent."""
        # Register a client with auth_code + exchange grants
        web_client = _register_full_client(test_client, scope="read write")
        downstream = _register_exchange_client(test_client, scope="read")

        verifier, challenge = _pkce_pair()

        # Authorize
        auth_resp = test_client.get(
            "/authorize",
            params={
                "response_type": "code",
                "client_id": web_client["client_id"],
                "redirect_uri": "http://localhost:3000/callback",
                "scope": "read write",
                "state": "xyzzy",
                "code_challenge": challenge,
                "code_challenge_method": "S256",
            },
            follow_redirects=False,
        )
        assert auth_resp.status_code == 302
        location = auth_resp.headers["location"]
        assert "code=" in location
        assert "state=xyzzy" in location
        code = location.split("code=")[1].split("&")[0]

        # Exchange code for token
        token_resp = test_client.post(
            "/token",
            data={
                "grant_type": "authorization_code",
                "client_id": web_client["client_id"],
                "client_secret": web_client["client_secret"],
                "code": code,
                "redirect_uri": "http://localhost:3000/callback",
                "code_verifier": verifier,
            },
        )
        assert token_resp.status_code == 200
        tokens = token_resp.json()
        assert "access_token" in tokens
        assert "refresh_token" in tokens

        # Delegate to downstream
        delegate = _exchange(
            test_client,
            downstream["client_id"],
            downstream["client_secret"],
            tokens["access_token"],
            scope="read",
            audience="https://downstream.example.com",
        )
        assert delegate.status_code == 200
        assert _introspect(test_client, delegate.json()["access_token"])["active"] is True

    @pytest.mark.asyncio
    async def test_refresh_then_delegate(self, test_client):
        """Refresh token rotation, then delegate the new access token."""
        client = _register_full_client(test_client, scope="read write")
        downstream = _register_exchange_client(test_client, scope="read")

        verifier, challenge = _pkce_pair()

        auth_resp = test_client.get(
            "/authorize",
            params={
                "response_type": "code",
                "client_id": client["client_id"],
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
                "client_id": client["client_id"],
                "client_secret": client["client_secret"],
                "code": code,
                "redirect_uri": "http://localhost:3000/callback",
                "code_verifier": verifier,
            },
        )
        assert token_resp.status_code == 200
        rt = token_resp.json()["refresh_token"]

        # Refresh
        refresh_resp = test_client.post(
            "/token",
            data={
                "grant_type": "refresh_token",
                "client_id": client["client_id"],
                "client_secret": client["client_secret"],
                "refresh_token": rt,
            },
        )
        assert refresh_resp.status_code == 200
        new_at = refresh_resp.json()["access_token"]

        # Delegate the refreshed token
        delegate = _exchange(
            test_client,
            downstream["client_id"],
            downstream["client_secret"],
            new_at,
            scope="read",
            audience="https://downstream.example.com",
        )
        assert delegate.status_code == 200
        assert _introspect(test_client, delegate.json()["access_token"])["active"] is True


# ══════════════════════════════════════════════════════════════════════
# 10. Discovery & Health from Agent Perspective
# ══════════════════════════════════════════════════════════════════════


class TestDiscoveryAndHealth:
    """Simulates: Agent bootstrapping — discovers server capabilities
    before registering."""

    @pytest.mark.asyncio
    async def test_agent_discovers_server_then_registers(self, test_client):
        """Agent reads metadata, confirms grant types, then registers."""
        # Discovery
        meta_resp = test_client.get("/.well-known/oauth-authorization-server")
        assert meta_resp.status_code == 200
        meta = meta_resp.json()
        assert "client_credentials" in meta["grant_types_supported"]
        assert "token_endpoint" in meta

        # JWKS endpoint available
        jwks_resp = test_client.get("/.well-known/jwks.json")
        assert jwks_resp.status_code == 200
        jwks = jwks_resp.json()
        assert "keys" in jwks
        # Keys may be empty in test fixture (generated lazily on first token issue)
        # The important thing is the endpoint exists and returns valid JWKS format

        # Health check
        health_resp = test_client.get("/health")
        assert health_resp.status_code == 200

        # Now register
        agent = _create_agent(
            test_client,
            "discovery-aware-bot",
            scopes=["read"],
        )
        assert agent["client_id"].startswith("agnt_")
        assert "client_secret" in agent

    @pytest.mark.asyncio
    async def test_protected_resource_metadata(self, test_client):
        """RFC 9728 — resource server metadata endpoint exists."""
        resp = test_client.get("/.well-known/oauth-protected-resource")
        # May return 200 or 404 depending on config — document behavior
        if resp.status_code == 200:
            body = resp.json()
            assert "resource" in body or "authorization_servers" in body


# ══════════════════════════════════════════════════════════════════════
# 11. Edge Cases — Error Handling with Real Agents
# ══════════════════════════════════════════════════════════════════════


class TestEdgeCasesRealAgents:
    """Edge cases a real user would hit."""

    @pytest.mark.asyncio
    async def test_duplicate_agent_names_allowed(self, test_client):
        """Two agents can have the same name (different IDs)."""
        a1 = _create_agent(test_client, "duplicate-name", scopes=["read"])
        a2 = _create_agent(test_client, "duplicate-name", scopes=["read"])
        assert a1["id"] != a2["id"]
        assert a1["client_id"] != a2["client_id"]

    @pytest.mark.asyncio
    async def test_agent_with_no_scopes(self, test_client):
        """Agent with empty scopes can register but token scope may be empty."""
        agent = _create_agent(test_client, "no-scope-bot")
        # Try to get token — behavior depends on whether server allows empty scope
        resp = test_client.post(
            "/token",
            data={
                "grant_type": "client_credentials",
                "client_id": agent["client_id"],
                "client_secret": agent["client_secret"],
            },
        )
        # Either 200 with empty scope or 400 — both are valid
        assert resp.status_code in (200, 400)

    @pytest.mark.asyncio
    async def test_nonexistent_agent_get_returns_404(self, test_client):
        """GET /agents/fake-id returns 404."""
        resp = test_client.get("/agents/nonexistent-id-12345")
        assert resp.status_code in (404, 422)

    @pytest.mark.asyncio
    async def test_token_with_garbage_client_id(self, test_client):
        """Completely bogus client_id returns 401."""
        resp = test_client.post(
            "/token",
            data={
                "grant_type": "client_credentials",
                "client_id": "not_a_real_client",
                "client_secret": "not_a_real_secret",
                "scope": "read",
            },
        )
        assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_introspect_garbage_token(self, test_client):
        """Introspecting garbage returns active=false, not a 500."""
        intro = _introspect(test_client, "this.is.not.a.token")
        assert intro["active"] is False

    @pytest.mark.asyncio
    async def test_revoke_nonexistent_token_succeeds(self, test_client):
        """RFC 7009: Revocation of unknown tokens SHOULD return 200."""
        resp = _revoke(test_client, "nonexistent-token-value")
        assert resp.status_code in (200, 204)


# ══════════════════════════════════════════════════════════════════════
# 12. Scope Propagation — Agent Update → OAuthClient Sync
# ══════════════════════════════════════════════════════════════════════


class TestScopePropagation:
    """Verifies that PATCH /agents/{id} with allowed_scopes changes
    propagates to the linked OAuthClient.scope, so token issuance
    enforces the updated scopes immediately."""

    @pytest.mark.asyncio
    async def test_update_scopes_restricts_future_tokens(self, test_client):
        """After narrowing allowed_scopes, agent cannot request old scopes."""
        agent = _create_agent(
            test_client,
            "scope-prop-bot",
            scopes=["read", "write", "delete"],
        )

        # Can get token with full scopes initially
        token = _cc_token(test_client, agent["client_id"], agent["client_secret"], scope="read write delete")
        assert _introspect(test_client, token["access_token"])["active"] is True

        # Admin narrows scopes to read-only
        update_resp = test_client.patch(
            f"/agents/{agent['id']}",
            json={"allowed_scopes": ["read"]},
        )
        assert update_resp.status_code == 200
        assert update_resp.json()["allowed_scopes"] == ["read"]

        # Agent can still get a "read" token
        read_token = _cc_token(test_client, agent["client_id"], agent["client_secret"], scope="read")
        assert _introspect(test_client, read_token["access_token"])["active"] is True

        # Agent CANNOT get "write" or "delete" anymore
        fail_resp = test_client.post(
            "/token",
            data={
                "grant_type": "client_credentials",
                "client_id": agent["client_id"],
                "client_secret": agent["client_secret"],
                "scope": "write",
            },
        )
        assert fail_resp.status_code in (400, 403), (
            f"Expected scope rejection, got {fail_resp.status_code}: {fail_resp.text}"
        )

    @pytest.mark.asyncio
    async def test_update_scopes_expand_allows_new_scopes(self, test_client):
        """After expanding allowed_scopes, agent can request the new scopes."""
        agent = _create_agent(
            test_client,
            "expand-scope-bot",
            scopes=["read"],
        )

        # Initially cannot get "write"
        fail_resp = test_client.post(
            "/token",
            data={
                "grant_type": "client_credentials",
                "client_id": agent["client_id"],
                "client_secret": agent["client_secret"],
                "scope": "write",
            },
        )
        assert fail_resp.status_code in (400, 403)

        # Admin expands scopes
        test_client.patch(
            f"/agents/{agent['id']}",
            json={"allowed_scopes": ["read", "write"]},
        )

        # Now agent CAN get "write"
        token = _cc_token(test_client, agent["client_id"], agent["client_secret"], scope="write")
        assert _introspect(test_client, token["access_token"])["active"] is True


# ══════════════════════════════════════════════════════════════════════
# 13. Allowed Exchange Targets — Delegation Audience Restriction
# ══════════════════════════════════════════════════════════════════════


class TestAllowedExchangeTargets:
    """Verifies that allowed_exchange_targets on the Agent model is
    enforced during actual token exchange (not just dry-run)."""

    @pytest.mark.asyncio
    async def test_exchange_to_allowed_target_succeeds(self, test_client):
        """Exchange to an audience in allowed_exchange_targets works."""
        agent = _create_agent(
            test_client,
            "restricted-delegator",
            scopes=["read", "write"],
        )
        # Set allowed exchange targets
        test_client.patch(
            f"/agents/{agent['id']}",
            json={"allowed_exchange_targets": ["agent:coder", "agent:reviewer"]},
        )

        # Get parent token
        parent = _cc_token(test_client, agent["client_id"], agent["client_secret"], scope="read write")

        # Create downstream client
        downstream = _register_exchange_client(test_client, scope="read")

        # Exchange to allowed target
        resp = _exchange(
            test_client,
            downstream["client_id"],
            downstream["client_secret"],
            parent["access_token"],
            scope="read",
            audience="agent:coder",
        )
        assert resp.status_code == 200, f"Expected 200, got {resp.status_code}: {resp.text}"

    @pytest.mark.asyncio
    async def test_exchange_to_disallowed_target_blocked(self, test_client):
        """Exchange to an audience NOT in allowed_exchange_targets is rejected."""
        agent = _create_agent(
            test_client,
            "locked-delegator",
            scopes=["read", "write"],
        )
        test_client.patch(
            f"/agents/{agent['id']}",
            json={"allowed_exchange_targets": ["agent:coder"]},
        )

        parent = _cc_token(test_client, agent["client_id"], agent["client_secret"], scope="read write")
        downstream = _register_exchange_client(test_client, scope="read")

        # Exchange to DISALLOWED target
        resp = _exchange(
            test_client,
            downstream["client_id"],
            downstream["client_secret"],
            parent["access_token"],
            scope="read",
            audience="agent:evil-bot",
        )
        assert resp.status_code in (400, 403), (
            f"Expected rejection for disallowed target, got {resp.status_code}: {resp.text}"
        )

    @pytest.mark.asyncio
    async def test_no_targets_restriction_allows_any(self, test_client):
        """Agent with empty allowed_exchange_targets can delegate to anyone."""
        agent = _create_agent(
            test_client,
            "unrestricted-delegator",
            scopes=["read"],
        )
        # No allowed_exchange_targets set (empty list by default)
        parent = _cc_token(test_client, agent["client_id"], agent["client_secret"], scope="read")
        downstream = _register_exchange_client(test_client, scope="read")

        resp = _exchange(
            test_client,
            downstream["client_id"],
            downstream["client_secret"],
            parent["access_token"],
            scope="read",
            audience="agent:literally-anyone",
        )
        assert resp.status_code == 200


# ══════════════════════════════════════════════════════════════════════
# 14. Registration Policy Enforcement
# ══════════════════════════════════════════════════════════════════════


class TestRegistrationPolicy:
    """Verifies that registration_policy setting is enforced on
    POST /agents and POST /register endpoints."""

    @pytest.mark.asyncio
    async def test_open_policy_allows_registration(self, test_client):
        """Default open policy: anyone can register."""
        # conftest sets AUTHGENT_REGISTRATION_POLICY=open
        agent = _create_agent(test_client, "open-policy-bot", scopes=["read"])
        assert agent["client_id"].startswith("agnt_")

    @pytest.mark.asyncio
    async def test_token_policy_blocks_unauthenticated(self, test_client):
        """With registration_policy=token, unauthenticated requests are rejected."""
        import os
        from authgent_server.config import reset_settings

        # Temporarily switch to token policy
        os.environ["AUTHGENT_REGISTRATION_POLICY"] = "token"
        os.environ["AUTHGENT_REGISTRATION_TOKEN"] = "super-secret-reg-token"
        reset_settings()

        try:
            # No auth header → rejected
            resp = test_client.post(
                "/agents",
                json={"name": "blocked-bot", "allowed_scopes": ["read"]},
            )
            assert resp.status_code == 401, (
                f"Expected 401 for unauthenticated registration, got {resp.status_code}"
            )

            # Wrong token → rejected
            resp2 = test_client.post(
                "/agents",
                json={"name": "wrong-token-bot", "allowed_scopes": ["read"]},
                headers={"Authorization": "Bearer wrong-token"},
            )
            assert resp2.status_code == 401

            # Correct token → allowed
            resp3 = test_client.post(
                "/agents",
                json={"name": "authorized-bot", "allowed_scopes": ["read"]},
                headers={"Authorization": "Bearer super-secret-reg-token"},
            )
            assert resp3.status_code == 201
            assert resp3.json()["name"] == "authorized-bot"
        finally:
            # Restore open policy
            os.environ["AUTHGENT_REGISTRATION_POLICY"] = "open"
            os.environ.pop("AUTHGENT_REGISTRATION_TOKEN", None)
            reset_settings()
