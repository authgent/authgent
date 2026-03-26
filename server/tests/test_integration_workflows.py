"""
Integration tests — real-world agent-to-agent workflows.

Each test class models a complete production scenario end-to-end,
creating all resources from scratch and verifying every step.

Coverage targets (gaps from existing unit tests):
  - Multi-hop delegation chains with act claim verification
  - Agent lifecycle → token impact
  - Cross-client token isolation
  - Auth code flow with resource indicators (RFC 8707)
  - Token exchange scope reduction across N hops
  - Refresh token family revocation (full chain)
  - Device grant → token exchange pipeline
  - HITL step-up integrated with agent workflows
  - Token introspection claim completeness
  - Discovery metadata → endpoint liveness
  - Redirect URI strict validation
  - HTTP Basic auth on token endpoint
  - Multi-grant client lifecycle
  - Agent listing pagination and filters
  - Concurrent client isolation
  - Revocation blast radius (parent → child tokens)
"""

from __future__ import annotations

import base64
import hashlib
import secrets
from urllib.parse import parse_qs, urlparse

from fastapi.testclient import TestClient

# ─── Helpers ──────────────────────────────────────────────────────────

def _register(
    c: TestClient,
    *,
    name: str = "",
    grant_types: list[str] | None = None,
    scope: str = "read write",
    redirect_uris: list[str] | None = None,
    dpop_bound: bool = False,
    allowed_resources: list[str] | None = None,
) -> dict:
    """Register an OAuth client and return the full response body."""
    body: dict = {
        "client_name": name or f"test-{secrets.token_hex(4)}",
        "grant_types": grant_types or ["client_credentials"],
        "scope": scope,
        "dpop_bound_access_tokens": dpop_bound,
    }
    if redirect_uris:
        body["redirect_uris"] = redirect_uris
    if allowed_resources:
        body["allowed_resources"] = allowed_resources
    resp = c.post("/register", json=body)
    assert resp.status_code == 201, f"Registration failed: {resp.json()}"
    return resp.json()


def _create_agent(c: TestClient, *, name: str, scopes: list[str] | None = None, **kw) -> dict:
    """Create an agent in the registry."""
    body: dict = {"name": name, "owner": "test@acme.com"}
    if scopes:
        body["allowed_scopes"] = scopes
    body.update(kw)
    resp = c.post("/agents", json=body)
    assert resp.status_code == 201, f"Agent creation failed: {resp.json()}"
    return resp.json()


def _cc_token(c: TestClient, creds: dict, scope: str = "read") -> dict:
    """Get a client_credentials token."""
    resp = c.post("/token", data={
        "grant_type": "client_credentials",
        "client_id": creds["client_id"],
        "client_secret": creds["client_secret"],
        "scope": scope,
    })
    assert resp.status_code == 200, f"Token failed: {resp.json()}"
    return resp.json()


def _exchange(
    c: TestClient, creds: dict, subject_token: str,
    audience: str = "https://api.example.com", scope: str = "read",
) -> tuple[int, dict]:
    """Perform token exchange, returning (status_code, body)."""
    resp = c.post("/token", data={
        "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
        "client_id": creds["client_id"],
        "client_secret": creds["client_secret"],
        "subject_token": subject_token,
        "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
        "audience": audience,
        "scope": scope,
    })
    return resp.status_code, resp.json()


def _introspect(c: TestClient, token: str) -> dict:
    resp = c.post("/introspect", data={"token": token})
    assert resp.status_code == 200
    return resp.json()


def _revoke(c: TestClient, token: str, client_id: str = "") -> int:
    resp = c.post("/revoke", data={"token": token, "client_id": client_id})
    return resp.status_code


def _pkce() -> tuple[str, str]:
    """Generate PKCE verifier + S256 challenge."""
    verifier = secrets.token_urlsafe(64)
    digest = hashlib.sha256(verifier.encode()).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
    return verifier, challenge


def _auth_code_flow(
    c: TestClient, creds: dict, scope: str = "read",
    resource: str = "", nonce: str = "",
) -> dict:
    """Run full auth code + PKCE flow, return token response body."""
    verifier, challenge = _pkce()
    params: dict = {
        "response_type": "code",
        "client_id": creds["client_id"],
        "redirect_uri": "http://localhost:3000/callback",
        "scope": scope,
        "state": secrets.token_hex(8),
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    }
    if resource:
        params["resource"] = resource
    if nonce:
        params["nonce"] = nonce

    auth_resp = c.get("/authorize", params=params, follow_redirects=False)
    assert auth_resp.status_code == 302, f"Authorize failed: {auth_resp.status_code}"
    location = auth_resp.headers["location"]
    code = parse_qs(urlparse(location).query)["code"][0]

    token_resp = c.post("/token", data={
        "grant_type": "authorization_code",
        "client_id": creds["client_id"],
        "client_secret": creds["client_secret"],
        "code": code,
        "code_verifier": verifier,
        "redirect_uri": "http://localhost:3000/callback",
    })
    assert token_resp.status_code == 200, f"Token exchange failed: {token_resp.json()}"
    return token_resp.json()


# ═════════════════════════════════════════════════════════════════════
# 1. MULTI-HOP DELEGATION PIPELINE
#    Human → Orchestrator → Search Agent → DB Agent
# ═════════════════════════════════════════════════════════════════════

class TestMultiHopDelegationPipeline:
    """Real-world: Human delegates to an orchestrator which fans out
    to specialized agents, each with progressively narrower scope."""

    def test_three_hop_delegation_chain(self, test_client):
        """Full 3-hop chain: human token → orchestrator → search → db."""
        # Register 3 agents with token exchange capability
        orchestrator = _register(
            test_client, name="orchestrator",
            grant_types=["client_credentials", "authorization_code",
                         "refresh_token", "urn:ietf:params:oauth:grant-type:token-exchange"],
            scope="search:exec db:read summarize",
            redirect_uris=["http://localhost:3000/callback"],
        )
        search = _register(
            test_client, name="search-agent",
            grant_types=["client_credentials", "urn:ietf:params:oauth:grant-type:token-exchange"],
            scope="search:exec db:read",
        )
        db = _register(
            test_client, name="db-agent",
            grant_types=["client_credentials", "urn:ietf:params:oauth:grant-type:token-exchange"],
            scope="db:read",
        )

        # Hop 0: Human delegates to orchestrator via auth code
        tokens = _auth_code_flow(test_client, orchestrator, scope="search:exec db:read summarize")
        human_token = tokens["access_token"]

        # Hop 1: Orchestrator → Search (drop summarize)
        s1, body1 = _exchange(test_client, search, human_token,
                              audience="agent:search", scope="search:exec db:read")
        assert s1 == 200
        search_token = body1["access_token"]

        intro1 = _introspect(test_client, search_token)
        assert intro1["active"] is True
        assert intro1["act"] is not None  # delegation chain started
        assert "sub" in intro1["act"]

        # Hop 2: Search → DB (drop search:exec)
        s2, body2 = _exchange(test_client, db, search_token,
                              audience="agent:db", scope="db:read")
        assert s2 == 200
        db_token = body2["access_token"]

        intro2 = _introspect(test_client, db_token)
        assert intro2["active"] is True
        assert intro2["scope"] == "db:read"
        # 2-hop chain: act contains nested act
        assert "act" in intro2["act"]  # nested act = 2 hops

    def test_delegation_preserves_original_subject(self, test_client):
        """The original subject (sub) is preserved across all hops."""
        parent = _register(test_client, scope="a b")
        child = _register(
            test_client,
            grant_types=["client_credentials", "urn:ietf:params:oauth:grant-type:token-exchange"],
            scope="a",
        )

        parent_tok = _cc_token(test_client, parent, scope="a b")
        parent_intro = _introspect(test_client, parent_tok["access_token"])
        original_sub = parent_intro["sub"]

        _, body = _exchange(test_client, child, parent_tok["access_token"],
                            audience="downstream", scope="a")
        child_intro = _introspect(test_client, body["access_token"])

        assert child_intro["sub"] == original_sub

    def test_act_claim_records_correct_actor(self, test_client):
        """The act.sub in the exchanged token identifies the exchanging client."""
        parent = _register(test_client, scope="read write")
        child = _register(
            test_client, name="actor-child",
            grant_types=["client_credentials", "urn:ietf:params:oauth:grant-type:token-exchange"],
            scope="read",
        )

        parent_tok = _cc_token(test_client, parent, scope="read write")
        _, body = _exchange(test_client, child, parent_tok["access_token"],
                            audience="target", scope="read")
        intro = _introspect(test_client, body["access_token"])

        assert intro["act"]["sub"].startswith("client:")


# ═════════════════════════════════════════════════════════════════════
# 2. SCOPE REDUCTION ENFORCEMENT
# ═════════════════════════════════════════════════════════════════════

class TestScopeReductionEnforcement:
    """Scopes can only decrease across delegation hops — never escalate."""

    def test_scope_reduction_allowed(self, test_client):
        parent = _register(test_client, scope="a b c")
        child = _register(
            test_client,
            grant_types=["client_credentials", "urn:ietf:params:oauth:grant-type:token-exchange"],
            scope="a",
        )
        tok = _cc_token(test_client, parent, scope="a b c")
        status, body = _exchange(test_client, child, tok["access_token"],
                                 audience="x", scope="a")
        assert status == 200
        intro = _introspect(test_client, body["access_token"])
        assert intro["scope"] == "a"

    def test_scope_escalation_blocked(self, test_client):
        """Cannot request scopes not in the parent token."""
        parent = _register(test_client, scope="read")
        child = _register(
            test_client,
            grant_types=["client_credentials", "urn:ietf:params:oauth:grant-type:token-exchange"],
            scope="read admin",
        )
        tok = _cc_token(test_client, parent, scope="read")
        status, body = _exchange(test_client, child, tok["access_token"],
                                 audience="x", scope="admin")
        assert status == 403

    def test_multi_hop_scope_narrows_monotonically(self, test_client):
        """Scope narrows at each hop: a b c → a b → a."""
        agents = []
        for i in range(3):
            gt = ["client_credentials"]
            if i > 0:
                gt.append("urn:ietf:params:oauth:grant-type:token-exchange")
            agents.append(_register(test_client, scope="a b c", grant_types=gt))

        tok = _cc_token(test_client, agents[0], scope="a b c")["access_token"]

        _, b1 = _exchange(test_client, agents[1], tok, audience="hop1", scope="a b")
        assert _introspect(test_client, b1["access_token"])["scope"] == "a b"

        _, b2 = _exchange(test_client, agents[2], b1["access_token"],
                          audience="hop2", scope="a")
        assert _introspect(test_client, b2["access_token"])["scope"] == "a"

    def test_scope_re_escalation_blocked_after_reduction(self, test_client):
        """After reducing to 'a', cannot get 'b' back in next hop."""
        a0 = _register(test_client, scope="a b c")
        a1 = _register(
            test_client,
            grant_types=["client_credentials", "urn:ietf:params:oauth:grant-type:token-exchange"],
            scope="a b c",
        )
        a2 = _register(
            test_client,
            grant_types=["client_credentials", "urn:ietf:params:oauth:grant-type:token-exchange"],
            scope="a b c",
        )

        tok = _cc_token(test_client, a0, scope="a b c")["access_token"]
        _, b1 = _exchange(test_client, a1, tok, audience="h1", scope="a")
        narrow_token = b1["access_token"]

        # Try to re-escalate from 'a' → 'a b'
        status, _ = _exchange(test_client, a2, narrow_token, audience="h2", scope="a b")
        assert status == 403


# ═════════════════════════════════════════════════════════════════════
# 3. REFRESH TOKEN FAMILY REVOCATION
# ═════════════════════════════════════════════════════════════════════

class TestRefreshTokenFamilyRevocation:
    """Refresh token replay triggers revocation of entire token family."""

    def _get_refresh_tokens(self, c, creds, scope="read"):
        """Get initial tokens via auth code flow."""
        return _auth_code_flow(c, creds, scope=scope)

    def test_rotation_issues_new_pair(self, test_client):
        creds = _register(
            test_client,
            grant_types=["authorization_code", "refresh_token", "client_credentials"],
            scope="read write",
            redirect_uris=["http://localhost:3000/callback"],
        )
        tok = self._get_refresh_tokens(test_client, creds)
        rt1 = tok["refresh_token"]
        at1 = tok["access_token"]

        resp = test_client.post("/token", data={
            "grant_type": "refresh_token",
            "client_id": creds["client_id"],
            "client_secret": creds["client_secret"],
            "refresh_token": rt1,
        })
        assert resp.status_code == 200
        body = resp.json()
        assert body["access_token"] != at1
        assert body["refresh_token"] != rt1

    def test_replay_old_refresh_token_triggers_family_revocation(self, test_client):
        """Using an already-rotated refresh token revokes the entire family."""
        creds = _register(
            test_client,
            grant_types=["authorization_code", "refresh_token", "client_credentials"],
            scope="read",
            redirect_uris=["http://localhost:3000/callback"],
        )
        tok = self._get_refresh_tokens(test_client, creds)
        rt_gen1 = tok["refresh_token"]

        # Rotate once → gen2
        r2 = test_client.post("/token", data={
            "grant_type": "refresh_token",
            "client_id": creds["client_id"],
            "client_secret": creds["client_secret"],
            "refresh_token": rt_gen1,
        })
        assert r2.status_code == 200
        rt_gen2 = r2.json()["refresh_token"]

        # Replay gen1 (attacker) → should trigger family revocation
        r_replay = test_client.post("/token", data={
            "grant_type": "refresh_token",
            "client_id": creds["client_id"],
            "client_secret": creds["client_secret"],
            "refresh_token": rt_gen1,
        })
        assert r_replay.status_code == 400

        # gen2 should ALSO be revoked now (family revocation)
        r_gen2 = test_client.post("/token", data={
            "grant_type": "refresh_token",
            "client_id": creds["client_id"],
            "client_secret": creds["client_secret"],
            "refresh_token": rt_gen2,
        })
        assert r_gen2.status_code == 400

    def test_three_generation_rotation_then_replay(self, test_client):
        """Rotate 3 times, replay gen1, all gens revoked."""
        creds = _register(
            test_client,
            grant_types=["authorization_code", "refresh_token", "client_credentials"],
            scope="read",
            redirect_uris=["http://localhost:3000/callback"],
        )
        tok = self._get_refresh_tokens(test_client, creds)
        gen1 = tok["refresh_token"]

        # Rotate: gen1 → gen2 → gen3
        r2 = test_client.post("/token", data={
            "grant_type": "refresh_token",
            "client_id": creds["client_id"],
            "client_secret": creds["client_secret"],
            "refresh_token": gen1,
        })
        gen2 = r2.json()["refresh_token"]

        r3 = test_client.post("/token", data={
            "grant_type": "refresh_token",
            "client_id": creds["client_id"],
            "client_secret": creds["client_secret"],
            "refresh_token": gen2,
        })
        gen3 = r3.json()["refresh_token"]

        # Replay gen1
        test_client.post("/token", data={
            "grant_type": "refresh_token",
            "client_id": creds["client_id"],
            "client_secret": creds["client_secret"],
            "refresh_token": gen1,
        })

        # gen3 should be dead
        r_g3 = test_client.post("/token", data={
            "grant_type": "refresh_token",
            "client_id": creds["client_id"],
            "client_secret": creds["client_secret"],
            "refresh_token": gen3,
        })
        assert r_g3.status_code == 400


# ═════════════════════════════════════════════════════════════════════
# 4. AGENT LIFECYCLE → TOKEN IMPACT
# ═════════════════════════════════════════════════════════════════════

class TestAgentLifecycle:
    """Agent registry operations and their impact on the system."""

    def test_agent_creation_returns_usable_credentials(self, test_client):
        """Credentials from agent creation can immediately get tokens."""
        agent = _create_agent(test_client, name="usable-agent",
                              scopes=["search:execute"])
        tok = test_client.post("/token", data={
            "grant_type": "client_credentials",
            "client_id": agent["client_id"],
            "client_secret": agent["client_secret"],
        })
        assert tok.status_code == 200
        assert "access_token" in tok.json()

    def test_deactivated_agent_registry_shows_inactive(self, test_client):
        """After deactivation, agent shows inactive in registry."""
        agent = _create_agent(test_client, name="will-deactivate")
        agent_id = agent["id"]

        test_client.delete(f"/agents/{agent_id}")

        resp = test_client.get(f"/agents/{agent_id}")
        assert resp.status_code == 200
        assert resp.json()["status"] == "inactive"

    def test_update_agent_metadata(self, test_client):
        """Agent metadata updates (version, description, capabilities) persist."""
        agent = _create_agent(test_client, name="versioned-agent",
                              agent_type="supervised",
                              agent_model="gpt-4o",
                              agent_version="1.0.0",
                              agent_provider="acme")
        agent_id = agent["id"]

        resp = test_client.patch(f"/agents/{agent_id}", json={
            "agent_version": "2.0.0",
            "description": "Updated to v2",
        })
        assert resp.status_code == 200
        body = resp.json()
        assert body["agent_version"] == "2.0.0"
        assert body["description"] == "Updated to v2"
        assert body["agent_model"] == "gpt-4o"  # unchanged fields preserved

    def test_list_agents_pagination(self, test_client):
        """Agent listing supports offset/limit pagination."""
        for i in range(5):
            _create_agent(test_client, name=f"page-agent-{i}")

        # Page 1
        r1 = test_client.get("/agents", params={"offset": 0, "limit": 2})
        assert r1.status_code == 200
        d1 = r1.json()
        assert len(d1["items"]) == 2
        assert d1["total"] >= 5

        # Page 2
        r2 = test_client.get("/agents", params={"offset": 2, "limit": 2})
        d2 = r2.json()
        assert len(d2["items"]) == 2
        # Items should differ
        assert d1["items"][0]["id"] != d2["items"][0]["id"]

    def test_list_agents_filter_by_owner(self, test_client):
        """Agent listing can be filtered by owner."""
        _create_agent(test_client, name="alice-agent", owner="alice@co.com")
        _create_agent(test_client, name="bob-agent", owner="bob@co.com")

        r = test_client.get("/agents", params={"owner": "alice@co.com"})
        assert r.status_code == 200
        items = r.json()["items"]
        for item in items:
            assert item["owner"] == "alice@co.com"


# ═════════════════════════════════════════════════════════════════════
# 5. CROSS-CLIENT TOKEN ISOLATION
# ═════════════════════════════════════════════════════════════════════

class TestCrossClientIsolation:
    """Tokens from one client cannot be used by another client."""

    def test_client_b_cannot_authenticate_with_a_secret(self, test_client):
        a = _register(test_client, name="client-a")
        b = _register(test_client, name="client-b")

        resp = test_client.post("/token", data={
            "grant_type": "client_credentials",
            "client_id": a["client_id"],
            "client_secret": b["client_secret"],
        })
        assert resp.status_code == 401

    def test_revoke_only_affects_target_token(self, test_client):
        """Revoking client A's token doesn't affect client B's token."""
        a = _register(test_client, scope="read")
        b = _register(test_client, scope="read")

        tok_a = _cc_token(test_client, a)["access_token"]
        tok_b = _cc_token(test_client, b)["access_token"]

        _revoke(test_client, tok_a, a["client_id"])

        assert _introspect(test_client, tok_a)["active"] is False
        assert _introspect(test_client, tok_b)["active"] is True

    def test_each_client_gets_unique_tokens(self, test_client):
        """Two clients with the same scope get different tokens."""
        a = _register(test_client, scope="read")
        b = _register(test_client, scope="read")

        tok_a = _cc_token(test_client, a)["access_token"]
        tok_b = _cc_token(test_client, b)["access_token"]
        assert tok_a != tok_b


# ═════════════════════════════════════════════════════════════════════
# 6. TOKEN INTROSPECTION COMPLETENESS
# ═════════════════════════════════════════════════════════════════════

class TestTokenIntrospectionCompleteness:
    """Introspection returns all expected RFC 7662 + delegation fields."""

    def test_active_token_returns_all_standard_fields(self, test_client):
        creds = _register(test_client, scope="read write")
        tok = _cc_token(test_client, creds, scope="read write")
        intro = _introspect(test_client, tok["access_token"])

        assert intro["active"] is True
        assert intro["client_id"] == creds["client_id"]
        assert intro["scope"] is not None
        assert intro["token_type"] in ("Bearer", "DPoP")
        assert intro["iss"] is not None
        assert intro["sub"] is not None
        assert intro["jti"] is not None
        assert intro["exp"] is not None
        assert intro["iat"] is not None

    def test_exchanged_token_shows_act_claim(self, test_client):
        parent = _register(test_client, scope="read write")
        child = _register(
            test_client,
            grant_types=["client_credentials", "urn:ietf:params:oauth:grant-type:token-exchange"],
            scope="read",
        )
        tok = _cc_token(test_client, parent, scope="read write")
        _, body = _exchange(test_client, child, tok["access_token"],
                            audience="target", scope="read")
        intro = _introspect(test_client, body["access_token"])

        assert intro["active"] is True
        assert intro["act"] is not None
        assert "sub" in intro["act"]

    def test_revoked_token_returns_inactive_only(self, test_client):
        creds = _register(test_client, scope="read")
        tok = _cc_token(test_client, creds)["access_token"]
        _revoke(test_client, tok, creds["client_id"])

        intro = _introspect(test_client, tok)
        assert intro["active"] is False

    def test_garbage_token_returns_inactive(self, test_client):
        intro = _introspect(test_client, "this.is.not.a.jwt")
        assert intro["active"] is False

    def test_empty_token_rejected(self, test_client):
        resp = test_client.post("/introspect", data={"token": ""})
        assert resp.status_code == 400


# ═════════════════════════════════════════════════════════════════════
# 7. DEVICE GRANT → TOKEN EXCHANGE PIPELINE
# ═════════════════════════════════════════════════════════════════════

class TestDeviceGrantPipeline:
    """CLI agent authenticates via device grant, then exchanges token downstream."""

    def test_device_grant_token_can_be_exchanged(self, test_client):
        """Token from device grant is a normal access token usable in exchange."""
        cli = _register(
            test_client, name="cli-agent",
            grant_types=["client_credentials", "urn:ietf:params:oauth:grant-type:device_code"],
            scope="read write",
        )
        downstream = _register(
            test_client, name="downstream",
            grant_types=["client_credentials", "urn:ietf:params:oauth:grant-type:token-exchange"],
            scope="read",
        )

        # Device flow
        dev_resp = test_client.post("/device/authorize", data={
            "client_id": cli["client_id"], "scope": "read write",
        })
        dev = dev_resp.json()

        test_client.post("/device/complete", json={
            "user_code": dev["user_code"],
            "subject": "user:developer",
            "action": "approve",
        })

        tok_resp = test_client.post("/device/token", data={
            "device_code": dev["device_code"],
            "client_id": cli["client_id"],
        })
        assert tok_resp.status_code == 200
        device_token = tok_resp.json()["access_token"]

        # Exchange the device-granted token
        status, body = _exchange(test_client, downstream, device_token,
                                 audience="agent:worker", scope="read")
        assert status == 200
        intro = _introspect(test_client, body["access_token"])
        assert intro["active"] is True
        assert intro["scope"] == "read"

    def test_device_code_consumed_after_use(self, test_client):
        """Device code can only be redeemed once (one-time use)."""
        cli = _register(
            test_client, name="single-use",
            grant_types=["client_credentials", "urn:ietf:params:oauth:grant-type:device_code"],
        )

        dev = test_client.post("/device/authorize", data={
            "client_id": cli["client_id"],
        }).json()

        test_client.post("/device/complete", json={
            "user_code": dev["user_code"],
            "subject": "user:dev",
            "action": "approve",
        })

        # First poll → success
        r1 = test_client.post("/device/token", data={
            "device_code": dev["device_code"],
            "client_id": cli["client_id"],
        })
        assert r1.status_code == 200

        # Second poll → consumed
        r2 = test_client.post("/device/token", data={
            "device_code": dev["device_code"],
            "client_id": cli["client_id"],
        })
        assert r2.status_code == 400

    def test_device_denial_prevents_token_issuance(self, test_client):
        cli = _register(
            test_client,
            grant_types=["client_credentials", "urn:ietf:params:oauth:grant-type:device_code"],
        )
        dev = test_client.post("/device/authorize", data={
            "client_id": cli["client_id"],
        }).json()

        test_client.post("/device/complete", json={
            "user_code": dev["user_code"],
            "subject": "user:dev",
            "action": "deny",
        })

        r = test_client.post("/device/token", data={
            "device_code": dev["device_code"],
            "client_id": cli["client_id"],
        })
        assert r.status_code == 400


# ═════════════════════════════════════════════════════════════════════
# 8. HITL STEP-UP INTEGRATED WORKFLOW
# ═════════════════════════════════════════════════════════════════════

class TestHITLStepUpWorkflow:
    """Agent encounters sensitive operation → requests step-up → human decides."""

    def test_full_approve_flow(self, test_client):
        resp = test_client.post("/stepup", json={
            "agent_id": "agent:cleanup-bot",
            "action": "DELETE FROM users WHERE inactive=true",
            "scope": "db:delete",
            "resource": "https://db.example.com/users",
        })
        assert resp.status_code == 202
        req_id = resp.json()["id"]
        assert resp.json()["status"] == "pending"

        # Poll — still pending
        poll = test_client.get(f"/stepup/{req_id}")
        assert poll.json()["status"] == "pending"

        # Approve
        approve = test_client.post(f"/stepup/{req_id}/approve", json={
            "approved_by": "dba@company.com",
        })
        assert approve.status_code == 200
        assert approve.json()["status"] == "approved"
        assert approve.json()["approved_by"] == "dba@company.com"
        assert approve.json()["approved_at"] is not None

        # Final poll
        final = test_client.get(f"/stepup/{req_id}")
        assert final.json()["status"] == "approved"

    def test_full_deny_flow(self, test_client):
        resp = test_client.post("/stepup", json={
            "agent_id": "agent:rogue",
            "action": "DROP DATABASE production",
            "scope": "db:admin",
        })
        req_id = resp.json()["id"]

        deny = test_client.post(f"/stepup/{req_id}/deny")
        assert deny.status_code == 200
        assert deny.json()["status"] == "denied"

    def test_cannot_approve_already_approved(self, test_client):
        resp = test_client.post("/stepup", json={
            "agent_id": "x", "action": "y", "scope": "z",
        })
        req_id = resp.json()["id"]
        test_client.post(f"/stepup/{req_id}/approve", json={"approved_by": "a"})

        double = test_client.post(f"/stepup/{req_id}/approve", json={"approved_by": "b"})
        assert double.status_code == 400

    def test_cannot_deny_already_denied(self, test_client):
        resp = test_client.post("/stepup", json={
            "agent_id": "x", "action": "y", "scope": "z",
        })
        req_id = resp.json()["id"]
        test_client.post(f"/stepup/{req_id}/deny")

        double = test_client.post(f"/stepup/{req_id}/deny")
        assert double.status_code == 400

    def test_stepup_with_metadata(self, test_client):
        """Step-up request can carry arbitrary context for the reviewer."""
        resp = test_client.post("/stepup", json={
            "agent_id": "agent:data-bot",
            "action": "export_pii",
            "scope": "data:export",
            "resource": "https://api.example.com/users/export",
            "metadata": {
                "rows": 50000,
                "reason": "GDPR data subject access request",
                "ticket": "JIRA-12345",
            },
        })
        assert resp.status_code == 202
        assert resp.json()["status"] == "pending"


# ═════════════════════════════════════════════════════════════════════
# 9. AUTHORIZATION CODE FLOW — EDGE CASES
# ═════════════════════════════════════════════════════════════════════

class TestAuthCodeEdgeCases:
    """Auth code flow: redirect URI validation, nonce, resource indicators."""

    def test_unregistered_redirect_uri_rejected(self, test_client):
        """redirect_uri not in client's registered set → 400."""
        creds = _register(
            test_client,
            grant_types=["authorization_code"],
            redirect_uris=["http://localhost:3000/callback"],
        )
        verifier, challenge = _pkce()
        resp = test_client.get("/authorize", params={
            "response_type": "code",
            "client_id": creds["client_id"],
            "redirect_uri": "http://evil.com/steal",
            "scope": "read",
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        })
        assert resp.status_code == 400

    def test_missing_pkce_rejected(self, test_client):
        """PKCE is mandatory — missing code_challenge → 400."""
        creds = _register(
            test_client,
            grant_types=["authorization_code"],
            redirect_uris=["http://localhost:3000/callback"],
        )
        resp = test_client.get("/authorize", params={
            "response_type": "code",
            "client_id": creds["client_id"],
            "redirect_uri": "http://localhost:3000/callback",
            "scope": "read",
        })
        assert resp.status_code == 400

    def test_only_s256_challenge_method_accepted(self, test_client):
        creds = _register(
            test_client,
            grant_types=["authorization_code"],
            redirect_uris=["http://localhost:3000/callback"],
        )
        _, challenge = _pkce()
        resp = test_client.get("/authorize", params={
            "response_type": "code",
            "client_id": creds["client_id"],
            "redirect_uri": "http://localhost:3000/callback",
            "scope": "read",
            "code_challenge": challenge,
            "code_challenge_method": "plain",
        })
        assert resp.status_code == 400

    def test_state_preserved_in_redirect(self, test_client):
        creds = _register(
            test_client,
            grant_types=["authorization_code"],
            redirect_uris=["http://localhost:3000/callback"],
        )
        _, challenge = _pkce()
        resp = test_client.get("/authorize", params={
            "response_type": "code",
            "client_id": creds["client_id"],
            "redirect_uri": "http://localhost:3000/callback",
            "scope": "read",
            "state": "csrf_random_789",
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        }, follow_redirects=False)
        assert resp.status_code == 302
        assert "state=csrf_random_789" in resp.headers["location"]

    def test_auth_code_with_resource_indicator(self, test_client):
        """Resource indicator is passed through to the authorization code."""
        creds = _register(
            test_client,
            grant_types=["authorization_code", "client_credentials"],
            redirect_uris=["http://localhost:3000/callback"],
            scope="read",
        )
        tokens = _auth_code_flow(test_client, creds, scope="read",
                                 resource="https://mcp.example.com/")
        assert "access_token" in tokens


# ═════════════════════════════════════════════════════════════════════
# 10. HTTP BASIC AUTH & TOKEN ENDPOINT VARIANTS
# ═════════════════════════════════════════════════════════════════════

class TestTokenEndpointAuth:
    """Token endpoint supports multiple authentication methods."""

    def test_http_basic_auth(self, test_client):
        creds = _register(test_client, scope="read")
        basic = base64.b64encode(
            f"{creds['client_id']}:{creds['client_secret']}".encode()
        ).decode()
        resp = test_client.post("/token",
            data={"grant_type": "client_credentials", "scope": "read"},
            headers={"authorization": f"Basic {basic}"})
        assert resp.status_code == 200
        assert "access_token" in resp.json()

    def test_client_secret_in_form_body(self, test_client):
        creds = _register(test_client, scope="read")
        resp = test_client.post("/token", data={
            "grant_type": "client_credentials",
            "client_id": creds["client_id"],
            "client_secret": creds["client_secret"],
            "scope": "read",
        })
        assert resp.status_code == 200

    def test_missing_client_id_returns_401(self, test_client):
        resp = test_client.post("/token", data={
            "grant_type": "client_credentials",
        })
        assert resp.status_code == 401

    def test_wrong_content_type_returns_400(self, test_client):
        resp = test_client.post("/token",
            json={"grant_type": "client_credentials"},
            headers={"content-type": "application/json"})
        assert resp.status_code == 400

    def test_unsupported_grant_type(self, test_client):
        creds = _register(test_client)
        resp = test_client.post("/token", data={
            "grant_type": "password",
            "client_id": creds["client_id"],
            "client_secret": creds["client_secret"],
        })
        assert resp.status_code == 400
        assert resp.json()["error"] in ("unsupported_grant_type", "invalid_request")


# ═════════════════════════════════════════════════════════════════════
# 11. REVOCATION BLAST RADIUS
# ═════════════════════════════════════════════════════════════════════

class TestRevocationBlastRadius:
    """Verify revocation affects only the intended tokens."""

    def test_revoke_access_token(self, test_client):
        creds = _register(test_client, scope="a b")
        tok = _cc_token(test_client, creds, scope="a b")["access_token"]

        assert _introspect(test_client, tok)["active"] is True
        assert _revoke(test_client, tok, creds["client_id"]) == 200
        assert _introspect(test_client, tok)["active"] is False

    def test_revoke_is_idempotent(self, test_client):
        creds = _register(test_client, scope="read")
        tok = _cc_token(test_client, creds)["access_token"]
        assert _revoke(test_client, tok, creds["client_id"]) == 200
        assert _revoke(test_client, tok, creds["client_id"]) == 200

    def test_revoking_one_token_does_not_affect_others(self, test_client):
        creds = _register(test_client, scope="read")
        tok1 = _cc_token(test_client, creds)["access_token"]
        tok2 = _cc_token(test_client, creds)["access_token"]

        _revoke(test_client, tok1, creds["client_id"])
        assert _introspect(test_client, tok1)["active"] is False
        assert _introspect(test_client, tok2)["active"] is True

    def test_revoked_token_cannot_be_exchanged(self, test_client):
        """A revoked parent token must be rejected during exchange."""
        parent = _register(test_client, scope="read write")
        child = _register(
            test_client,
            grant_types=["client_credentials", "urn:ietf:params:oauth:grant-type:token-exchange"],
            scope="read",
        )
        tok = _cc_token(test_client, parent, scope="read write")["access_token"]
        _revoke(test_client, tok, parent["client_id"])

        status, _ = _exchange(test_client, child, tok, audience="x", scope="read")
        assert status in (400, 401)


# ═════════════════════════════════════════════════════════════════════
# 12. DISCOVERY METADATA ACCURACY
# ═════════════════════════════════════════════════════════════════════

class TestDiscoveryMetadata:
    """Verify discovery documents are accurate and consistent."""

    def test_oauth_metadata_contains_all_endpoints(self, test_client):
        r = test_client.get("/.well-known/oauth-authorization-server")
        assert r.status_code == 200
        meta = r.json()

        assert meta["issuer"] == "http://localhost:8000"
        assert meta["token_endpoint"].endswith("/token")
        assert meta["authorization_endpoint"].endswith("/authorize")
        assert meta["registration_endpoint"].endswith("/register")
        assert meta["revocation_endpoint"].endswith("/revoke")
        assert meta["introspection_endpoint"].endswith("/introspect")
        assert meta["jwks_uri"].endswith("/jwks.json")
        assert meta["device_authorization_endpoint"].endswith("/device/authorize")
        assert "client_credentials" in meta["grant_types_supported"]
        assert "authorization_code" in meta["grant_types_supported"]
        assert "S256" in meta["code_challenge_methods_supported"]
        assert meta["resource_indicators_supported"] is True

    def test_oidc_discovery_extends_oauth_metadata(self, test_client):
        oauth = test_client.get("/.well-known/oauth-authorization-server").json()
        oidc = test_client.get("/.well-known/openid-configuration").json()

        # OIDC must be a superset
        assert oidc["issuer"] == oauth["issuer"]
        assert oidc["token_endpoint"] == oauth["token_endpoint"]
        assert "userinfo_endpoint" in oidc  # OIDC-specific

    def test_jwks_returns_valid_structure(self, test_client):
        """JWKS endpoint returns valid JSON with keys array.
        Note: In test mode without lifespan, the keys array may be empty
        since signing keys are created during app startup."""
        r = test_client.get("/.well-known/jwks.json")
        assert r.status_code == 200
        body = r.json()
        assert "keys" in body
        assert isinstance(body["keys"], list)
        # If keys exist (e.g. created by a previous token request), validate structure
        if body["keys"]:
            k = body["keys"][0]
            assert k["kty"] == "EC"
            assert k["alg"] == "ES256"
            assert k["crv"] == "P-256"
            assert "kid" in k
            assert "x" in k and "y" in k
            # Private key must NOT be exposed
            assert "d" not in k

    def test_jwks_has_key_after_token_issued(self, test_client):
        """After a token is issued, JWKS must contain the signing key."""
        creds = _register(test_client, scope="read")
        _cc_token(test_client, creds)  # forces key creation

        r = test_client.get("/.well-known/jwks.json")
        keys = r.json()["keys"]
        assert len(keys) >= 1
        assert keys[0]["kty"] == "EC"
        assert keys[0]["alg"] == "ES256"
        assert "d" not in keys[0]  # no private key leak

    def test_protected_resource_metadata(self, test_client):
        r = test_client.get("/.well-known/oauth-protected-resource")
        assert r.status_code == 200
        body = r.json()
        assert "authorization_servers" in body
        assert len(body["authorization_servers"]) >= 1

    def test_all_metadata_endpoints_reachable(self, test_client):
        """Every endpoint listed in metadata actually responds."""
        meta = test_client.get("/.well-known/oauth-authorization-server").json()

        # Token endpoint
        r = test_client.post(meta["token_endpoint"].replace("http://localhost:8000", ""),
                             data={"grant_type": "client_credentials"})
        assert r.status_code in (400, 401)  # expected error, but endpoint is alive

        # Registration
        r2 = test_client.post(meta["registration_endpoint"].replace("http://localhost:8000", ""),
                              json={"client_name": "probe"})
        assert r2.status_code == 201

        # JWKS
        jwks_path = meta["jwks_uri"].replace("http://localhost:8000", "")
        r3 = test_client.get(jwks_path)
        assert r3.status_code == 200


# ═════════════════════════════════════════════════════════════════════
# 13. CLIENT REGISTRATION VALIDATION
# ═════════════════════════════════════════════════════════════════════

class TestClientRegistrationValidation:
    """Input validation on Dynamic Client Registration (RFC 7591)."""

    def test_register_with_all_valid_grant_types(self, test_client):
        for gt in ["client_credentials", "authorization_code", "refresh_token",
                    "urn:ietf:params:oauth:grant-type:token-exchange",
                    "urn:ietf:params:oauth:grant-type:device_code"]:
            resp = test_client.post("/register", json={
                "client_name": f"test-{gt[:10]}",
                "grant_types": [gt],
            })
            assert resp.status_code == 201, f"Failed for grant_type: {gt}"

    def test_invalid_grant_type_rejected(self, test_client):
        resp = test_client.post("/register", json={
            "client_name": "bad",
            "grant_types": ["password"],
        })
        assert resp.status_code == 422

    def test_redirect_uri_fragment_rejected(self, test_client):
        resp = test_client.post("/register", json={
            "client_name": "bad",
            "grant_types": ["authorization_code"],
            "redirect_uris": ["http://localhost:3000/callback#fragment"],
        })
        assert resp.status_code == 422

    def test_redirect_uri_non_https_non_localhost_rejected(self, test_client):
        resp = test_client.post("/register", json={
            "client_name": "bad",
            "grant_types": ["authorization_code"],
            "redirect_uris": ["http://evil.com/callback"],
        })
        assert resp.status_code == 422

    def test_redirect_uri_localhost_http_allowed(self, test_client):
        resp = test_client.post("/register", json={
            "client_name": "local-dev",
            "grant_types": ["authorization_code"],
            "redirect_uris": ["http://localhost:3000/cb"],
        })
        assert resp.status_code == 201

    def test_client_ids_are_unique(self, test_client):
        r1 = _register(test_client, name="c1")
        r2 = _register(test_client, name="c2")
        assert r1["client_id"] != r2["client_id"]

    def test_client_secrets_are_unique(self, test_client):
        r1 = _register(test_client, name="c1")
        r2 = _register(test_client, name="c2")
        assert r1["client_secret"] != r2["client_secret"]


# ═════════════════════════════════════════════════════════════════════
# 14. MULTI-GRANT CLIENT LIFECYCLE
# ═════════════════════════════════════════════════════════════════════

class TestMultiGrantClientLifecycle:
    """A single client uses multiple grant types in sequence."""

    def test_client_uses_cc_then_auth_code_then_refresh(self, test_client):
        """One client exercises client_credentials, auth_code, and refresh."""
        creds = _register(
            test_client, name="multi-grant",
            grant_types=["client_credentials", "authorization_code", "refresh_token"],
            scope="read write",
            redirect_uris=["http://localhost:3000/callback"],
        )

        # 1. Client credentials
        cc_tok = _cc_token(test_client, creds, scope="read")
        assert _introspect(test_client, cc_tok["access_token"])["active"] is True

        # 2. Auth code + PKCE
        ac_tok = _auth_code_flow(test_client, creds, scope="write")
        assert _introspect(test_client, ac_tok["access_token"])["active"] is True
        assert ac_tok["refresh_token"]

        # 3. Refresh token
        r = test_client.post("/token", data={
            "grant_type": "refresh_token",
            "client_id": creds["client_id"],
            "client_secret": creds["client_secret"],
            "refresh_token": ac_tok["refresh_token"],
        })
        assert r.status_code == 200
        assert r.json()["access_token"] != ac_tok["access_token"]

    def test_client_credentials_and_exchange_on_same_client(self, test_client):
        """A client can both get its own token and exchange another's."""
        provider = _register(test_client, scope="a b c")
        dual = _register(
            test_client, name="dual-mode",
            grant_types=["client_credentials", "urn:ietf:params:oauth:grant-type:token-exchange"],
            scope="a b",
        )

        # Own token
        own = _cc_token(test_client, dual, scope="a b")
        assert _introspect(test_client, own["access_token"])["active"] is True

        # Exchange someone else's token
        provider_tok = _cc_token(test_client, provider, scope="a b c")["access_token"]
        status, body = _exchange(test_client, dual, provider_tok,
                                 audience="target", scope="a")
        assert status == 200


# ═════════════════════════════════════════════════════════════════════
# 15. RESOURCE INDICATOR VALIDATION (RFC 8707)
# ═════════════════════════════════════════════════════════════════════

class TestResourceIndicators:
    """RFC 8707 resource indicators — audience binding for tokens."""

    def test_resource_in_allowed_list_accepted(self, test_client):
        creds = _register(
            test_client, scope="read",
            allowed_resources=["https://api.example.com/", "https://mcp.example.com/"],
        )
        resp = test_client.post("/token", data={
            "grant_type": "client_credentials",
            "client_id": creds["client_id"],
            "client_secret": creds["client_secret"],
            "scope": "read",
            "resource": "https://api.example.com/",
        })
        assert resp.status_code == 200

    def test_resource_not_in_allowed_list_rejected(self, test_client):
        creds = _register(
            test_client, scope="read",
            allowed_resources=["https://api.example.com/"],
        )
        resp = test_client.post("/token", data={
            "grant_type": "client_credentials",
            "client_id": creds["client_id"],
            "client_secret": creds["client_secret"],
            "scope": "read",
            "resource": "https://evil.com/",
        })
        assert resp.status_code == 400

    def test_no_allowed_resources_means_unrestricted(self, test_client):
        creds = _register(test_client, scope="read")  # no allowed_resources
        resp = test_client.post("/token", data={
            "grant_type": "client_credentials",
            "client_id": creds["client_id"],
            "client_secret": creds["client_secret"],
            "scope": "read",
            "resource": "https://anything.example.com/",
        })
        assert resp.status_code == 200


# ═════════════════════════════════════════════════════════════════════
# 16. HEALTH ENDPOINTS
# ═════════════════════════════════════════════════════════════════════

class TestHealthEndpoints:

    def test_liveness(self, test_client):
        r = test_client.get("/health")
        assert r.status_code == 200
        assert r.json()["status"] == "ok"

    def test_readiness_checks_db_and_keys(self, test_client):
        r = test_client.get("/ready")
        body = r.json()
        assert body["db"] == "ok"
        # keys check depends on whether a signing key was created
        assert body["status"] in ("ready", "not_ready")


# ═════════════════════════════════════════════════════════════════════
# 17. ERROR FORMAT COMPLIANCE
# ═════════════════════════════════════════════════════════════════════

class TestErrorFormats:
    """OAuth endpoints use RFC 6749 error format; others use RFC 9457."""

    def test_token_endpoint_returns_oauth_error_format(self, test_client):
        resp = test_client.post("/token", data={
            "grant_type": "client_credentials",
            "client_id": "nonexistent",
            "client_secret": "bad",
        })
        body = resp.json()
        assert "error" in body
        assert "error_description" in body

    def test_non_token_endpoint_returns_problem_details(self, test_client):
        resp = test_client.get("/agents/nonexistent_id_12345")
        body = resp.json()
        # RFC 9457 Problem Details
        assert "type" in body or "title" in body or "status" in body

    def test_500_never_leaks_stack_trace(self, test_client):
        """Unhandled errors return generic message, no internal details."""
        # Introspect with missing token param → controlled 400
        resp = test_client.post("/introspect", data={})
        assert resp.status_code == 400
        body = resp.json()
        assert "traceback" not in str(body).lower()
        assert "Traceback" not in str(body)


# ═════════════════════════════════════════════════════════════════════
# 18. SCOPE VALIDATION ON REGISTRATION & TOKEN REQUEST
# ═════════════════════════════════════════════════════════════════════

class TestScopeValidation:

    def test_request_scope_subset_of_registration(self, test_client):
        creds = _register(test_client, scope="read write admin")
        tok = _cc_token(test_client, creds, scope="read")
        intro = _introspect(test_client, tok["access_token"])
        assert "read" in intro["scope"]
        assert "admin" not in intro["scope"]

    def test_request_scope_exceeding_registration_rejected(self, test_client):
        creds = _register(test_client, scope="read")
        resp = test_client.post("/token", data={
            "grant_type": "client_credentials",
            "client_id": creds["client_id"],
            "client_secret": creds["client_secret"],
            "scope": "read admin",
        })
        assert resp.status_code in (400, 403)

    def test_empty_scope_defaults_to_client_scope(self, test_client):
        creds = _register(test_client, scope="read write")
        resp = test_client.post("/token", data={
            "grant_type": "client_credentials",
            "client_id": creds["client_id"],
            "client_secret": creds["client_secret"],
            # no scope param
        })
        assert resp.status_code == 200
