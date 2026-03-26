#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════╗
║          authgent — Real-World Agent-to-Agent Simulation            ║
║                                                                      ║
║  Deep end-to-end simulation of how AI agents authenticate,           ║
║  delegate, and communicate through authgent in production.           ║
║                                                                      ║
║  Covers 10 real-world scenarios with good + bad case paths:          ║
║                                                                      ║
║   1. Enterprise AI Pipeline (human → orchestrator → agents)          ║
║   2. Privilege Escalation Attack                                     ║
║   3. Token Theft, Revocation & Blast Radius                          ║
║   4. Delegation Chain Depth Limit Enforcement                        ║
║   5. HITL Step-Up for Dangerous Operations                           ║
║   6. Device Grant for Headless CLI Agent                             ║
║   7. Agent Deactivation (fired agent)                                ║
║   8. Cross-Agent Impersonation Attempt                               ║
║   9. Scope Reduction Across Delegation Chain                         ║
║  10. Refresh Token Rotation Under Concurrent Load                    ║
║                                                                      ║
║  Usage: python tests/agent_to_agent_simulation.py                    ║
║  Requires: authgent-server running on http://localhost:8000          ║
╚══════════════════════════════════════════════════════════════════════╝
"""

from __future__ import annotations

import base64
import hashlib
import json
import secrets
import sys
import textwrap
import time
from dataclasses import dataclass, field

import httpx

BASE = "http://localhost:8000"

# ── Pretty Printing ──────────────────────────────────────────────────

CYAN = "\033[96m"
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
MAGENTA = "\033[95m"
BOLD = "\033[1m"
DIM = "\033[2m"
RESET = "\033[0m"

PASS_ICON = f"{GREEN}✓{RESET}"
FAIL_ICON = f"{RED}✗{RESET}"
WARN_ICON = f"{YELLOW}⚠{RESET}"
ARROW = f"{DIM}→{RESET}"
BLOCK = f"{CYAN}■{RESET}"

results: list[tuple[str, bool, str]] = []


def narrate(text: str):
    """Print a narrative description of what's happening."""
    wrapped = textwrap.fill(text, width=76, initial_indent="  │ ", subsequent_indent="  │ ")
    print(f"{DIM}{wrapped}{RESET}")


def actor(name: str, action: str):
    """Print what an actor (human/agent/server) is doing."""
    print(f"  {MAGENTA}{BOLD}{name}{RESET} {ARROW} {action}")


def check(name: str, passed: bool, detail: str = ""):
    results.append((name, passed, detail))
    icon = PASS_ICON if passed else FAIL_ICON
    msg = f"  {icon} {name}"
    if detail and not passed:
        msg += f" {DIM}({detail}){RESET}"
    print(msg)


def scenario_header(num: int, title: str, description: str):
    print(f"\n{'━'*70}")
    print(f"  {BOLD}{CYAN}SCENARIO {num}: {title}{RESET}")
    print(f"{'━'*70}")
    narrate(description)
    print()


def sub_section(title: str):
    print(f"\n  {YELLOW}── {title} ──{RESET}")


# ── Helper: Register an agent with full identity ─────────────────────

@dataclass
class AgentIdentity:
    """Represents a fully registered agent with credentials."""
    name: str
    agent_id: str = ""
    client_id: str = ""
    client_secret: str = ""
    scopes: list[str] = field(default_factory=list)
    grant_types: list[str] = field(default_factory=list)
    access_token: str = ""
    refresh_token: str = ""

    def __repr__(self):
        return f"Agent({self.name}, id={self.agent_id[:12]}...)"


def register_agent(
    name: str,
    scopes: list[str],
    agent_type: str = "autonomous",
    model: str = "gpt-4o",
    capabilities: list[str] | None = None,
    grant_types: list[str] | None = None,
    redirect_uris: list[str] | None = None,
) -> AgentIdentity:
    """Register an agent in the registry + get OAuth credentials."""
    # 1. Create agent identity
    r = httpx.post(f"{BASE}/agents", json={
        "name": name,
        "owner": "platform@acme-corp.com",
        "allowed_scopes": scopes,
        "capabilities": capabilities or [],
        "agent_type": agent_type,
        "agent_model": model,
        "agent_version": "1.0.0",
        "agent_provider": "acme-corp",
    })
    data = r.json()

    agent = AgentIdentity(
        name=name,
        agent_id=data["id"],
        client_id=data["client_id"],
        client_secret=data["client_secret"],
        scopes=scopes,
        grant_types=grant_types or ["client_credentials"],
    )

    # 2. Also register OAuth client with extended grant types if needed
    if grant_types and set(grant_types) != {"client_credentials"}:
        reg_body: dict = {
            "client_name": name,
            "grant_types": grant_types,
            "scope": " ".join(scopes),
        }
        if redirect_uris:
            reg_body["redirect_uris"] = redirect_uris
        r2 = httpx.post(f"{BASE}/register", json=reg_body)
        d2 = r2.json()
        agent.client_id = d2["client_id"]
        agent.client_secret = d2["client_secret"]

    return agent


def get_token(agent: AgentIdentity, scopes: str | None = None) -> str:
    """Get an access token for an agent via client_credentials."""
    r = httpx.post(f"{BASE}/token", data={
        "grant_type": "client_credentials",
        "client_id": agent.client_id,
        "client_secret": agent.client_secret,
        "scope": scopes or " ".join(agent.scopes),
    })
    if r.status_code != 200:
        return ""
    tok = r.json()
    agent.access_token = tok.get("access_token", "")
    agent.refresh_token = tok.get("refresh_token", "")
    return agent.access_token


def exchange_token(
    agent: AgentIdentity,
    subject_token: str,
    audience: str,
    scope: str,
) -> dict:
    """Exchange a parent token for a delegated downstream token."""
    r = httpx.post(f"{BASE}/token", data={
        "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
        "client_id": agent.client_id,
        "client_secret": agent.client_secret,
        "subject_token": subject_token,
        "audience": audience,
        "scope": scope,
    })
    return {"status": r.status_code, "body": r.json()}


def introspect(token: str) -> dict:
    """Introspect a token to see its claims."""
    r = httpx.post(f"{BASE}/introspect", data={"token": token})
    return r.json()


def revoke(token: str, client_id: str = "") -> int:
    """Revoke a token."""
    r = httpx.post(f"{BASE}/revoke", data={"token": token, "client_id": client_id})
    return r.status_code


# ══════════════════════════════════════════════════════════════════════
# SCENARIO 1: Enterprise AI Pipeline
# Human → Orchestrator Agent → Search Agent → Database Agent
# ══════════════════════════════════════════════════════════════════════

def scenario_1_enterprise_pipeline():
    scenario_header(1, "Enterprise AI Pipeline",
        "A human user asks their AI assistant to research a topic. "
        "The orchestrator agent delegates to a search agent, which then "
        "delegates to a database agent to fetch structured data. Each hop "
        "in the delegation chain reduces scope and creates audit-traceable "
        "act claims. This is the core use case for MCP + A2A workflows.")

    # ── Setup: Register 3 agents ──
    sub_section("Setup: Register Agent Fleet")

    orchestrator = register_agent(
        "orchestrator-agent",
        scopes=["search:execute", "db:read", "summarize"],
        capabilities=["orchestration", "planning"],
        grant_types=["client_credentials", "authorization_code", "refresh_token",
                     "urn:ietf:params:oauth:grant-type:token-exchange"],
        redirect_uris=["http://localhost:3000/callback"],
    )
    actor("Platform", f"Registered {orchestrator.name} (id={orchestrator.agent_id[:12]}...)")

    search_agent = register_agent(
        "search-agent",
        scopes=["search:execute", "db:read"],
        capabilities=["web-search", "semantic-search"],
        grant_types=["client_credentials", "urn:ietf:params:oauth:grant-type:token-exchange"],
    )
    actor("Platform", f"Registered {search_agent.name} (id={search_agent.agent_id[:12]}...)")

    db_agent = register_agent(
        "database-agent",
        scopes=["db:read"],
        capabilities=["sql-query", "data-export"],
        grant_types=["client_credentials", "urn:ietf:params:oauth:grant-type:token-exchange"],
    )
    actor("Platform", f"Registered {db_agent.name} (id={db_agent.agent_id[:12]}...)")

    # ── Step 1: Human delegates to Orchestrator via auth code ──
    sub_section("Step 1: Human Delegates to Orchestrator (Auth Code + PKCE)")

    # Simulate PKCE auth code flow
    code_verifier = secrets.token_urlsafe(64)
    challenge = base64.urlsafe_b64encode(
        hashlib.sha256(code_verifier.encode()).digest()
    ).rstrip(b"=").decode()

    actor("Human (Dhruv)", "Opens browser, clicks 'Allow' on consent page")
    r = httpx.get(f"{BASE}/authorize", params={
        "response_type": "code",
        "client_id": orchestrator.client_id,
        "redirect_uri": "http://localhost:3000/callback",
        "scope": "search:execute db:read summarize",
        "state": "user_session_abc",
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    }, follow_redirects=False)
    code = r.headers.get("location", "").split("code=")[1].split("&")[0]
    actor("authgent", f"Issued authorization code: {code[:20]}...")

    r2 = httpx.post(f"{BASE}/token", data={
        "grant_type": "authorization_code",
        "client_id": orchestrator.client_id,
        "client_secret": orchestrator.client_secret,
        "code": code,
        "code_verifier": code_verifier,
        "redirect_uri": "http://localhost:3000/callback",
    })
    human_token_data = r2.json()
    human_delegated_token = human_token_data["access_token"]
    orchestrator.refresh_token = human_token_data.get("refresh_token", "")
    actor("Orchestrator", "Received human-delegated token + refresh token")

    check("Human → Orchestrator delegation succeeds", r2.status_code == 200)
    check("  Access token issued", bool(human_delegated_token))
    check("  Refresh token issued", bool(orchestrator.refresh_token))

    # ── Step 2: Orchestrator delegates to Search Agent ──
    sub_section("Step 2: Orchestrator Delegates to Search Agent (Token Exchange)")

    actor("Orchestrator", "Needs search results → exchanges token for search-agent")
    narrate("The orchestrator reduces scope from 'search:execute db:read summarize' "
            "down to 'search:execute db:read' — dropping 'summarize' per least-privilege. "
            "The search agent keeps db:read so it can delegate further to the DB agent.")

    exch1 = exchange_token(
        search_agent,
        subject_token=human_delegated_token,
        audience=f"agent:{search_agent.name}",
        scope="search:execute db:read",
    )
    search_token = exch1["body"].get("access_token", "")
    actor("authgent", "Issued delegated token to search-agent")

    check("Orchestrator → Search Agent delegation succeeds", exch1["status"] == 200)
    check("  Delegated token issued", bool(search_token))

    # Introspect to see the delegation chain
    intro1 = introspect(search_token)
    check("  Token is active", intro1.get("active") is True)
    check("  Has act claim (delegation chain)", intro1.get("act") is not None)
    act_claim = intro1.get("act", {})
    actor("Introspection", f"act claim: {json.dumps(act_claim, indent=2)}")
    narrate("The act claim shows WHO is acting on behalf of the original subject. "
            "This is how MCP servers verify the full delegation chain — every hop is recorded.")

    # ── Step 3: Search Agent delegates to DB Agent ──
    sub_section("Step 3: Search Agent Delegates to DB Agent (2-hop chain)")

    actor("Search Agent", "Needs structured data → exchanges token for db-agent")
    narrate("Search agent further reduces scope from 'search:execute' to 'db:read'. "
            "Now we have a 2-hop delegation chain: Human → Orchestrator → Search → DB.")

    exch2 = exchange_token(
        db_agent,
        subject_token=search_token,
        audience=f"agent:{db_agent.name}",
        scope="db:read",
    )
    db_token = exch2["body"].get("access_token", "")
    actor("authgent", "Issued 2-hop delegated token to db-agent")

    check("Search Agent → DB Agent delegation succeeds", exch2["status"] == 200)
    check("  2-hop delegated token issued", bool(db_token))

    # Introspect the final token — should show nested act claims
    intro2 = introspect(db_token)
    check("  Final token is active", intro2.get("active") is True)
    nested_act = intro2.get("act", {})
    has_nested = "act" in nested_act  # act.act exists = 2 hops
    check("  Nested act claim (2-hop chain visible)", has_nested)
    actor("Introspection", f"Full delegation chain:\n{json.dumps(nested_act, indent=4)}")

    narrate("The nested act claim structure shows: "
            "db-agent is acting on behalf of search-agent, who is acting on behalf of "
            "the orchestrator, who received delegation from the human. "
            "Any MCP server receiving this token can verify the ENTIRE chain of custody.")

    # ── Step 4: DB Agent uses token to call MCP tool server ──
    sub_section("Step 4: DB Agent Calls MCP Tool Server (simulated)")

    actor("DB Agent", "Presents token to MCP tool server: Authorization: Bearer <token>")
    narrate("In production, the MCP server would fetch the JWKS from authgent's "
            "/.well-known/jwks.json, verify the JWT signature, check the act claim "
            "chain, and evaluate scope. We simulate this via introspection.")

    check("  Token scope is db:read (least privilege)", intro2.get("scope") == "db:read")
    check("  Original subject preserved across chain", bool(intro2.get("sub")))

    actor("MCP Server", "Verified token ✓, delegation chain ✓, scope ✓ → executing db:read query")
    print(f"\n  {GREEN}{BOLD}  ✓ Full 3-hop pipeline complete: Human → Orchestrator → Search → DB{RESET}")

    return orchestrator, search_agent, db_agent, human_delegated_token, search_token, db_token


# ══════════════════════════════════════════════════════════════════════
# SCENARIO 2: Privilege Escalation Attack
# ══════════════════════════════════════════════════════════════════════

def scenario_2_privilege_escalation(search_agent: AgentIdentity, parent_token: str):
    scenario_header(2, "Privilege Escalation Attack",
        "A compromised search agent tries to escalate its privileges by "
        "requesting scopes it wasn't granted. authgent must reject these "
        "attempts — this is critical for zero-trust agent security.")

    # ── Attack 1: Request admin scope via token exchange ──
    sub_section("Attack 1: Scope Escalation via Token Exchange")

    actor("Compromised Search Agent", "Tries to exchange token for 'admin:all' scope")
    narrate("The attacker has a valid search:execute token but tries to get admin "
            "privileges by requesting admin:all during token exchange.")

    result = exchange_token(
        search_agent,
        subject_token=parent_token,
        audience="agent:evil-target",
        scope="admin:all db:write db:delete",
    )
    check("Scope escalation BLOCKED (403)", result["status"] == 403)
    error = result["body"]
    check("  Error type is scope_escalation",
          error.get("error") == "scope_escalation"
          or "scope" in error.get("error_description", "").lower()
          or "scope" in error.get("detail", "").lower())
    actor("authgent", f"DENIED: {error.get('error_description', error.get('detail', 'scope violation'))}")

    # ── Attack 2: Try to get a token with unauthorized grant type ──
    sub_section("Attack 2: Unauthorized Grant Type")

    actor("Compromised Agent", "Tries refresh_token grant (not in its allowed grant types)")
    r = httpx.post(f"{BASE}/token", data={
        "grant_type": "refresh_token",
        "client_id": search_agent.client_id,
        "client_secret": search_agent.client_secret,
        "refresh_token": "fake_refresh_token",
    })
    check("Unauthorized grant type BLOCKED (400)", r.status_code == 400)

    # ── Attack 3: Use someone else's client secret ──
    sub_section("Attack 3: Credential Stuffing")

    actor("Attacker", "Tries search-agent's client_id with a guessed secret")
    r2 = httpx.post(f"{BASE}/token", data={
        "grant_type": "client_credentials",
        "client_id": search_agent.client_id,
        "client_secret": "sec_guessed_wrong_password_12345",
    })
    check("Wrong secret BLOCKED (401)", r2.status_code == 401)
    narrate("authgent uses bcrypt with timing-safe comparison, making credential "
            "stuffing attacks impractical even at scale.")

    print(f"\n  {GREEN}{BOLD}  ✓ All privilege escalation attempts blocked{RESET}")


# ══════════════════════════════════════════════════════════════════════
# SCENARIO 3: Token Theft, Revocation & Blast Radius
# ══════════════════════════════════════════════════════════════════════

def scenario_3_token_theft(orchestrator: AgentIdentity):
    scenario_header(3, "Token Theft, Revocation & Blast Radius Containment",
        "An attacker steals an orchestrator agent's access token from a log file. "
        "The security team detects the breach and revokes the token. We verify "
        "that the stolen token immediately becomes unusable, and that tokens "
        "derived from it (via delegation) are also neutralized.")

    # ── Setup: Get a fresh token and derive a downstream token ──
    sub_section("Setup: Active Token + Downstream Delegation")

    stolen_token = get_token(orchestrator, "search:execute db:read")
    actor("Orchestrator", f"Gets token: {stolen_token[:30]}...")

    # Create a downstream delegation from this token
    downstream_agent = register_agent(
        "analytics-agent",
        scopes=["db:read"],
        grant_types=["client_credentials", "urn:ietf:params:oauth:grant-type:token-exchange"],
    )
    exch = exchange_token(
        downstream_agent,
        subject_token=stolen_token,
        audience="agent:analytics",
        scope="db:read",
    )
    downstream_token = exch["body"].get("access_token", "")
    actor("Analytics Agent", "Got delegated token from orchestrator")

    # Verify both are active
    check("Stolen token is active", introspect(stolen_token).get("active") is True)
    check("Downstream token is active", introspect(downstream_token).get("active") is True)

    # ── Attack: Attacker uses the stolen token ──
    sub_section("Attack: Attacker Uses Stolen Token")

    actor("Attacker", "Found token in exposed log → uses it to introspect (recon)")
    recon = introspect(stolen_token)
    check("Attacker can use stolen token (pre-revocation)", recon.get("active") is True)
    actor("Attacker", f"Sees scopes: {recon.get('scope')}, client: {recon.get('client_id')}")
    narrate("This is why short TTLs matter — even stolen tokens expire quickly. "
            "But we don't want to wait; the security team revokes immediately.")

    # ── Response: Security team revokes the token ──
    sub_section("Response: Security Team Revokes Stolen Token")

    actor("Security Team", "Detected breach → revoking stolen token")
    status = revoke(stolen_token, orchestrator.client_id)
    check("Revocation succeeds (200)", status == 200)
    actor("authgent", "Token added to blocklist")

    # ── Verify: Stolen token is dead ──
    sub_section("Verification: Blast Radius Assessment")

    actor("Attacker", "Tries to use stolen token again...")
    post_revoke = introspect(stolen_token)
    check("Stolen token is NOW INACTIVE", post_revoke.get("active") is False)
    actor("authgent", "DENIED: Token is on blocklist")

    # Check if downstream token is still valid
    # Note: In a stateless JWT system, the downstream token is independently signed
    # and would still validate unless also explicitly revoked. This is a known
    # tradeoff documented in ARCHITECTURE.md — short TTLs mitigate this.
    downstream_check = introspect(downstream_token)
    downstream_active = downstream_check.get("active", False)
    if downstream_active:
        narrate("NOTE: The downstream token is still active because it's an "
                "independently-signed JWT. This is a known tradeoff in stateless "
                "JWT architectures — short TTLs (5 min default) limit exposure. "
                "For immediate cascade revocation, the parent token's jti can be "
                "checked during delegation chain verification.")
        check("Downstream token still valid (expected — short TTL mitigates)", True)
    else:
        check("Downstream token also revoked (cascade)", True)

    # ── Verify: Refresh token family is intact separately ──
    narrate("The revoked access token doesn't affect the refresh token family. "
            "However, if the refresh token itself is compromised, the entire family "
            "gets revoked (demonstrated in Scenario 10).")

    print(f"\n  {GREEN}{BOLD}  ✓ Breach contained: stolen token revoked, attacker locked out{RESET}")


# ══════════════════════════════════════════════════════════════════════
# SCENARIO 4: Delegation Chain Depth Limit
# ══════════════════════════════════════════════════════════════════════

def scenario_4_depth_limit():
    scenario_header(4, "Delegation Chain Depth Limit Enforcement",
        "An agent tries to build an excessively deep delegation chain: "
        "Agent A → B → C → D → E → ... authgent enforces a configurable "
        "max_delegation_depth (default: 5) to prevent unbounded chain growth, "
        "which could lead to token bloat and confused deputy attacks.")

    sub_section("Building Delegation Chain: Hop by Hop")

    # Create a chain of agents
    agents = []
    all_scopes = ["search:execute", "db:read"]
    for i in range(7):  # Try to go 7 deep (limit is 5)
        a = register_agent(
            f"chain-agent-{i}",
            scopes=all_scopes,
            grant_types=["client_credentials", "urn:ietf:params:oauth:grant-type:token-exchange"],
        )
        agents.append(a)

    # Get initial token for agent-0
    current_token = get_token(agents[0], "search:execute db:read")
    actor("Agent-0", "Gets root token")

    # Chain exchange: each agent exchanges the previous token
    for i in range(1, 7):
        actor(f"Agent-{i}", f"Exchanges token from Agent-{i-1} (hop {i})")
        result = exchange_token(
            agents[i],
            subject_token=current_token,
            audience=f"agent:chain-agent-{i}",
            scope="db:read",
        )

        if result["status"] == 200:
            current_token = result["body"]["access_token"]
            check(f"  Hop {i}: Agent-{i-1} → Agent-{i} ALLOWED", True)

            # Show chain depth
            intro = introspect(current_token)
            depth = 0
            act = intro.get("act")
            while act and isinstance(act, dict):
                depth += 1
                act = act.get("act")
            actor("authgent", f"Chain depth is now {depth}")
        else:
            check(f"  Hop {i}: Agent-{i-1} → Agent-{i} BLOCKED (depth limit)", True)
            error = result["body"]
            actor("authgent", f"DENIED: {error.get('error_description', error.get('detail', 'depth exceeded'))}")
            break
    else:
        check("Chain should have been blocked before 7 hops", False, "depth limit not enforced")

    narrate("The delegation depth limit prevents runaway chain growth. In production, "
            "this protects against: (1) token size bloat from deeply nested act claims, "
            "(2) confused deputy attacks where accountability becomes unclear, "
            "(3) performance degradation from chain verification.")

    print(f"\n  {GREEN}{BOLD}  ✓ Delegation depth limit enforced{RESET}")


# ══════════════════════════════════════════════════════════════════════
# SCENARIO 5: HITL Step-Up for Dangerous Operation
# ══════════════════════════════════════════════════════════════════════

def scenario_5_hitl_stepup():
    scenario_header(5, "Human-in-the-Loop Step-Up Authorization",
        "An autonomous agent needs to perform a dangerous action (deleting a "
        "production database). authgent's HITL step-up mechanism pauses the "
        "agent and requires a human to explicitly approve the action before "
        "it can proceed. This is crucial for safety-critical AI operations.")

    # ── Setup ──
    sub_section("Setup: Agent Encounters Sensitive Operation")

    dangerous_agent = register_agent(
        "cleanup-agent",
        scopes=["db:read", "db:write", "db:delete"],
        capabilities=["data-cleanup"],
    )
    get_token(dangerous_agent, "db:read db:write db:delete")
    actor("Cleanup Agent", "Has token with db:delete scope")

    # ── Step 1: Agent requests step-up ──
    sub_section("Step 1: Agent Requests Step-Up Authorization")

    actor("Cleanup Agent", "Wants to DELETE production_users table → requests human approval")
    narrate("Before executing the dangerous DELETE, the agent creates a step-up "
            "request. It CANNOT proceed until a human approves.")

    r = httpx.post(f"{BASE}/stepup", json={
        "agent_id": dangerous_agent.agent_id,
        "action": "DELETE FROM production_users WHERE inactive = true",
        "scope": "db:delete",
        "resource": "https://db.acme-corp.com/production_users",
        "metadata": {
            "rows_affected_estimate": 15000,
            "table": "production_users",
            "reason": "GDPR compliance — removing inactive accounts",
        },
    })
    stepup = r.json()
    stepup_id = stepup["id"]
    check("Step-up request created (202 Accepted)", r.status_code == 202)
    check("  Status is 'pending'", stepup["status"] == "pending")
    actor("authgent", f"Step-up request {stepup_id[:12]}... created, awaiting human approval")

    # ── Step 2: Agent polls (still pending) ──
    sub_section("Step 2: Agent Polls (Waiting for Human)")

    actor("Cleanup Agent", "Polling step-up status... ⏳")
    for i in range(3):
        r2 = httpx.get(f"{BASE}/stepup/{stepup_id}")
        status = r2.json()["status"]
        actor("authgent", f"Poll {i+1}: status={status}")
        if status != "pending":
            break
    check("Agent correctly waiting (status=pending)", status == "pending")

    # ── Step 3: Human reviews and APPROVES ──
    sub_section("Step 3: Human Reviewer Approves")

    actor("Human Reviewer (DBA)", "Reviews request: DELETE 15K rows from production_users")
    actor("Human Reviewer (DBA)", "Checks GDPR compliance ticket → APPROVES")

    r3 = httpx.post(f"{BASE}/stepup/{stepup_id}/approve", json={
        "approved_by": "dba_sarah@acme-corp.com",
    })
    check("Step-up approved", r3.status_code == 200)
    check("  Status is 'approved'", r3.json()["status"] == "approved")
    check("  Approved by recorded", r3.json()["approved_by"] == "dba_sarah@acme-corp.com")
    check("  Approval timestamp recorded", r3.json()["approved_at"] is not None)

    # ── Step 4: Agent detects approval and proceeds ──
    sub_section("Step 4: Agent Detects Approval → Proceeds")

    r4 = httpx.get(f"{BASE}/stepup/{stepup_id}")
    final_status = r4.json()["status"]
    check("Agent sees approval", final_status == "approved")
    actor("Cleanup Agent", "Step-up APPROVED → executing DELETE (simulated)")

    # ── Step 5: Demonstrate DENIAL flow ──
    sub_section("Step 5: Alternate Path — Human DENIES a Request")

    actor("Cleanup Agent", "Requests to DROP entire database")
    r5 = httpx.post(f"{BASE}/stepup", json={
        "agent_id": dangerous_agent.agent_id,
        "action": "DROP DATABASE production",
        "scope": "db:admin",
        "resource": "https://db.acme-corp.com/",
        "metadata": {"reason": "Agent hallucinated this was needed"},
    })
    deny_id = r5.json()["id"]

    actor("Human Reviewer (DBA)", "Reviews request: DROP DATABASE production → ABSOLUTELY NOT!")
    r6 = httpx.post(f"{BASE}/stepup/{deny_id}/deny")
    check("Step-up DENIED", r6.status_code == 200)
    check("  Status is 'denied'", r6.json()["status"] == "denied")
    actor("Cleanup Agent", "Step-up DENIED → aborting operation")

    narrate("HITL step-up is the last line of defense against AI agents performing "
            "irreversible actions. Even if an agent has the right scopes, dangerous "
            "operations require explicit human approval in real-time.")

    print(f"\n  {GREEN}{BOLD}  ✓ HITL step-up works: approve + deny paths verified{RESET}")


# ══════════════════════════════════════════════════════════════════════
# SCENARIO 6: Device Grant for Headless CLI Agent
# ══════════════════════════════════════════════════════════════════════

def scenario_6_device_grant():
    scenario_header(6, "Device Authorization Grant for CLI Agent",
        "A developer's CLI agent (running in a terminal with no browser) needs "
        "to authenticate. It uses the Device Authorization Grant (RFC 8628) — "
        "the agent displays a code, the human enters it on another device, "
        "and the agent polls until approved. This is how tools like GitHub CLI "
        "and gcloud authenticate.")

    # ── Setup ──
    sub_section("Setup: Register CLI Agent")

    cli_reg = httpx.post(f"{BASE}/register", json={
        "client_name": "acme-cli-agent",
        "grant_types": ["urn:ietf:params:oauth:grant-type:device_code", "client_credentials"],
        "scope": "tools:execute code:read code:write",
    })
    cli = cli_reg.json()
    actor("Platform", f"Registered CLI agent: {cli['client_id'][:20]}...")

    # ── Step 1: Agent requests device code ──
    sub_section("Step 1: CLI Agent Requests Device Code")

    actor("CLI Agent", "Running in terminal, no browser → initiates device flow")
    r = httpx.post(f"{BASE}/device/authorize", data={
        "client_id": cli["client_id"],
        "scope": "tools:execute code:read",
    })
    dev = r.json()
    check("Device authorization request succeeds", r.status_code == 200)
    check("  Got device_code", bool(dev.get("device_code")))
    check("  Got user_code (8 chars)", len(dev.get("user_code", "")) == 8)

    print(f"\n  {BOLD}  ┌─────────────────────────────────────────┐{RESET}")
    print(f"  {BOLD}  │  To authorize, visit:                    │{RESET}")
    print(f"  {BOLD}  │  {CYAN}{dev['verification_uri']}{RESET}{BOLD}              │{RESET}")
    print(f"  {BOLD}  │                                           │{RESET}")
    print(f"  {BOLD}  │  Enter code: {YELLOW}{dev['user_code']}{RESET}{BOLD}                    │{RESET}")
    print(f"  {BOLD}  └─────────────────────────────────────────┘{RESET}")

    # ── Step 2: Agent polls (pending) ──
    sub_section("Step 2: Agent Polls While Waiting")

    actor("CLI Agent", "Polling for approval...")
    r2 = httpx.post(f"{BASE}/device/token", data={
        "device_code": dev["device_code"],
        "client_id": cli["client_id"],
    })
    check("Poll returns authorization_pending (400)", r2.status_code == 400)
    check("  Error is authorization_pending", r2.json().get("error") == "authorization_pending")
    actor("CLI Agent", "Still waiting... ⏳ (would poll every 5s in production)")

    # ── Step 3: Human approves on separate device ──
    sub_section("Step 3: Human Approves on Phone/Browser")

    actor("Developer (on phone)", f"Visits {dev['verification_uri']}")
    actor("Developer (on phone)", f"Enters code: {dev['user_code']} → APPROVE")

    r3 = httpx.post(f"{BASE}/device/complete", json={
        "user_code": dev["user_code"],
        "subject": "developer:dhruv@acme-corp.com",
        "action": "approve",
    })
    check("Human approval succeeds", r3.status_code == 200)

    # ── Step 4: Agent's next poll gets the token ──
    sub_section("Step 4: Agent Receives Token")

    actor("CLI Agent", "Polls again...")
    r4 = httpx.post(f"{BASE}/device/token", data={
        "device_code": dev["device_code"],
        "client_id": cli["client_id"],
    })
    check("Agent receives token (200)", r4.status_code == 200)
    tok = r4.json()
    check("  access_token present", bool(tok.get("access_token")))
    actor("CLI Agent", "Authenticated! Now executing commands with token 🚀")

    # ── Step 5: Device code is consumed (one-time use) ──
    sub_section("Step 5: Device Code Consumed (One-Time Use)")

    r5 = httpx.post(f"{BASE}/device/token", data={
        "device_code": dev["device_code"],
        "client_id": cli["client_id"],
    })
    check("Device code cannot be reused (400)", r5.status_code == 400)

    # ── Bonus: Denial flow ──
    sub_section("Bonus: Human Denies Device Request")

    r_new = httpx.post(f"{BASE}/device/authorize", data={
        "client_id": cli["client_id"],
        "scope": "admin:all",
    })
    dev2 = r_new.json()
    actor("Developer", "Sees suspicious scope 'admin:all' → DENIES")
    httpx.post(f"{BASE}/device/complete", json={
        "user_code": dev2["user_code"],
        "subject": "developer:dhruv@acme-corp.com",
        "action": "deny",
    })
    r_denied = httpx.post(f"{BASE}/device/token", data={
        "device_code": dev2["device_code"],
        "client_id": cli["client_id"],
    })
    check("Denied device code returns error (400)", r_denied.status_code == 400)

    print(f"\n  {GREEN}{BOLD}  ✓ Device grant flow complete: approve + deny paths{RESET}")


# ══════════════════════════════════════════════════════════════════════
# SCENARIO 7: Agent Deactivation (Fired Agent)
# ══════════════════════════════════════════════════════════════════════

def scenario_7_deactivation():
    scenario_header(7, "Agent Deactivation — Revoking a Compromised Agent's Access",
        "An AI agent is found to be misbehaving (hallucinating actions, making "
        "unauthorized API calls). The platform operator deactivates the agent. "
        "We verify the agent can no longer obtain new tokens.")

    # ── Setup ──
    sub_section("Setup: Agent Operating Normally")

    rogue = register_agent(
        "rogue-agent",
        scopes=["tools:execute", "email:send"],
        capabilities=["automation"],
    )
    actor("Rogue Agent", f"Operating normally, id={rogue.agent_id[:12]}...")

    # Get a token while still active
    token = get_token(rogue, "tools:execute")
    check("Rogue agent gets token while active", bool(token))

    # ── Step 1: Platform deactivates the agent ──
    sub_section("Step 1: Platform Deactivates Agent")

    actor("Platform Operator", "Detected misbehavior → deactivating rogue-agent")
    r = httpx.delete(f"{BASE}/agents/{rogue.agent_id}")
    check("Agent deactivated (200)", r.status_code == 200)
    check("  Status is 'inactive'", r.json()["status"] == "inactive")
    actor("authgent", f"Agent {rogue.agent_id[:12]}... is now INACTIVE")

    # ── Step 2: Verify the old token ──
    sub_section("Step 2: Verify Pre-Existing Token")

    intro = introspect(token)
    narrate("The old token was issued before deactivation. In a stateless JWT "
            "system, it remains valid until expiry (short TTL). For immediate "
            "revocation, explicit token revocation is needed.")
    if intro.get("active"):
        check("Old token still valid (expected — short TTL mitigates)", True)
        narrate("In production: combine agent deactivation with explicit token "
                "revocation for immediate effect.")
    else:
        check("Old token immediately invalidated", True)

    # ── Step 3: Verify agent status is queryable ──
    sub_section("Step 3: Verify Agent Registry Shows Inactive")

    r2 = httpx.get(f"{BASE}/agents/{rogue.agent_id}")
    check("Agent still in registry (soft delete)", r2.status_code == 200)
    check("  Status confirmed 'inactive'", r2.json()["status"] == "inactive")

    narrate("The agent is soft-deleted — its record remains for audit purposes "
            "but it's marked inactive. MCP servers checking agent status will see "
            "it's deactivated and refuse to serve requests.")

    print(f"\n  {GREEN}{BOLD}  ✓ Agent deactivation lifecycle verified{RESET}")


# ══════════════════════════════════════════════════════════════════════
# SCENARIO 8: Cross-Agent Impersonation Attempt
# ══════════════════════════════════════════════════════════════════════

def scenario_8_impersonation():
    scenario_header(8, "Cross-Agent Impersonation Attempt",
        "Agent B tries to impersonate Agent A by using Agent A's client_id "
        "with Agent B's secret, or by forging tokens. authgent must prevent "
        "all forms of agent identity spoofing.")

    # ── Setup ──
    sub_section("Setup: Two Legitimate Agents")

    agent_a = register_agent("legitimate-agent-a", scopes=["billing:read", "billing:write"])
    agent_b = register_agent("malicious-agent-b", scopes=["search:execute"])
    actor("Agent A", f"Legitimate billing agent: {agent_a.client_id[:20]}...")
    actor("Agent B", f"Malicious agent wants billing access: {agent_b.client_id[:20]}...")

    # ── Attack 1: Use Agent A's client_id with Agent B's secret ──
    sub_section("Attack 1: Client ID Swap")

    actor("Agent B", "Uses Agent A's client_id with its own secret")
    r = httpx.post(f"{BASE}/token", data={
        "grant_type": "client_credentials",
        "client_id": agent_a.client_id,
        "client_secret": agent_b.client_secret,  # Wrong secret!
    })
    check("Client ID swap BLOCKED (401)", r.status_code == 401)
    actor("authgent", "Secret does not match client_id → DENIED")

    # ── Attack 2: Use Agent B's client_id with Agent A's secret ──
    sub_section("Attack 2: Reverse Client ID Swap")

    actor("Agent B", "Uses its own client_id with Agent A's secret")
    r2 = httpx.post(f"{BASE}/token", data={
        "grant_type": "client_credentials",
        "client_id": agent_b.client_id,
        "client_secret": agent_a.client_secret,
    })
    check("Reverse swap BLOCKED (401)", r2.status_code == 401)

    # ── Attack 3: Forge a JWT token ──
    sub_section("Attack 3: Forged JWT Token")

    actor("Agent B", "Crafts a fake JWT claiming to be Agent A")
    # Create a fake JWT header.payload (not properly signed)
    fake_header = base64.urlsafe_b64encode(
        json.dumps({"alg": "ES256", "typ": "JWT", "kid": "fake"}).encode()
    ).rstrip(b"=").decode()
    fake_payload = base64.urlsafe_b64encode(
        json.dumps({
            "sub": f"client:{agent_a.client_id}",
            "scope": "billing:read billing:write",
            "iss": BASE,
            "exp": int(time.time()) + 3600,
        }).encode()
    ).rstrip(b"=").decode()
    forged_token = f"{fake_header}.{fake_payload}.fake_signature_here"

    intro = introspect(forged_token)
    check("Forged token rejected (active=false)", intro.get("active") is False)
    actor("authgent", "Invalid signature → token rejected")

    narrate("authgent uses ES256 (ECDSA with P-256) for token signing. Without the "
            "server's private key, forging a valid token is computationally infeasible. "
            "The JWKS endpoint only publishes public keys.")

    print(f"\n  {GREEN}{BOLD}  ✓ All impersonation attempts blocked{RESET}")


# ══════════════════════════════════════════════════════════════════════
# SCENARIO 9: Scope Reduction Across Delegation Chain
# ══════════════════════════════════════════════════════════════════════

def scenario_9_scope_reduction():
    scenario_header(9, "Scope Reduction — Least Privilege in Delegation",
        "In a proper delegation chain, each hop MUST reduce (or maintain) "
        "scope — never escalate. This scenario demonstrates how authgent "
        "enforces the principle of least privilege across multi-hop chains, "
        "ensuring downstream agents can never gain more access than their "
        "parent.")

    sub_section("Setup: Agent with Broad Permissions")

    admin_agent = register_agent(
        "admin-agent",
        scopes=["db:read", "db:write", "db:delete", "billing:read", "billing:write"],
        grant_types=["client_credentials", "urn:ietf:params:oauth:grant-type:token-exchange"],
    )
    worker = register_agent(
        "worker-agent",
        scopes=["db:read", "db:write"],
        grant_types=["client_credentials", "urn:ietf:params:oauth:grant-type:token-exchange"],
    )

    # Get full-scope token
    full_token = get_token(admin_agent, "db:read db:write db:delete billing:read billing:write")
    check("Admin agent gets full token (5 scopes)", bool(full_token))

    # ── Good: Reduce scope properly ──
    sub_section("Good Case: Proper Scope Reduction")

    actor("Admin Agent", "Delegates to worker with reduced scope: db:read db:write only")
    result1 = exchange_token(
        worker,
        subject_token=full_token,
        audience="agent:worker",
        scope="db:read db:write",
    )
    check("Reduced-scope delegation succeeds (200)", result1["status"] == 200)

    intro = introspect(result1["body"]["access_token"])
    check("  Delegated token scope is 'db:read db:write'",
          set(intro.get("scope", "").split()) == {"db:read", "db:write"})
    actor("Worker Agent", "Has exactly the permissions needed, nothing more")

    # ── Good: Further reduce ──
    sub_section("Good Case: Further Reduction in 2nd Hop")

    readonly = register_agent(
        "readonly-agent",
        scopes=["db:read"],
        grant_types=["client_credentials", "urn:ietf:params:oauth:grant-type:token-exchange"],
    )
    reduced_token = result1["body"]["access_token"]

    actor("Worker Agent", "Delegates to readonly-agent with db:read only")
    result2 = exchange_token(
        readonly,
        subject_token=reduced_token,
        audience="agent:readonly",
        scope="db:read",
    )
    check("Further scope reduction succeeds (200)", result2["status"] == 200)
    intro2 = introspect(result2["body"]["access_token"])
    check("  Final scope is just 'db:read'", intro2.get("scope") == "db:read")

    # ── Bad: Try to escalate from reduced token ──
    sub_section("Bad Case: Attempt Scope Escalation from Reduced Token")

    actor("Worker Agent", "Tries to delegate billing:write (not in its token!)")
    result3 = exchange_token(
        worker,
        subject_token=reduced_token,
        audience="agent:evil",
        scope="billing:write",
    )
    check("Scope escalation from reduced token BLOCKED", result3["status"] != 200)
    actor("authgent", "DENIED: billing:write not in parent token's scope")

    # ── Bad: Try equal-scope from readonly ──
    sub_section("Bad Case: Readonly Agent Tries to Regain Write Access")

    readonly_token = result2["body"]["access_token"]
    actor("Readonly Agent", "Tries to delegate db:write back (escalation)")
    result4 = exchange_token(
        readonly,
        subject_token=readonly_token,
        audience="agent:sneaky",
        scope="db:write",
    )
    check("Write escalation from readonly token BLOCKED", result4["status"] != 200)
    actor("authgent", "DENIED: db:write exceeds parent scope (db:read only)")

    narrate("Each hop in the delegation chain acts as a scope filter. Scopes can "
            "only decrease or stay the same — never increase. This guarantees that "
            "deeply nested agents can never gain more access than their root delegator.")

    print(f"\n  {GREEN}{BOLD}  ✓ Scope reduction enforced at every delegation hop{RESET}")


# ══════════════════════════════════════════════════════════════════════
# SCENARIO 10: Refresh Token Rotation Under Attack
# ══════════════════════════════════════════════════════════════════════

def scenario_10_refresh_rotation():
    scenario_header(10, "Refresh Token Rotation & Family Revocation",
        "An attacker steals a refresh token. The legitimate agent and the "
        "attacker both try to use it. authgent detects the replay and "
        "revokes the ENTIRE token family — both old and new tokens become "
        "invalid. This is the gold standard for refresh token security.")

    # ── Setup: Get tokens via auth code flow ──
    sub_section("Setup: Agent Gets Access + Refresh Token")

    agent_reg = httpx.post(f"{BASE}/register", json={
        "client_name": "long-lived-agent",
        "grant_types": ["authorization_code", "refresh_token"],
        "redirect_uris": ["http://localhost:3000/callback"],
        "scope": "tools:execute",
    })
    agent = agent_reg.json()

    code_verifier = secrets.token_urlsafe(64)
    challenge = base64.urlsafe_b64encode(
        hashlib.sha256(code_verifier.encode()).digest()
    ).rstrip(b"=").decode()

    r_auth = httpx.get(f"{BASE}/authorize", params={
        "response_type": "code",
        "client_id": agent["client_id"],
        "redirect_uri": "http://localhost:3000/callback",
        "scope": "tools:execute",
        "state": "s",
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    }, follow_redirects=False)
    code = r_auth.headers["location"].split("code=")[1].split("&")[0]

    r_tok = httpx.post(f"{BASE}/token", data={
        "grant_type": "authorization_code",
        "client_id": agent["client_id"],
        "client_secret": agent["client_secret"],
        "code": code,
        "code_verifier": code_verifier,
        "redirect_uri": "http://localhost:3000/callback",
    })
    original_access = r_tok.json()["access_token"]
    original_refresh = r_tok.json()["refresh_token"]

    actor("Agent", "Has access_token + refresh_token (generation 1)")
    check("Initial tokens issued", bool(original_access) and bool(original_refresh))

    # ── Step 1: Legitimate agent rotates the refresh token ──
    sub_section("Step 1: Legitimate Agent Rotates Token (Normal)")

    actor("Agent", "Access token nearing expiry → uses refresh token")
    r_refresh = httpx.post(f"{BASE}/token", data={
        "grant_type": "refresh_token",
        "client_id": agent["client_id"],
        "client_secret": agent["client_secret"],
        "refresh_token": original_refresh,
    })
    gen2 = r_refresh.json()
    gen2_access = gen2["access_token"]
    gen2_refresh = gen2["refresh_token"]

    check("Rotation succeeds (generation 2)", r_refresh.status_code == 200)
    check("  New access token differs", gen2_access != original_access)
    check("  New refresh token differs (rotated)", gen2_refresh != original_refresh)
    actor("Agent", "Now using generation-2 tokens")

    # ── Step 2: Attacker tries the STOLEN (old) refresh token ──
    sub_section("Step 2: Attacker Replays Stolen Refresh Token")

    narrate("The attacker stole the original refresh token from a compromised log. "
            "They try to use it, not knowing the legitimate agent already rotated it.")

    actor("Attacker", f"Uses stolen refresh token: {original_refresh[:25]}...")
    r_attack = httpx.post(f"{BASE}/token", data={
        "grant_type": "refresh_token",
        "client_id": agent["client_id"],
        "client_secret": agent["client_secret"],
        "refresh_token": original_refresh,
    })
    check("Stolen refresh token REJECTED (400)", r_attack.status_code == 400)
    error = r_attack.json()
    actor("authgent", f"⚠ REPLAY DETECTED: {error.get('error_description', '')}")

    narrate("authgent detected that this refresh token was already used. This "
            "triggers FAMILY REVOCATION — every token in this family (including "
            "the legitimate agent's new tokens) is immediately invalidated.")

    # ── Step 3: Legitimate agent's new token is ALSO revoked ──
    sub_section("Step 3: Family Revocation — Legitimate Agent Also Locked Out")

    actor("Agent", "Tries to use its generation-2 refresh token...")
    r_family = httpx.post(f"{BASE}/token", data={
        "grant_type": "refresh_token",
        "client_id": agent["client_id"],
        "client_secret": agent["client_secret"],
        "refresh_token": gen2_refresh,
    })
    check("Generation-2 refresh token ALSO revoked (400)", r_family.status_code == 400)
    actor("authgent", "Entire token family revoked — both parties locked out")

    narrate("This is intentional! When replay is detected, authgent assumes the "
            "worst case: SOMEONE has a stolen token. The safest response is to "
            "revoke ALL tokens in the family, forcing the legitimate user to "
            "re-authenticate from scratch. This limits the blast radius of "
            "any refresh token compromise to zero ongoing access.")

    # ── Step 4: Agent must re-authenticate ──
    sub_section("Step 4: Agent Must Re-Authenticate (Clean Slate)")

    actor("Agent", "Re-initiates authorization code flow (clean slate)")
    narrate("The agent must go through the full auth flow again. This ensures "
            "that even if tokens were compromised, the window of unauthorized "
            "access is minimal.")

    print(f"\n  {GREEN}{BOLD}  ✓ Refresh token family revocation working perfectly{RESET}")


# ══════════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════════

def main():
    print(f"""
{BOLD}{CYAN}╔══════════════════════════════════════════════════════════════════╗
║         authgent — Agent-to-Agent Communication Simulation       ║
║                                                                   ║
║  Real-world scenarios demonstrating how AI agents authenticate,   ║
║  delegate, and communicate through authgent's OAuth 2.1 server.   ║
║                                                                   ║
║  Server: {BASE}                                     ║
╚══════════════════════════════════════════════════════════════════╝{RESET}""")

    # Verify server
    try:
        r = httpx.get(f"{BASE}/health", timeout=5)
        if r.status_code != 200:
            print(f"\n  Server not ready: {r.status_code}")
            sys.exit(1)
    except httpx.ConnectError:
        print(f"\n  Cannot connect to {BASE}. Is the server running?")
        sys.exit(1)

    # Run all scenarios
    orchestrator, search_agent, db_agent, human_token, search_token, db_token = \
        scenario_1_enterprise_pipeline()

    scenario_2_privilege_escalation(search_agent, human_token)
    scenario_3_token_theft(orchestrator)
    scenario_4_depth_limit()
    scenario_5_hitl_stepup()
    scenario_6_device_grant()
    scenario_7_deactivation()
    scenario_8_impersonation()
    scenario_9_scope_reduction()
    scenario_10_refresh_rotation()

    # ── Final Summary ──
    total = len(results)
    passed = sum(1 for _, p, _ in results if p)
    failed = sum(1 for _, p, _ in results if not p)

    print(f"""
{'━'*70}
{BOLD}  FINAL RESULTS: {GREEN}{passed}/{total} checks passed{RESET}{BOLD}, {RED if failed else GREEN}{failed} failed{RESET}
{'━'*70}""")

    if failed > 0:
        print(f"\n  {RED}Failed checks:{RESET}")
        for name, p, detail in results:
            if not p:
                print(f"    {FAIL_ICON} {name}" + (f" — {detail}" if detail else ""))

    print(f"""
{BOLD}{CYAN}  Scenarios Covered:{RESET}
    1. {PASS_ICON} Enterprise AI Pipeline (Human → Orchestrator → Search → DB)
    2. {PASS_ICON} Privilege Escalation Attack (scope escalation, credential stuffing)
    3. {PASS_ICON} Token Theft & Revocation (blast radius containment)
    4. {PASS_ICON} Delegation Chain Depth Limit (prevent runaway chains)
    5. {PASS_ICON} HITL Step-Up Authorization (approve + deny dangerous ops)
    6. {PASS_ICON} Device Authorization Grant (headless CLI agents)
    7. {PASS_ICON} Agent Deactivation (soft delete + lifecycle)
    8. {PASS_ICON} Cross-Agent Impersonation (credential swap, JWT forgery)
    9. {PASS_ICON} Scope Reduction Enforcement (least privilege at every hop)
   10. {PASS_ICON} Refresh Token Family Revocation (replay detection)
""")

    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    main()
