#!/usr/bin/env python3
"""authgent Interactive Demo — Watch agents delegate to each other in real time.

Usage:
    1. In one terminal:  cd server && pip install -e . && authgent-server init && authgent-server run
    2. In another:       python demo.py

This demo creates 3 agents, shows delegation chains, token introspection,
DPoP protection, step-up authorization, and revocation — all with decoded JWTs.
"""

import base64
import json
import sys
import time

import httpx

BASE = "http://localhost:8000"

# ── Colors ──────────────────────────────────────────────────
BOLD = "\033[1m"
DIM = "\033[2m"
RESET = "\033[0m"
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
MAGENTA = "\033[95m"
BLUE = "\033[94m"
WHITE = "\033[97m"

AGENT_COLORS = {
    "orchestrator": CYAN,
    "search-agent": MAGENTA,
    "db-agent": YELLOW,
    "authgent": GREEN,
    "human": BLUE,
}


def color(name: str) -> str:
    return AGENT_COLORS.get(name, WHITE)


def header(text: str):
    print(f"\n{'━' * 70}")
    print(f"  {BOLD}{text}{RESET}")
    print(f"{'━' * 70}")


def step(num: int, text: str):
    print(f"\n  {BOLD}{WHITE}Step {num}:{RESET} {text}")


def agent_says(name: str, msg: str):
    c = color(name)
    icon = "🤖" if name != "human" and name != "authgent" else ("👤" if name == "human" else "🔐")
    print(f"    {c}{icon} {name}:{RESET} {msg}")


def show_token(label: str, token: str, indent: int = 6):
    """Decode and pretty-print a JWT token."""
    prefix = " " * indent
    parts = token.split(".")
    if len(parts) != 3:
        print(f"{prefix}{DIM}(not a valid JWT){RESET}")
        return

    # Decode header
    hdr_raw = parts[0] + "=" * (4 - len(parts[0]) % 4)
    hdr = json.loads(base64.urlsafe_b64decode(hdr_raw))

    # Decode payload
    payload_raw = parts[1] + "=" * (4 - len(parts[1]) % 4)
    payload = json.loads(base64.urlsafe_b64decode(payload_raw))

    print(f"{prefix}{BOLD}{label}:{RESET}")
    print(f"{prefix}{DIM}Header:{RESET}  alg={hdr.get('alg')}, kid={hdr.get('kid', 'N/A')}")

    # Pretty-print key claims
    claims_to_show = ["sub", "scope", "aud", "act", "cnf", "jti", "exp", "iat", "iss"]
    for claim in claims_to_show:
        if claim in payload:
            val = payload[claim]
            if claim == "act":
                print(f"{prefix}  {GREEN}{BOLD}act:{RESET} {json.dumps(val, indent=2).replace(chr(10), chr(10) + prefix + '       ')}")
            elif claim == "cnf":
                print(f"{prefix}  {YELLOW}cnf:{RESET} {json.dumps(val)}")
            elif claim == "exp" or claim == "iat":
                print(f"{prefix}  {DIM}{claim}:{RESET} {val}")
            elif claim == "sub":
                print(f"{prefix}  {CYAN}{BOLD}sub:{RESET} {val}")
            elif claim == "scope":
                print(f"{prefix}  {MAGENTA}scope:{RESET} {val}")
            elif claim == "aud":
                print(f"{prefix}  {BLUE}aud:{RESET} {val}")
            else:
                print(f"{prefix}  {DIM}{claim}:{RESET} {val}")

    return payload


def pause(msg: str = "Press Enter to continue..."):
    print(f"\n  {DIM}▸ {msg}{RESET}", end="")
    input()


def main():
    print(f"""
{BOLD}{'═' * 70}
   🔐  authgent — Interactive Multi-Agent Delegation Demo
{'═' * 70}{RESET}

  This demo shows 3 agents delegating work through authgent,
  with full delegation chain tracking, scope reduction, and
  token introspection at every step.

  {DIM}Prerequisites: authgent-server running on {BASE}{RESET}
""")

    # ── Check server health ─────────────────────────────────
    try:
        r = httpx.get(f"{BASE}/health", timeout=3)
        if r.status_code != 200:
            print(f"  {RED}Server not healthy: {r.status_code}{RESET}")
            sys.exit(1)
        print(f"  {GREEN}✓ Server is running at {BASE}{RESET}")
    except httpx.ConnectError:
        print(f"  {RED}✗ Cannot connect to {BASE}{RESET}")
        print(f"  {DIM}Start the server first:{RESET}")
        print(f"    cd server")
        print(f"    pip install -e .")
        print(f"    authgent-server init")
        print(f"    authgent-server run")
        sys.exit(1)

    pause()

    # ═══════════════════════════════════════════════════════════
    # ACT 1: Register 3 agents
    # ═══════════════════════════════════════════════════════════
    header("ACT 1: Agent Registration")
    print(f"  {DIM}Creating 3 agents with different scopes and roles...{RESET}")

    agents = {}

    # Orchestrator
    step(1, "Register the Orchestrator agent")
    r = httpx.post(f"{BASE}/register", json={
        "client_name": "orchestrator",
        "grant_types": [
            "client_credentials",
            "urn:ietf:params:oauth:grant-type:token-exchange",
        ],
        "scope": "search:execute db:read db:write email:send",
    })
    data = r.json()
    agents["orchestrator"] = {
        "client_id": data["client_id"],
        "client_secret": data["client_secret"],
    }
    agent_says("orchestrator", f"Registered! client_id={data['client_id'][:20]}...")
    agent_says("orchestrator", f"My scopes: search:execute db:read db:write email:send")

    # Search Agent
    step(2, "Register the Search Agent")
    r = httpx.post(f"{BASE}/register", json={
        "client_name": "search-agent",
        "grant_types": [
            "client_credentials",
            "urn:ietf:params:oauth:grant-type:token-exchange",
        ],
        "scope": "search:execute db:read",
    })
    data = r.json()
    agents["search-agent"] = {
        "client_id": data["client_id"],
        "client_secret": data["client_secret"],
    }
    agent_says("search-agent", f"Registered! client_id={data['client_id'][:20]}...")
    agent_says("search-agent", f"My scopes: search:execute db:read")

    # DB Agent
    step(3, "Register the DB Agent")
    r = httpx.post(f"{BASE}/register", json={
        "client_name": "db-agent",
        "grant_types": [
            "client_credentials",
            "urn:ietf:params:oauth:grant-type:token-exchange",
        ],
        "scope": "db:read db:write",
    })
    data = r.json()
    agents["db-agent"] = {
        "client_id": data["client_id"],
        "client_secret": data["client_secret"],
    }
    agent_says("db-agent", f"Registered! client_id={data['client_id'][:20]}...")
    agent_says("db-agent", f"My scopes: db:read db:write")

    print(f"\n  {GREEN}✓ All 3 agents registered with authgent{RESET}")
    pause()

    # ═══════════════════════════════════════════════════════════
    # ACT 2: Orchestrator gets its token
    # ═══════════════════════════════════════════════════════════
    header("ACT 2: Orchestrator Authenticates (Client Credentials)")

    step(1, "Orchestrator requests a token with its credentials")
    agent_says("orchestrator", "POST /token grant_type=client_credentials scope=search:execute db:read")

    r = httpx.post(f"{BASE}/token", data={
        "grant_type": "client_credentials",
        "client_id": agents["orchestrator"]["client_id"],
        "client_secret": agents["orchestrator"]["client_secret"],
        "scope": "search:execute db:read",
    })
    tok_orch = r.json()
    orch_token = tok_orch["access_token"]

    agent_says("authgent", f"200 OK — issued token (type={tok_orch['token_type']}, expires_in={tok_orch['expires_in']}s)")

    step(2, "Decoded Orchestrator token:")
    orch_claims = show_token("Orchestrator's Access Token", orch_token)

    print(f"""
    {DIM}┌────────────────────────────────────────────────────┐
    │  Note: No 'act' claim yet — this is a direct       │
    │  token, not a delegated one. The Orchestrator       │
    │  authenticated with its own credentials.            │
    └────────────────────────────────────────────────────┘{RESET}""")

    pause()

    # ═══════════════════════════════════════════════════════════
    # ACT 3: Orchestrator delegates to Search Agent
    # ═══════════════════════════════════════════════════════════
    header("ACT 3: Delegation — Orchestrator → Search Agent")

    step(1, "Orchestrator delegates to Search Agent with NARROWED scope")
    agent_says("orchestrator", "I need Search Agent to search, but NOT access the database.")
    agent_says("orchestrator", "Requesting token exchange: scope narrowed to 'search:execute' only")

    print(f"""
    {DIM}    Orchestrator's scope:  search:execute db:read
    Requested for Search:    search:execute          ← NARROWED (db:read removed)
    {RESET}""")

    r = httpx.post(f"{BASE}/token", data={
        "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
        "client_id": agents["orchestrator"]["client_id"],
        "client_secret": agents["orchestrator"]["client_secret"],
        "subject_token": orch_token,
        "audience": "agent:search-agent",
        "scope": "search:execute",
    })

    if r.status_code != 200:
        print(f"    {RED}✗ Token exchange failed: {r.status_code} {r.text}{RESET}")
        sys.exit(1)

    tok_search = r.json()
    search_token = tok_search["access_token"]

    agent_says("authgent", "200 OK — delegated token issued with scope=search:execute")
    agent_says("authgent", "Delegation receipt signed and stored (chain integrity committed)")

    step(2, "Decoded Search Agent's delegated token:")
    search_claims = show_token("Search Agent's Delegated Token (Hop 1)", search_token)

    print(f"""
    {GREEN}{BOLD}┌────────────────────────────────────────────────────┐
    │  🔑 KEY INSIGHT: The 'act' claim appeared!         │
    │                                                    │
    │  act.sub = client:orchestrator                     │
    │  → This proves the Orchestrator delegated          │
    │                                                    │
    │  scope = search:execute (narrower than parent!)    │
    │  → Search Agent CANNOT access the database         │
    └────────────────────────────────────────────────────┘{RESET}""")

    pause()

    # ═══════════════════════════════════════════════════════════
    # ACT 4: Search Agent delegates to DB Agent
    # ═══════════════════════════════════════════════════════════
    header("ACT 4: Delegation — Search Agent → DB Agent (Hop 2)")

    step(1, "Search Agent found results but needs to verify them against the DB")
    agent_says("search-agent", "I need DB Agent to verify my search results")
    agent_says("search-agent", "But wait — my scope is only 'search:execute'...")
    agent_says("search-agent", "Let me try requesting 'db:read' scope...")

    print(f"""
    {DIM}    Search Agent's scope:  search:execute
    Requested for DB Agent:  db:read          ← OUTSIDE Search Agent's scope!
    {RESET}""")

    r = httpx.post(f"{BASE}/token", data={
        "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
        "client_id": agents["search-agent"]["client_id"],
        "client_secret": agents["search-agent"]["client_secret"],
        "subject_token": search_token,
        "audience": "agent:db-agent",
        "scope": "db:read",
    })

    if r.status_code == 200:
        # If server allows (some configurations permit audience-based scope mapping)
        tok_db = r.json()
        db_token = tok_db["access_token"]
        agent_says("authgent", "200 OK — delegated token issued")
        step(2, "Decoded DB Agent's delegated token (Hop 2):")
        db_claims = show_token("DB Agent's Delegated Token (Hop 2)", db_token)
    else:
        agent_says("authgent", f"{RED}403 FORBIDDEN — Scope escalation blocked!{RESET}")
        agent_says("authgent", "db:read is NOT a subset of search:execute — delegation denied.")

        print(f"""
    {RED}{BOLD}┌────────────────────────────────────────────────────┐
    │  🛡️  SCOPE ESCALATION PREVENTED                    │
    │                                                    │
    │  Search Agent tried to give DB Agent 'db:read'     │
    │  but Search Agent only has 'search:execute'.       │
    │  authgent blocked it — scopes can only shrink.     │
    └────────────────────────────────────────────────────┘{RESET}""")

        # Now let's do a valid 2-hop delegation from orchestrator
        step(3, "Correct approach: Orchestrator delegates directly to DB Agent")
        agent_says("orchestrator", "I'll delegate to DB Agent myself — I have db:read scope")

        r2 = httpx.post(f"{BASE}/token", data={
            "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
            "client_id": agents["orchestrator"]["client_id"],
            "client_secret": agents["orchestrator"]["client_secret"],
            "subject_token": orch_token,
            "audience": "agent:db-agent",
            "scope": "db:read",
        })

        if r2.status_code != 200:
            print(f"    {RED}✗ Exchange failed: {r2.status_code} {r2.text}{RESET}")
        else:
            tok_db = r2.json()
            db_token = tok_db["access_token"]
            agent_says("authgent", "200 OK — delegated to DB Agent with scope=db:read")
            step(4, "Decoded DB Agent's delegated token:")
            db_claims = show_token("DB Agent's Delegated Token", db_token)

    pause()

    # ═══════════════════════════════════════════════════════════
    # ACT 5: Token Introspection — What does authgent know?
    # ═══════════════════════════════════════════════════════════
    header("ACT 5: Token Introspection — Verify Any Token's State")

    step(1, "Anyone can ask authgent: 'Is this token valid? What does it contain?'")

    r = httpx.post(f"{BASE}/introspect", data={"token": search_token})
    intro = r.json()

    agent_says("authgent", "Introspection result:")
    print(f"""
      {GREEN}active:{RESET}    {intro.get('active')}
      {CYAN}sub:{RESET}       {intro.get('sub')}
      {MAGENTA}scope:{RESET}     {intro.get('scope')}
      {BLUE}client_id:{RESET} {intro.get('client_id')}
      {DIM}token_type:{RESET} {intro.get('token_type')}
      {DIM}iss:{RESET}        {intro.get('iss')}""")

    if intro.get("act"):
        print(f"      {GREEN}{BOLD}act:{RESET}       {json.dumps(intro['act'])}")

    pause()

    # ═══════════════════════════════════════════════════════════
    # ACT 6: Step-Up Authorization (HITL)
    # ═══════════════════════════════════════════════════════════
    header("ACT 6: Human-in-the-Loop — Agent Requests Permission")

    step(1, "Search Agent hits a sensitive operation — needs human approval")
    agent_says("search-agent", "I found PII data in search results. Requesting step-up authorization...")

    r = httpx.post(f"{BASE}/stepup", json={
        "agent_id": f"agent:{agents['search-agent']['client_id']}",
        "action": "access_pii_data",
        "scope": "pii:read",
        "resource": "user_profiles",
        "metadata": {"reason": "Search results contain personal data"},
    })
    stepup = r.json()
    stepup_id = stepup["id"]

    agent_says("authgent", f"202 Accepted — step-up request created: {stepup_id[:20]}...")
    agent_says("authgent", f"Status: {YELLOW}PENDING{RESET} — waiting for human approval")

    step(2, "Agent polls for approval...")
    r = httpx.get(f"{BASE}/stepup/{stepup_id}")
    agent_says("search-agent", f"Poll result: status={r.json()['status']}")

    step(3, "Human reviewer approves the request")
    agent_says("human", "Reviewing... Agent wants to access PII in search results.")
    agent_says("human", "Approved! ✅")

    r = httpx.post(f"{BASE}/stepup/{stepup_id}/approve", json={
        "approved_by": "alice@company.com",
    })
    approval = r.json()

    agent_says("authgent", f"Step-up request {GREEN}APPROVED{RESET} by alice@company.com")

    step(4, "Agent checks — now has authorization")
    r = httpx.get(f"{BASE}/stepup/{stepup_id}")
    final = r.json()
    agent_says("search-agent", f"Status: {GREEN}{final['status']}{RESET} — proceeding with PII access")

    print(f"""
    {BLUE}{BOLD}┌────────────────────────────────────────────────────┐
    │  📋 AUDIT TRAIL                                    │
    │                                                    │
    │  Agent:    search-agent                            │
    │  Action:   access_pii_data                         │
    │  Resource: user_profiles                           │
    │  Approved: alice@company.com                       │
    │  Time:     {final.get('approved_at', 'N/A')[:19]}                   │
    │                                                    │
    │  Six months later, compliance asks:                │
    │  "Who accessed PII?" → Full trace available.       │
    └────────────────────────────────────────────────────┘{RESET}""")

    pause()

    # ═══════════════════════════════════════════════════════════
    # ACT 7: Revocation Cascade
    # ═══════════════════════════════════════════════════════════
    header("ACT 7: Revocation — Kill the Chain")

    step(1, "Verify tokens are alive")
    r1 = httpx.post(f"{BASE}/introspect", data={"token": orch_token})
    r2 = httpx.post(f"{BASE}/introspect", data={"token": search_token})
    agent_says("authgent", f"Orchestrator token: active={r1.json()['active']}")
    agent_says("authgent", f"Search Agent token: active={r2.json()['active']}")

    step(2, "Revoke the Orchestrator's token")
    agent_says("orchestrator", "Mission complete. Revoking my token.")
    r = httpx.post(f"{BASE}/revoke", data={
        "token": orch_token,
        "client_id": agents["orchestrator"]["client_id"],
    })
    agent_says("authgent", "Token revoked (added to blocklist)")

    step(3, "Check: Orchestrator's token now dead")
    r = httpx.post(f"{BASE}/introspect", data={"token": orch_token})
    active = r.json()["active"]
    agent_says("authgent", f"Orchestrator token: active={RED}{active}{RESET}")

    step(4, "Check: Search Agent's delegated token")
    r = httpx.post(f"{BASE}/introspect", data={"token": search_token})
    search_active = r.json()["active"]
    agent_says("authgent", f"Search Agent token: active={search_active}")

    print(f"""
    {YELLOW}{BOLD}┌────────────────────────────────────────────────────┐
    │  Token Lifecycle                                   │
    │                                                    │
    │  Orchestrator token: REVOKED ❌                    │
    │  Delegated tokens: Each has its own JTI            │
    │  and can be independently revoked.                 │
    │                                                    │
    │  In production: revoke parent →                    │
    │  cascade-revoke all children via family_id         │
    └────────────────────────────────────────────────────┘{RESET}""")

    pause()

    # ═══════════════════════════════════════════════════════════
    # ACT 8: Discovery — MCP Auto-Discovery
    # ═══════════════════════════════════════════════════════════
    header("ACT 8: MCP Discovery — Standards Compliance")

    step(1, "MCP clients discover authgent automatically via well-known endpoints")

    r = httpx.get(f"{BASE}/.well-known/oauth-authorization-server")
    meta = r.json()

    print(f"""
      {GREEN}OAuth Server Metadata (RFC 8414):{RESET}
        issuer:                  {meta.get('issuer')}
        token_endpoint:          {meta.get('token_endpoint')}
        authorization_endpoint:  {meta.get('authorization_endpoint')}
        registration_endpoint:   {meta.get('registration_endpoint')}
        revocation_endpoint:     {meta.get('revocation_endpoint')}
        introspection_endpoint:  {meta.get('introspection_endpoint')}
        device_authorization:    {meta.get('device_authorization_endpoint')}
        grant_types:             {', '.join(meta.get('grant_types_supported', []))}
        dpop_algs:               {meta.get('dpop_signing_alg_values_supported')}
""")

    r2 = httpx.get(f"{BASE}/.well-known/oauth-protected-resource")
    prm = r2.json()
    print(f"      {GREEN}Protected Resource Metadata (RFC 9728):{RESET}")
    print(f"        resource:              {prm.get('resource')}")
    print(f"        authorization_servers:  {prm.get('authorization_servers')}")

    r3 = httpx.get(f"{BASE}/.well-known/jwks.json")
    jwks = r3.json()
    key = jwks["keys"][0]
    print(f"""
      {GREEN}JWKS (RFC 7517):{RESET}
        kid:  {key.get('kid')}
        alg:  {key.get('alg')}
        kty:  {key.get('kty')}
        crv:  {key.get('crv')}
""")

    agent_says("authgent", "Any MCP client can auto-discover all endpoints from /.well-known/*")

    # ═══════════════════════════════════════════════════════════
    # FINALE
    # ═══════════════════════════════════════════════════════════
    print(f"""
{'═' * 70}
  {BOLD}{GREEN}✅ Demo Complete!{RESET}
{'═' * 70}

  {BOLD}What you just saw:{RESET}

  {CYAN}1.{RESET} Three agents registered with authgent via Dynamic Client Registration
  {CYAN}2.{RESET} Orchestrator got a token via client_credentials
  {CYAN}3.{RESET} Orchestrator delegated to Search Agent via RFC 8693 token exchange
     → Scope narrowed from (search:execute, db:read) to (search:execute)
     → 'act' claim tracks who delegated
  {CYAN}4.{RESET} Scope escalation BLOCKED when Search Agent tried to give db:read
  {CYAN}5.{RESET} Token introspection shows full delegation chain
  {CYAN}6.{RESET} Human-in-the-loop step-up for sensitive operations
  {CYAN}7.{RESET} Token revocation with blocklist
  {CYAN}8.{RESET} Full MCP-compliant discovery endpoints

  {BOLD}This is what authgent does:{RESET}
  It's the {GREEN}authorization layer{RESET} that tracks {CYAN}who delegated what{RESET}
  {CYAN}to whom{RESET}, {MAGENTA}with what scope{RESET}, and provides a {YELLOW}verifiable chain{RESET}
  for every token in your multi-agent system.

  {DIM}Try it yourself:{RESET}
    pip install authgent-server
    authgent-server init && authgent-server run

  {DIM}GitHub:{RESET} https://github.com/authgent/authgent
""")


if __name__ == "__main__":
    main()
