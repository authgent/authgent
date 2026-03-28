#!/usr/bin/env python3
"""Run the full 3-agent delegation pipeline.

Demonstrates:
  Orchestrator → Search Agent → DB Agent
  with scope narrowing and verifiable act claims at every hop.

Prerequisites:
    1. authgent-server running on localhost:8000
    2. python setup_agents.py  (registers agents, saves .agents.json)

Run: python run_pipeline.py
"""

import asyncio
import json
import sys

import httpx

SERVER = "http://localhost:8000"


def load_agents() -> dict:
    try:
        with open(".agents.json") as f:
            return json.load(f)
    except FileNotFoundError:
        print("Error: .agents.json not found. Run setup_agents.py first.")
        sys.exit(1)


def pp(label: str, data: dict):
    print(f"\n{'━' * 60}")
    print(f"  {label}")
    print(f"{'━' * 60}")
    print(json.dumps(data, indent=2))


def decode_jwt_payload(token: str) -> dict:
    """Decode JWT payload without verification (for display only)."""
    import base64
    payload = token.split(".")[1]
    padding = 4 - len(payload) % 4
    payload += "=" * padding
    return json.loads(base64.urlsafe_b64decode(payload))


async def main():
    agents = load_agents()

    print("\n" + "=" * 60)
    print("  authgent — Multi-Agent Delegation Pipeline Demo")
    print("=" * 60)

    async with httpx.AsyncClient(base_url=SERVER) as c:

        # ── STEP 1: Orchestrator authenticates ───────────────────
        print("\n\n📋 STEP 1: Orchestrator authenticates with its own credentials")
        print("   (This is what happens when your orchestrator agent starts up)")

        orch = agents["orchestrator"]
        resp = await c.post("/token", data={
            "grant_type": "client_credentials",
            "client_id": orch["client_id"],
            "client_secret": orch["client_secret"],
            "scope": "read write search db:read",
        })
        assert resp.status_code == 200, f"Token failed: {resp.text}"
        orch_token = resp.json()["access_token"]

        claims = decode_jwt_payload(orch_token)
        pp("Orchestrator's token (decoded)", {
            "sub": claims.get("sub"),
            "scope": claims.get("scope"),
            "act": claims.get("act", "none — this is the root, nobody delegated yet"),
            "exp": claims.get("exp"),
        })

        # ── STEP 2: Orchestrator → Search Agent ─────────────────
        print("\n\n🔗 STEP 2: Orchestrator delegates to Search Agent")
        print("   Scope narrowed: 'read write search db:read' → 'search db:read'")
        print("   This is what happens when your orchestrator calls a tool agent")

        search = agents["search_agent"]
        resp = await c.post("/token", data={
            "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
            "subject_token": orch_token,
            "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
            "client_id": search["client_id"],
            "client_secret": search["client_secret"],
            "audience": "https://search.internal.example.com",
            "scope": "search db:read",
        })
        assert resp.status_code == 200, f"Exchange failed: {resp.text}"
        search_token = resp.json()["access_token"]

        claims = decode_jwt_payload(search_token)
        pp("Search Agent's delegated token (decoded)", {
            "sub": claims.get("sub"),
            "scope": claims.get("scope"),
            "act": claims.get("act"),
            "_explanation": "act.sub shows WHO delegated — the orchestrator",
        })

        # Introspect to show server-side view
        intro = (await c.post("/introspect", data={"token": search_token})).json()
        pp("Server introspection of search token", {
            "active": intro["active"],
            "sub": intro.get("sub"),
            "scope": intro.get("scope"),
            "act": intro.get("act"),
        })

        # ── STEP 3: Search Agent → DB Agent ──────────────────────
        print("\n\n🔗 STEP 3: Search Agent delegates to DB Agent")
        print("   Scope narrowed again: 'search db:read' → 'db:read'")
        print("   The delegation chain grows: orchestrator → search → db")

        db = agents["db_agent"]
        resp = await c.post("/token", data={
            "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
            "subject_token": search_token,
            "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
            "client_id": db["client_id"],
            "client_secret": db["client_secret"],
            "audience": "https://db.internal.example.com",
            "scope": "db:read",
        })
        assert resp.status_code == 200, f"Exchange failed: {resp.text}"
        db_token = resp.json()["access_token"]

        claims = decode_jwt_payload(db_token)
        pp("DB Agent's delegated token (decoded)", {
            "sub": claims.get("sub"),
            "scope": claims.get("scope"),
            "act": claims.get("act"),
            "_explanation": "Nested act chain: search-agent → orchestrator",
        })

        intro = (await c.post("/introspect", data={"token": db_token})).json()
        pp("Server introspection of DB token", {
            "active": intro["active"],
            "sub": intro.get("sub"),
            "scope": intro.get("scope"),
            "act": intro.get("act"),
        })

        # ── STEP 4: Verify scope escalation is blocked ──────────
        print("\n\n🚫 STEP 4: DB Agent tries to escalate to 'write' — BLOCKED")

        resp = await c.post("/token", data={
            "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
            "subject_token": search_token,
            "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
            "client_id": db["client_id"],
            "client_secret": db["client_secret"],
            "audience": "https://db.internal.example.com",
            "scope": "db:read write",  # 'write' not in search token's scope
        })
        pp("Scope escalation attempt", {
            "status": resp.status_code,
            "result": "BLOCKED" if resp.status_code >= 400 else "allowed",
            "detail": resp.json().get("error", resp.json().get("detail", "")),
        })

        # ── STEP 5: Incident response — revoke orchestrator ─────
        print("\n\n🗑️  STEP 5: Security team revokes the orchestrator's token")
        print("   (Simulates: compromised orchestrator, kill the whole chain)")

        await c.post("/revoke", data={
            "token": orch_token,
            "client_id": orch["client_id"],
        })

        # Orchestrator token is now dead
        intro_orch = (await c.post("/introspect", data={"token": orch_token})).json()

        # Try new exchange with revoked token
        resp = await c.post("/token", data={
            "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
            "subject_token": orch_token,
            "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
            "client_id": search["client_id"],
            "client_secret": search["client_secret"],
            "audience": "https://search.internal.example.com",
            "scope": "search",
        })

        pp("After revocation", {
            "orchestrator_token_active": intro_orch["active"],
            "new_exchange_attempt": resp.status_code,
            "result": "BLOCKED — revoked tokens can't be exchanged",
        })

        # ── Summary ──────────────────────────────────────────────
        print("\n\n" + "=" * 60)
        print("  ✅ Pipeline Demo Complete")
        print("=" * 60)
        print("""
  What you just saw:

  ┌─────────────┐     ┌──────────────┐     ┌───────────┐
  │ Orchestrator │────▶│ Search Agent  │────▶│  DB Agent │
  │ scope: all   │     │ scope: search │     │ scope: db │
  │ act: none    │     │ act: orch     │     │ act: search→orch
  └─────────────┘     └──────────────┘     └───────────┘

  At each hop:
    ✓ Scope can ONLY shrink (never escalate)
    ✓ The 'act' chain grows (tracks who delegated to whom)
    ✓ Original subject is preserved (sub stays the same)
    ✓ Revocation kills the entire chain

  In your real code, you add 3 lines per agent call:
    1. token = await auth.exchange_token(parent_token, audience, scopes)
    2. headers = {"Authorization": f"Bearer {token.access_token}"}
    3. resp = httpx.post(agent_url, headers=headers, json=data)

  And on the receiving side, add middleware:
    app.add_middleware(AgentAuthMiddleware, issuer="http://authgent:8000")
""")


if __name__ == "__main__":
    asyncio.run(main())
