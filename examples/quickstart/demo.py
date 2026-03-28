#!/usr/bin/env python3
"""authgent quickstart — see it work in 60 seconds.

Prerequisites:
    pip install authgent-server httpx
    authgent-server init && authgent-server run   # in another terminal

Run:
    python demo.py
"""

import asyncio
import json

import httpx

SERVER = "http://localhost:8000"


def pp(label: str, data: dict):
    print(f"\n{'─' * 50}")
    print(f"  {label}")
    print(f"{'─' * 50}")
    print(json.dumps(data, indent=2))


async def main():
    async with httpx.AsyncClient(base_url=SERVER) as c:

        # ── Step 1: Register two agents ──────────────────────────
        print("\n🔧 Registering agents...")

        orch = (await c.post("/agents", json={
            "name": "orchestrator",
            "allowed_scopes": ["read", "write", "search"],
        })).json()
        pp("Orchestrator registered", {
            "id": orch["id"],
            "client_id": orch["client_id"],
            "status": orch["status"],
        })

        search = (await c.post("/agents", json={
            "name": "search-agent",
            "allowed_scopes": ["search"],
        })).json()
        pp("Search Agent registered", {
            "id": search["id"],
            "client_id": search["client_id"],
            "status": search["status"],
        })

        # ── Step 2: Orchestrator gets its own token ──────────────
        print("\n🔑 Orchestrator authenticates...")

        token_resp = (await c.post("/token", data={
            "grant_type": "client_credentials",
            "client_id": orch["client_id"],
            "client_secret": orch["client_secret"],
            "scope": "read write search",
        })).json()
        orch_token = token_resp["access_token"]
        pp("Orchestrator token", {
            "token": orch_token[:50] + "...",
            "expires_in": token_resp["expires_in"],
            "scope": token_resp["scope"],
        })

        # ── Step 3: Introspect — no delegation yet ──────────────
        intro1 = (await c.post("/introspect", data={"token": orch_token})).json()
        pp("Introspect orchestrator token (no delegation yet)", {
            "sub": intro1.get("sub"),
            "scope": intro1.get("scope"),
            "act": intro1.get("act", "none — this is the root token"),
        })

        # ── Step 4: Delegate to search agent (scope narrowed) ───
        print("\n🔗 Orchestrator delegates to Search Agent (scope: search only)...")

        # Register search agent as an OAuth client that can do token exchange
        search_client = (await c.post("/register", json={
            "client_name": f"search-exchanger",
            "grant_types": [
                "client_credentials",
                "urn:ietf:params:oauth:grant-type:token-exchange",
            ],
            "scope": "search",
        })).json()

        exchange_resp = (await c.post("/token", data={
            "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
            "subject_token": orch_token,
            "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
            "client_id": search_client["client_id"],
            "client_secret": search_client["client_secret"],
            "audience": "https://search.example.com",
            "scope": "search",
        })).json()
        search_token = exchange_resp["access_token"]

        # ── Step 5: Introspect delegated token — see the act claim ─
        intro2 = (await c.post("/introspect", data={"token": search_token})).json()
        pp("Delegated token (search agent acting on behalf of orchestrator)", {
            "sub": intro2.get("sub"),
            "scope": intro2.get("scope"),
            "act": intro2.get("act"),
        })

        print("\n✅ The 'act' claim shows WHO delegated to whom.")
        print("   sub = original identity, act.sub = who is acting")

        # ── Step 6: Try to escalate scope — BLOCKED ─────────────
        print("\n🚫 Search agent tries to escalate to 'write' scope...")

        escalate = await c.post("/token", data={
            "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
            "subject_token": orch_token,
            "client_id": search_client["client_id"],
            "client_secret": search_client["client_secret"],
            "audience": "https://search.example.com",
            "scope": "search write",  # 'write' was NOT in search agent's allowed scopes
        })
        pp("Scope escalation result", {
            "status": escalate.status_code,
            "error": escalate.json().get("error", escalate.json().get("detail", "blocked")),
        })

        # ── Step 7: Revoke the orchestrator token ────────────────
        print("\n🗑️  Revoking orchestrator token (incident response)...")

        await c.post("/revoke", data={
            "token": orch_token,
            "client_id": orch["client_id"],
        })
        intro3 = (await c.post("/introspect", data={"token": orch_token})).json()
        pp("After revocation", {"active": intro3["active"]})

        # ── Done ─────────────────────────────────────────────────
        print("\n" + "=" * 50)
        print("  ✅ Demo complete!")
        print("=" * 50)
        print("""
What you just saw:
  1. Two agents registered with different scopes
  2. Orchestrator got a token (client_credentials)
  3. Token exchanged to search agent with NARROWER scope
  4. Delegated token has 'act' claim tracking who delegated
  5. Scope escalation BLOCKED — agents can't give themselves more power
  6. Token revoked — immediate invalidation for incident response

Next: Try the full pipeline example in examples/pipeline/
""")


if __name__ == "__main__":
    asyncio.run(main())
