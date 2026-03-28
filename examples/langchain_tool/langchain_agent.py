#!/usr/bin/env python3
"""LangChain agent with authgent-managed authentication.

Shows how to use AuthgentToolWrapper to automatically handle:
  - Token acquisition (client_credentials)
  - Token caching + auto-refresh
  - Token exchange for downstream resources (delegation)
  - Optional DPoP proof generation

Prerequisites:
    pip install authgent langchain-core httpx
    authgent-server running on localhost:8000

Run: python langchain_agent.py
"""

import asyncio
import json
import os

import httpx

from authgent.adapters.langchain import AuthgentToolWrapper
from authgent.client import AgentAuthClient

SERVER = "http://localhost:8000"


async def main():
    print("\n" + "=" * 55)
    print("  LangChain + authgent Integration Demo")
    print("=" * 55)

    # ── Step 1: Register an agent (one-time setup) ───────────
    print("\n📋 Registering agent with authgent-server...")
    client = AgentAuthClient(SERVER)
    agent = await client.register_agent(
        name="langchain-research-bot",
        scopes=["search:execute", "summarize:execute", "db:read"],
        owner="research-team",
        capabilities=["search", "summarize", "database"],
    )
    print(f"   Agent registered: {agent.client_id}")

    # ── Step 2: Create the tool wrapper ──────────────────────
    print("\n🔧 Creating AuthgentToolWrapper...")
    wrapper = AuthgentToolWrapper(
        server_url=SERVER,
        client_id=agent.client_id,
        client_secret=agent.client_secret,
        scope="search:execute summarize:execute db:read",
    )

    # ── Step 3: Get auth headers (auto token management) ─────
    print("\n🔑 Getting auth headers (auto-acquires token)...")
    headers = await wrapper.get_auth_headers()
    print(f"   Authorization: {headers['Authorization'][:60]}...")

    # ── Step 4: Get headers again (uses cached token) ────────
    print("\n🔄 Getting headers again (should use cached token)...")
    headers2 = await wrapper.get_auth_headers()
    same = headers["Authorization"] == headers2["Authorization"]
    print(f"   Same token reused: {same} (cached, not expired)")

    # ── Step 5: Exchange for downstream resource ─────────────
    print("\n🔗 Exchanging token for downstream DB resource...")
    db_token = await wrapper.exchange_for(
        audience="https://db.internal.example.com",
        scopes=["db:read"],
    )
    print(f"   Delegated token: {db_token.access_token[:50]}...")
    print(f"   Scope narrowed to: {db_token.scope}")

    # ── Step 6: Introspect to show delegation ────────────────
    print("\n🔍 Introspecting delegated token...")
    async with httpx.AsyncClient() as c:
        intro = (await c.post(
            f"{SERVER}/introspect",
            data={"token": db_token.access_token},
        )).json()

    print(f"   sub: {intro.get('sub')}")
    print(f"   scope: {intro.get('scope')}")
    print(f"   act: {json.dumps(intro.get('act'), indent=2) if intro.get('act') else 'none'}")

    # ── Step 7: Simulate tool calls with auth ────────────────
    print("\n🛠️  Simulating authenticated tool calls...")
    print()

    # This is what your LangChain tool function would look like:
    async def search_tool(query: str) -> dict:
        """LangChain tool that calls an external search API with auth."""
        headers = await wrapper.get_auth_headers()
        # In production: httpx.get("https://search-api.com", headers=headers)
        return {
            "query": query,
            "auth": "Bearer token attached",
            "headers_sent": list(headers.keys()),
        }

    async def db_tool(query: str) -> dict:
        """LangChain tool that delegates to a DB agent."""
        headers = await wrapper.get_auth_headers(
            resource="https://db.internal.example.com",
        )
        # In production: httpx.post("https://db.internal.com/query", headers=headers)
        return {
            "query": query,
            "auth": "Delegated Bearer token attached (scoped to db:read)",
            "headers_sent": list(headers.keys()),
        }

    result1 = await search_tool("latest AI frameworks 2026")
    print(f"   search_tool: {json.dumps(result1, indent=2)}")

    result2 = await db_tool("SELECT * FROM papers LIMIT 5")
    print(f"   db_tool:     {json.dumps(result2, indent=2)}")

    # ── Step 8: Revoke on shutdown ───────────────────────────
    print("\n🗑️  Revoking token (agent shutdown cleanup)...")
    await wrapper.revoke()
    print("   Token revoked.")

    # ── Summary ──────────────────────────────────────────────
    print("\n" + "=" * 55)
    print("  ✅ LangChain Integration Demo Complete")
    print("=" * 55)
    print("""
  What you just saw:

  1. AuthgentToolWrapper manages the full token lifecycle
  2. get_auth_headers() auto-acquires and caches tokens
  3. exchange_for() delegates to downstream resources
  4. Each delegation narrows scope (can't escalate)
  5. revoke() cleans up on shutdown

  In your LangChain agent, you add ONE wrapper at startup:
    wrapper = AuthgentToolWrapper(server_url, client_id, client_secret, scope)

  Then in each tool:
    headers = await wrapper.get_auth_headers()
    # or for delegation:
    headers = await wrapper.get_auth_headers(resource="https://downstream.com")
""")


if __name__ == "__main__":
    asyncio.run(main())
