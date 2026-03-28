#!/usr/bin/env python3
"""Simulates an MCP client authenticating via authgent and calling tools.

This shows what an MCP client (Claude, Cursor, etc.) does under the hood:
  1. Discover the OAuth server via /.well-known/oauth-authorization-server
  2. Register as a client (Dynamic Client Registration)
  3. Get a token with appropriate scopes
  4. Call tools with the token

Prerequisites:
    authgent-server running on localhost:8000
    mcp_server.py running on localhost:9002  (uvicorn mcp_server:app --port 9002)

Run: python mcp_client_demo.py
"""

import asyncio
import json

import httpx

AUTHGENT = "http://localhost:8000"
MCP_SERVER = "http://localhost:9002"


def pp(label: str, data: dict):
    print(f"\n{'─' * 55}")
    print(f"  {label}")
    print(f"{'─' * 55}")
    print(json.dumps(data, indent=2))


async def main():
    print("\n" + "=" * 55)
    print("  MCP Client → authgent → MCP Server Demo")
    print("=" * 55)

    async with httpx.AsyncClient() as c:

        # ── Step 1: Discover OAuth server ────────────────────────
        print("\n📡 Step 1: MCP client discovers OAuth server")
        print(f"   GET {MCP_SERVER}/.well-known/oauth-protected-resource")

        prm = (await c.get(
            f"{MCP_SERVER}/.well-known/oauth-protected-resource",
        )).json()
        auth_server = prm["authorization_servers"][0]
        pp("Protected Resource Metadata (RFC 9728)", prm)

        meta = (await c.get(
            f"{auth_server}/.well-known/oauth-authorization-server",
        )).json()
        pp("OAuth Server Metadata (RFC 8414)", {
            "issuer": meta["issuer"],
            "token_endpoint": meta["token_endpoint"],
            "registration_endpoint": meta.get("registration_endpoint"),
            "scopes_supported": meta.get("scopes_supported", "any"),
        })

        # ── Step 2: Register as MCP client ───────────────────────
        print("\n📝 Step 2: MCP client registers via Dynamic Client Registration")

        reg = (await c.post(f"{auth_server}/register", json={
            "client_name": "claude-desktop",
            "grant_types": ["client_credentials"],
            "scope": "search:execute summarize:execute",
        })).json()
        pp("Registration result", {
            "client_id": reg["client_id"],
            "client_name": reg.get("client_name"),
        })

        # ── Step 3: Get token ────────────────────────────────────
        print("\n🔑 Step 3: MCP client gets access token")

        token_resp = (await c.post(f"{auth_server}/token", data={
            "grant_type": "client_credentials",
            "client_id": reg["client_id"],
            "client_secret": reg["client_secret"],
            "scope": "search:execute",
        })).json()
        token = token_resp["access_token"]
        pp("Token acquired", {
            "token": token[:50] + "...",
            "scope": token_resp["scope"],
            "expires_in": token_resp["expires_in"],
        })

        # ── Step 4: Call MCP tool with token ─────────────────────
        print("\n🔧 Step 4: Call search tool (with auth token)")

        search_resp = await c.post(
            f"{MCP_SERVER}/tools/search",
            params={"query": "latest AI agent frameworks", "max_results": 3},
            headers={"Authorization": f"Bearer {token}"},
        )
        pp("Search tool response", search_resp.json())

        # ── Step 5: Try calling without token — BLOCKED ──────────
        print("\n🚫 Step 5: Call without token — should fail")

        no_auth_resp = await c.post(
            f"{MCP_SERVER}/tools/search",
            params={"query": "hack the planet"},
        )
        pp("No-auth result", {
            "status": no_auth_resp.status_code,
            "detail": no_auth_resp.json().get("detail", "rejected"),
        })

        # ── Step 6: Try calling tool without required scope ──────
        print("\n🚫 Step 6: Call summarize tool (token only has search:execute scope)")

        summarize_resp = await c.post(
            f"{MCP_SERVER}/tools/summarize",
            params={"text": "This is a test document to summarize."},
            headers={"Authorization": f"Bearer {token}"},
        )
        pp("Wrong-scope result", {
            "status": summarize_resp.status_code,
            "detail": summarize_resp.json().get("detail", ""),
        })

        # ── Done ─────────────────────────────────────────────────
        print("\n" + "=" * 55)
        print("  ✅ MCP Client Demo Complete")
        print("=" * 55)
        print("""
  What happened:
    1. MCP client discovered authgent via .well-known endpoints
    2. Registered itself (Dynamic Client Registration, RFC 7591)
    3. Got a scoped token (client_credentials grant)
    4. Called search tool successfully (had search:execute scope)
    5. Unauthenticated call was rejected (401)
    6. Wrong-scope call was rejected (403)

  In production, MCP clients (Claude, Cursor) do steps 1-3 automatically.
  You just need to point your MCP server at authgent.
""")


if __name__ == "__main__":
    asyncio.run(main())
