#!/usr/bin/env python3
"""CrewAI + authgent — authenticated multi-agent crew demo.

Shows how to integrate authgent with CrewAI so that:
  - Each crew member has its own identity and scoped credentials
  - Tool calls carry scoped tokens
  - Scope narrows when work flows between agents
  - Tokens are revoked when the crew finishes

Prerequisites:
    pip install authgent httpx crewai
    authgent-server running on localhost:8000

Run: python crewai_demo.py
"""

import asyncio
import json
import base64

import httpx

from authgent.client import AgentAuthClient, TokenResult

SERVER = "http://localhost:8000"

# In-memory token store — maps agent name to its token
_tokens: dict[str, TokenResult] = {}
_creds: dict[str, dict] = {}


def decode_jwt_payload(token: str) -> dict:
    payload = token.split(".")[1]
    padding = 4 - len(payload) % 4
    payload += "=" * padding
    return json.loads(base64.urlsafe_b64decode(payload))


def pp(label: str, data: dict):
    print(f"\n{'━' * 60}")
    print(f"  {label}")
    print(f"{'━' * 60}")
    print(json.dumps(data, indent=2))


async def main():
    print("\n" + "=" * 60)
    print("  CrewAI + authgent Demo")
    print("  Each crew member gets its own identity + scoped token")
    print("=" * 60)

    auth = AgentAuthClient(SERVER)

    # ── Step 1: Register crew members ──────────────────────────
    print("\n\n📋 STEP 1: Register crew members with authgent-server")
    print("   Each agent gets different scopes matching their role")

    crew_roles = {
        "researcher": {
            "scopes": ["search", "read"],
            "description": "Searches the web and reads documents",
        },
        "analyst": {
            "scopes": ["read", "db:query"],
            "description": "Reads data and queries databases",
        },
        "writer": {
            "scopes": ["write"],
            "description": "Writes final reports and documents",
        },
    }

    for name, role in crew_roles.items():
        async with httpx.AsyncClient() as c:
            resp = await c.post(f"{SERVER}/register", json={
                "client_name": f"crew-{name}",
                "grant_types": [
                    "client_credentials",
                    "urn:ietf:params:oauth:grant-type:token-exchange",
                ],
                "scope": " ".join(role["scopes"]),
            })
            creds = resp.json()
        _creds[name] = creds
        print(f"   ✓ {name:<12} → {creds['client_id']}  scopes: {role['scopes']}")

    # ── Step 2: Each agent authenticates ───────────────────────
    print("\n\n🔑 STEP 2: Each crew member authenticates")
    print("   (In CrewAI, this happens when an agent starts a task)")

    for name, role in crew_roles.items():
        creds = _creds[name]
        token = await auth.get_token(
            client_id=creds["client_id"],
            client_secret=creds["client_secret"],
            scope=" ".join(role["scopes"]),
        )
        _tokens[name] = token

        claims = decode_jwt_payload(token.access_token)
        print(f"   ✓ {name:<12} → scope: {claims.get('scope')}")

    # ── Step 3: Simulate crew task execution ───────────────────
    print("\n\n🤖 STEP 3: Simulating CrewAI task execution")

    # --- Researcher searches ---
    print("\n   📎 Task 1: Researcher searches for information")
    r_token = _tokens["researcher"]
    claims = decode_jwt_payload(r_token.access_token)
    pp("Researcher's tool call context", {
        "agent": "researcher",
        "tool": "search_web",
        "token_scope": claims.get("scope"),
        "act": claims.get("act", "none — first-party token"),
        "Authorization": f"Bearer {r_token.access_token[:40]}...",
    })

    # In CrewAI, this would be:
    #   @tool
    #   def search_web(query: str) -> str:
    #       token = _tokens["researcher"]
    #       headers = {"Authorization": f"Bearer {token.access_token}"}
    #       return httpx.get("https://search-api.com", params={"q": query},
    #                        headers=headers).text

    # --- Analyst queries DB ---
    print("\n   📎 Task 2: Analyst queries database")
    a_token = _tokens["analyst"]
    claims = decode_jwt_payload(a_token.access_token)
    pp("Analyst's tool call context", {
        "agent": "analyst",
        "tool": "query_database",
        "token_scope": claims.get("scope"),
        "act": claims.get("act", "none — first-party token"),
        "Authorization": f"Bearer {a_token.access_token[:40]}...",
    })

    # --- Writer writes report ---
    print("\n   📎 Task 3: Writer produces final report")
    w_token = _tokens["writer"]
    claims = decode_jwt_payload(w_token.access_token)
    pp("Writer's tool call context", {
        "agent": "writer",
        "tool": "write_document",
        "token_scope": claims.get("scope"),
        "act": claims.get("act", "none — first-party token"),
        "Authorization": f"Bearer {w_token.access_token[:40]}...",
    })

    # ── Step 4: Scope enforcement ──────────────────────────────
    print("\n\n🚫 STEP 4: Writer tries to search (wrong scope) — BLOCKED")

    async with httpx.AsyncClient() as c:
        escalation = await c.post(f"{SERVER}/token", data={
            "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
            "subject_token": w_token.access_token,
            "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
            "client_id": _creds["writer"]["client_id"],
            "client_secret": _creds["writer"]["client_secret"],
            "audience": "https://search-api.internal",
            "scope": "search write",
        })
    pp("Scope escalation attempt", {
        "agent": "writer",
        "requested": "search write",
        "has": "write",
        "status": escalation.status_code,
        "result": "BLOCKED" if escalation.status_code >= 400 else "allowed",
        "detail": escalation.json().get("error", escalation.json().get("detail", "")),
    })

    # ── Step 5: Delegation between crew members ────────────────
    print("\n\n🔗 STEP 5: Researcher delegates to Analyst (task handoff)")
    print("   Scope narrows: 'search read' → 'read' (analyst only gets read)")

    delegated_token = await auth.exchange_token(
        subject_token=_tokens["researcher"].access_token,
        audience="https://analyst-agent.internal",
        scopes=["read"],
        client_id=_creds["analyst"]["client_id"],
        client_secret=_creds["analyst"]["client_secret"],
    )

    claims = decode_jwt_payload(delegated_token.access_token)
    pp("Delegated token (researcher → analyst)", {
        "sub": claims.get("sub"),
        "scope": claims.get("scope"),
        "act": claims.get("act"),
        "_note": "act.sub proves researcher delegated. Scope narrowed to 'read'.",
    })

    # ── Step 6: Audit — introspect all tokens ──────────────────
    print("\n\n🔍 STEP 6: Audit — who holds what right now")

    audit = {}
    for name in crew_roles:
        async with httpx.AsyncClient() as c:
            intro = (await c.post(f"{SERVER}/introspect",
                data={"token": _tokens[name].access_token})).json()
        audit[name] = {
            "active": intro["active"],
            "scope": intro.get("scope"),
            "act": intro.get("act", "none"),
        }
    pp("Crew token audit", audit)

    # ── Step 7: Crew finishes — revoke all tokens ──────────────
    print("\n\n🗑️  STEP 7: Crew complete — revoking all tokens")

    for name in crew_roles:
        await auth.revoke_token(
            _tokens[name].access_token,
            client_id=_creds[name]["client_id"],
        )
        print(f"   ✓ {name} token revoked")

    # Verify
    async with httpx.AsyncClient() as c:
        check = (await c.post(f"{SERVER}/introspect",
            data={"token": _tokens["researcher"].access_token})).json()
    pp("Post-cleanup check (researcher)", {"active": check["active"]})

    # ── Summary ────────────────────────────────────────────────
    print("\n\n" + "=" * 60)
    print("  ✅ CrewAI + authgent Demo Complete")
    print("=" * 60)
    print("""
  What you just saw:

  ┌────────────┐  ┌────────────┐  ┌────────────┐
  │ Researcher  │  │  Analyst   │  │   Writer   │
  │ search,read │  │  read,db   │  │   write    │
  └──────┬─────┘  └──────┬─────┘  └──────┬─────┘
         │               │               │
         └───────────────┼───────────────┘
                         │
              ┌──────────▼──────────┐
              │  authgent-server     │
              └─────────────────────┘

  Each crew member:
    ✓ Has its own client_id / client_secret
    ✓ Gets a token with scopes matching its role
    ✓ Can delegate to other agents (scope narrows)
    ✓ Cannot escalate beyond its assigned scopes
    ✓ Tokens revoked when crew completes

  In your CrewAI code, use AuthgentToolWrapper per agent:
    wrapper = AuthgentToolWrapper(server_url, client_id, client_secret, scope)
    headers = await wrapper.get_auth_headers()
""")


if __name__ == "__main__":
    asyncio.run(main())
