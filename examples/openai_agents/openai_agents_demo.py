#!/usr/bin/env python3
"""OpenAI Agents SDK + authgent — multi-agent delegation demo.

Shows how to integrate authgent with the OpenAI Agents SDK so that:
  - Each agent has its own identity and scoped credentials
  - Tool calls carry delegated tokens with verifiable act chains
  - Scope narrows at each delegation hop
  - Tokens are revoked on shutdown

Prerequisites:
    pip install authgent httpx
    authgent-server running on localhost:8000

Run: python openai_agents_demo.py
"""

import asyncio
import json
import base64

import httpx

from authgent.client import AgentAuthClient, TokenResult

SERVER = "http://localhost:8000"


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
    print("  OpenAI Agents SDK + authgent Demo")
    print("  Multi-agent delegation with verifiable token chains")
    print("=" * 60)

    auth = AgentAuthClient(SERVER)

    # ── Step 1: Register agents ────────────────────────────────
    print("\n\n📋 STEP 1: Register agents with authgent-server")

    orchestrator = await auth.register_agent(
        name="orchestrator",
        scopes=["search", "write", "summarize"],
        owner="demo-team",
        capabilities=["delegation", "orchestration"],
    )
    print(f"   ✓ orchestrator   → {orchestrator.client_id}")

    async with httpx.AsyncClient() as c:
        resp = await c.post(f"{SERVER}/register", json={
            "client_name": "research-agent",
            "grant_types": [
                "client_credentials",
                "urn:ietf:params:oauth:grant-type:token-exchange",
            ],
            "scope": "search summarize",
        })
        research_creds = resp.json()
    print(f"   ✓ research-agent → {research_creds['client_id']}")

    async with httpx.AsyncClient() as c:
        resp = await c.post(f"{SERVER}/register", json={
            "client_name": "writer-agent",
            "grant_types": [
                "client_credentials",
                "urn:ietf:params:oauth:grant-type:token-exchange",
            ],
            "scope": "write",
        })
        writer_creds = resp.json()
    print(f"   ✓ writer-agent   → {writer_creds['client_id']}")

    # ── Step 2: Orchestrator authenticates ─────────────────────
    print("\n\n🔑 STEP 2: Orchestrator authenticates (client_credentials)")

    orch_token = await auth.get_token(
        client_id=orchestrator.client_id,
        client_secret=orchestrator.client_secret,
        scope="search write summarize",
    )

    claims = decode_jwt_payload(orch_token.access_token)
    pp("Orchestrator token claims", {
        "sub": claims.get("sub"),
        "scope": claims.get("scope"),
        "act": claims.get("act", "none — root of the chain"),
    })

    # ── Step 3: Simulate agent tool calls ──────────────────────
    print("\n\n🤖 STEP 3: Simulating OpenAI Agents SDK tool execution")
    print("   (In production, the SDK orchestrates this automatically)")

    print("\n   🔗 Orchestrator delegates to Research Agent (scope: search)")

    research_token = await auth.exchange_token(
        subject_token=orch_token.access_token,
        audience="https://research-agent.internal",
        scopes=["search"],
        client_id=research_creds["client_id"],
        client_secret=research_creds["client_secret"],
    )

    claims = decode_jwt_payload(research_token.access_token)
    pp("Research Agent's delegated token", {
        "sub": claims.get("sub"),
        "scope": claims.get("scope"),
        "act": claims.get("act"),
        "_note": "act.sub proves orchestrator delegated this token",
    })

    print("\n   🔧 Research Agent calls search tool with delegated token")
    print(f"      Authorization: Bearer {research_token.access_token[:40]}...")
    print(f"      Scope: {research_token.scope}")

    # In the real OpenAI Agents SDK, this would be:
    #   @function_tool
    #   async def search_web(ctx: RunContextWrapper[AuthCtx], query: str) -> str:
    #       headers = {"Authorization": f"Bearer {ctx.context.token}"}
    #       return httpx.get(f"https://search-api.com?q={query}", headers=headers).text

    print("\n   🔗 Orchestrator delegates to Writer Agent (scope: write)")

    writer_token = await auth.exchange_token(
        subject_token=orch_token.access_token,
        audience="https://writer-agent.internal",
        scopes=["write"],
        client_id=writer_creds["client_id"],
        client_secret=writer_creds["client_secret"],
    )

    claims = decode_jwt_payload(writer_token.access_token)
    pp("Writer Agent's delegated token", {
        "sub": claims.get("sub"),
        "scope": claims.get("scope"),
        "act": claims.get("act"),
        "_note": "Writer can ONLY write — cannot search or summarize",
    })

    # ── Step 4: Scope enforcement ──────────────────────────────
    print("\n\n🚫 STEP 4: Writer Agent tries to escalate scope — BLOCKED")

    async with httpx.AsyncClient() as c:
        escalation = await c.post(f"{SERVER}/token", data={
            "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
            "subject_token": writer_token.access_token,
            "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
            "client_id": writer_creds["client_id"],
            "client_secret": writer_creds["client_secret"],
            "audience": "https://search-api.internal",
            "scope": "search write",
        })
    pp("Scope escalation attempt", {
        "status": escalation.status_code,
        "result": "BLOCKED" if escalation.status_code >= 400 else "allowed",
        "detail": escalation.json().get("error", escalation.json().get("detail", "")),
    })

    # ── Step 5: Introspect all tokens ──────────────────────────
    print("\n\n🔍 STEP 5: Introspect all tokens")

    async with httpx.AsyncClient() as c:
        i_orch = (await c.post(f"{SERVER}/introspect",
            data={"token": orch_token.access_token})).json()
        i_research = (await c.post(f"{SERVER}/introspect",
            data={"token": research_token.access_token})).json()
        i_writer = (await c.post(f"{SERVER}/introspect",
            data={"token": writer_token.access_token})).json()

    pp("Token landscape", {
        "orchestrator": {"active": i_orch["active"], "scope": i_orch.get("scope"),
                         "act": i_orch.get("act", "none (root)")},
        "research_agent": {"active": i_research["active"], "scope": i_research.get("scope"),
                           "act": i_research.get("act")},
        "writer_agent": {"active": i_writer["active"], "scope": i_writer.get("scope"),
                         "act": i_writer.get("act")},
    })

    # ── Step 6: Revoke on shutdown ─────────────────────────────
    print("\n\n🗑️  STEP 6: Revoke orchestrator token (agent shutdown)")

    await auth.revoke_token(orch_token.access_token, client_id=orchestrator.client_id)
    async with httpx.AsyncClient() as c:
        after = (await c.post(f"{SERVER}/introspect",
            data={"token": orch_token.access_token})).json()
    pp("After revocation", {"active": after["active"]})

    # ── Summary ────────────────────────────────────────────────
    print("\n\n" + "=" * 60)
    print("  ✅ OpenAI Agents SDK + authgent Demo Complete")
    print("=" * 60)
    print("""
  What you just saw:

  ┌──────────────┐    ┌─────────────────┐    ┌──────────────┐
  │ Orchestrator  │───▶│ Research Agent   │    │ Writer Agent │
  │ scope: all    │    │ scope: search   │    │ scope: write │
  │ act: none     │    │ act: orch       │    │ act: orch    │
  └──────────────┘    └─────────────────┘    └──────────────┘
          │                                          ▲
          └──────────────────────────────────────────┘
                    delegation (scope: write)

  In your OpenAI Agents SDK code:

    @function_tool
    async def search(ctx: RunContextWrapper[AuthCtx], query: str) -> str:
        headers = {"Authorization": f"Bearer {ctx.context.token}"}
        resp = httpx.get("https://search-api.com", params={"q": query}, headers=headers)
        return resp.text

    research = Agent(name="research", tools=[search])
    orchestrator = Agent(name="orchestrator", handoffs=[research])

  authgent handles the token lifecycle — acquisition, exchange,
  scope narrowing, delegation chain tracking, and revocation.
""")


if __name__ == "__main__":
    asyncio.run(main())
