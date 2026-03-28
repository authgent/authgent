# authgent Examples

Runnable examples showing exactly how to use authgent in real scenarios.

**All examples require authgent-server running:**
```bash
pip install authgent-server
authgent-server init && authgent-server run  # http://localhost:8000
```

---

## Choose Your Starting Point

### "I just want to see it work" → [`quickstart/`](quickstart/)
```bash
python examples/quickstart/demo.py
```
60-second demo: register agents, get tokens, delegate, see scope enforcement, revoke. No setup beyond the server.

---

### "I have a FastAPI endpoint — what do I add?" → [`fastapi_protected/`](fastapi_protected/)

Side-by-side before/after. The diff is **3 lines** — 2 imports and 1 middleware.

```diff
+ from authgent.middleware.fastapi import AgentAuthMiddleware, get_agent_identity
+ from authgent.models import AgentIdentity

  app = FastAPI()
+ app.add_middleware(AgentAuthMiddleware, issuer="http://localhost:8000")

  @app.post("/search")
- async def search(query: str):
+ async def search(query: str, identity: AgentIdentity = Depends(get_agent_identity)):
      # identity.subject, identity.scopes, identity.delegation_chain
```

---

### "I have a multi-agent pipeline" → [`pipeline/`](pipeline/)
```bash
python examples/pipeline/setup_agents.py   # one-time
python examples/pipeline/run_pipeline.py   # run the demo
```
Full 3-agent delegation chain: Orchestrator → Search Agent → DB Agent. Shows scope narrowing, nested `act` claims, and incident response (revocation).

---

### "I'm building an MCP server" → [`mcp_server/`](mcp_server/)
```bash
uvicorn examples.mcp_server.mcp_server:app --port 9002
python examples/mcp_server/mcp_client_demo.py
```
Complete MCP server with authgent as OAuth provider. Shows discovery (RFC 9728), Dynamic Client Registration, scoped tool access.

---

### "I'm using LangChain" → [`langchain_tool/`](langchain_tool/)
```bash
python examples/langchain_tool/langchain_agent.py
```
Uses `AuthgentToolWrapper` from the SDK to automatically manage tokens — acquisition, caching, refresh, and delegation via token exchange. Drop-in for any LangChain tool.

---

### "I'm using the OpenAI Agents SDK" → [`openai_agents/`](openai_agents/)
```bash
python examples/openai_agents/openai_agents_demo.py
```
Auth pattern for OpenAI Agents: orchestrator delegates to research + writer agents via token exchange. Shows the token lifecycle your `@function_tool` handlers would use — scope enforcement, delegation chains, and revocation.

---

### "I'm using CrewAI" → [`crewai/`](crewai/)
```bash
python examples/crewai/crewai_demo.py
```
Auth pattern for CrewAI: 3 crew members (researcher, analyst, writer) each with role-scoped tokens. Shows per-agent identity, cross-agent delegation with scope narrowing, escalation blocking, and bulk revocation on crew completion.

---

### "I want an interactive visual demo" → [`../playground/`](../playground/)
Open `playground/index.html` in a browser (with authgent-server running). Click through 7 steps of a delegation chain — including human-in-the-loop approval — and see decoded JWTs in real time.

---

## How authgent Fits Into Your Stack

```
┌─────────────────────────────────────────────────────────────────┐
│  YOUR EXISTING SETUP                                             │
│                                                                  │
│  ┌──────────────┐     ┌──────────────┐     ┌──────────────┐    │
│  │  Agent A      │────▶│  Agent B      │────▶│  Agent C      │    │
│  │  (LangChain)  │     │  (FastAPI)    │     │  (FastAPI)    │    │
│  └──────────────┘     └──────────────┘     └──────────────┘    │
│                                                                  │
│  Problem: Agent C has no idea who authorized the request,        │
│  whether scopes were respected, or if the chain is legitimate.   │
└─────────────────────────────────────────────────────────────────┘

                              ↓ Add authgent ↓

┌─────────────────────────────────────────────────────────────────┐
│  WITH authgent                                                   │
│                                                                  │
│  ┌──────────────┐     ┌──────────────┐     ┌──────────────┐    │
│  │  Agent A      │────▶│  Agent B      │────▶│  Agent C      │    │
│  │  + get token  │     │  + exchange   │     │  + verify     │    │
│  │  + exchange   │     │  + middleware │     │  + middleware │    │
│  └──────┬───────┘     └──────┬───────┘     └──────┬───────┘    │
│         │                     │                     │            │
│         └─────────────────────┴─────────────────────┘            │
│                               │                                  │
│                    ┌──────────▼──────────┐                      │
│                    │  authgent-server     │                      │
│                    │  (one shared server) │                      │
│                    └─────────────────────┘                      │
│                                                                  │
│  Agent C now knows: sub=user:alice, scope=db:read,               │
│  delegation_chain=[orchestrator → search-agent], depth=2         │
└─────────────────────────────────────────────────────────────────┘
```

## Where Does authgent-server Run?

| Scenario | Where to run | How |
|:---------|:-------------|:----|
| **Local dev** | Same machine | `authgent-server run` (SQLite, zero config) |
| **Team staging** | Shared VM/container | Docker + PostgreSQL |
| **Production** | Dedicated service | `docker compose up` behind load balancer |
| **Alongside Auth0/Okta** | Same infra | Exchange external id_tokens via token exchange |

**One server per environment.** All agents in that environment point to the same authgent-server. It's like a shared database — one instance, many clients.
