<div align="center">

# authgent

### Most MCP servers fail their own OAuth spec. authgent shows you which.

A free MCP-OAuth scanner — and the OAuth 2.1 server you can run if you
want to fix what it finds.

- **`authgent-server lint <mcp-url>`** — 10 RFC-mapped checks, A–F grade,
  embeddable badge. CLI + GitHub Action + hosted at
  [authgent.github.io/authgent/scan/](https://authgent.github.io/authgent/scan/).
- **Public registry** of how Stripe, Notion, Atlassian, Cloudflare, Linear,
  Descope grade today: [authgent.github.io/authgent/registry/](https://authgent.github.io/authgent/registry/).
- **`pip install authgent-server`** — full OAuth 2.1 server, reference
  implementation of [`draft-ietf-oauth-identity-chaining-14`][icn] and
  [`draft-ietf-oauth-transaction-tokens-08`][txntok]. Tested with Claude
  Desktop, Cursor, Claude Code, Continue, VS Code MCP, ChatGPT.

Apache 2.0, 464 tests, 3 published packages.

[icn]: https://datatracker.ietf.org/doc/draft-ietf-oauth-identity-chaining/
[rfc8693]: https://datatracker.ietf.org/doc/html/rfc8693
[rfc9449]: https://datatracker.ietf.org/doc/html/rfc9449

[![CI](https://github.com/authgent/authgent/actions/workflows/ci.yml/badge.svg)](https://github.com/authgent/authgent/actions/workflows/ci.yml)
[![PyPI - Server](https://img.shields.io/pypi/v/authgent-server?label=authgent-server&color=blue)](https://pypi.org/project/authgent-server/)
[![PyPI - SDK](https://img.shields.io/pypi/v/authgent?label=authgent%20SDK&color=blue)](https://pypi.org/project/authgent/)
[![npm](https://img.shields.io/npm/v/authgent?label=authgent%20npm&color=CB3837)](https://www.npmjs.com/package/authgent)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-3776AB.svg)](https://python.org)
[![Node 20+](https://img.shields.io/badge/node-20+-339933.svg)](https://nodejs.org)

<img src="docs/assets/demo.gif" alt="authgent demo — register agents, delegate with scope narrowing, block escalation, revoke chain" width="720">

```bash
pip install authgent-server && authgent-server run
```

[Home](https://authgent.github.io/authgent/home/) · [Scanner](https://authgent.github.io/authgent/scan/) · [Registry](https://authgent.github.io/authgent/registry/) · [Playground](https://authgent.github.io/authgent/) · [MCP Quickstart](docs/mcp-quickstart.md) · [Compatibility Matrix](docs/compatibility-matrix.md) · [vs Auth0](docs/compare/auth0.md) · [vs Keycloak](docs/compare/keycloak.md) · [vs Ory Hydra](docs/compare/ory-hydra.md) · [Standards Report](STANDARDS.md) · [Architecture](ARCHITECTURE.md)

</div>

---

## Who is this for

| Persona | What you get | Where to start |
|---|---|---|
| **MCP-server developer** — *"I need OAuth on my MCP server in 60 seconds, working with Claude Desktop / Cursor / Continue."* | A real `mcp` SDK example with stdio + HTTP transports, and copy-pastable client configs for every major MCP client. | [MCP Quickstart](docs/mcp-quickstart.md) |
| **Enterprise agent platform** — *"I need delegation receipts, DPoP, and an audit chain that proves which agent did what on whose behalf."* | RFC 8693 nested-`act` chains, signed delegation receipts, RFC 9449 DPoP by default, and the cross-domain identity-chaining flow. | [Architecture](ARCHITECTURE.md) |
| **IETF / spec implementer** — *"I'm working on identity-chaining, transaction-tokens, AIMS — I want a free reference impl to test against."* | A clean Apache-2.0 implementation of both WG-track drafts with a section-by-section conformance map. | [Standards Report](STANDARDS.md) |
| **Security engineer auditing MCP servers** — *"I need to lint our MCP servers' OAuth posture in CI."* | An MCP-OAuth scanner (`authgent-server lint <url>`) with a GitHub Action wrapper. | [MCP-Lint Action](.github/actions/mcp-lint/README.md) |

---

## What authgent does

Two products in one repo, both useful, both Apache 2.0:

1. **A scanner.** `authgent-server lint <mcp-url>` (or paste a URL into
   the [hosted scanner](https://authgent.github.io/authgent/scan/)) audits
   any MCP server's OAuth posture against 10 RFC-mapped checks and returns
   an A–F grade with an embeddable badge. The same scanner ships as a
   GitHub Action wrapper and powers the [public registry](https://authgent.github.io/authgent/registry/).

2. **An OAuth 2.1 server.** `pip install authgent-server`. A reference
   implementation of the IETF agent-OAuth stack — multi-hop nested-`act`
   chains, signed delegation receipts, RFC 9449 DPoP by default, RFC 8693
   token exchange with cross-domain identity chaining, transaction tokens.
   Designed to *not* fail the scanner.

You don't have to pick. Most visitors start with the scanner; some
self-host the server. The two products share the same code, the same
RFC interpretations, and the same audit semantics — what the scanner
reports, the server has to live up to.

### Already using Auth0/Okta?

authgent works **alongside** your existing IdP. Keep Auth0 for human SSO, social login, and compliance — bridge into authgent via token exchange for the agent delegation layer:

```bash
# Exchange an Auth0 id_token to start a delegation chain in authgent
curl -X POST http://localhost:8000/token \
  -d "grant_type=urn:ietf:params:oauth:grant-type:token-exchange" \
  -d "subject_token=$AUTH0_ID_TOKEN" \
  -d "subject_token_type=urn:ietf:params:oauth:token-type:id_token"
```

Or use authgent standalone — it handles the full auth lifecycle without any external IdP.

## Specifications implemented

| Spec | What authgent ships |
|---|---|
| OAuth 2.1 (draft) + RFC 6749 | Authorization Code + PKCE (S256), Client Credentials, Refresh, Device Auth |
| [draft-ietf-oauth-identity-chaining-14][icn] | Cross-domain JWT authorization grant (Domain A) and `jwt-bearer` consumer (Domain B), §2.3 + §2.4 + §5 |
| [draft-ietf-oauth-transaction-tokens-08][txntok] | Transaction Token Service — short-lived TT-tokens with `txn`/`tctx`/`rctx` claims, §3 + §7 |
| [RFC 8693][rfc8693] | Token Exchange with nested `act` claims (intra-domain agent delegation) |
| [RFC 7523][rfc7523] | JWT Profile for OAuth 2.0 Client Authentication and Authorization Grants |
| [RFC 9449][rfc9449] | DPoP — sender-constrained access tokens |
| [RFC 9728][rfc9728] | Protected Resource Metadata |
| [RFC 8414][rfc8414] | OAuth 2.0 Authorization Server Metadata |
| [RFC 7591][rfc7591] | Dynamic Client Registration |
| [RFC 7662][rfc7662] | Token Introspection |
| [RFC 7009][rfc7009] | Token Revocation (with ownership check) |
| [RFC 8628][rfc8628] | Device Authorization Grant |
| [RFC 8707][rfc8707] | Resource Indicators |
| [RFC 9457][rfc9457] | Problem Details for HTTP APIs (error responses) |
| MCP 2026-07-28 spec | OAuth discovery, RFC 8414 well-known suffix, RFC 9207 `iss` parameter |

[txntok]: https://datatracker.ietf.org/doc/draft-ietf-oauth-transaction-tokens/

[rfc7523]: https://datatracker.ietf.org/doc/html/rfc7523
[rfc9728]: https://datatracker.ietf.org/doc/html/rfc9728
[rfc8414]: https://datatracker.ietf.org/doc/html/rfc8414
[rfc7591]: https://datatracker.ietf.org/doc/html/rfc7591
[rfc7662]: https://datatracker.ietf.org/doc/html/rfc7662
[rfc7009]: https://datatracker.ietf.org/doc/html/rfc7009
[rfc8628]: https://datatracker.ietf.org/doc/html/rfc8628
[rfc8707]: https://datatracker.ietf.org/doc/html/rfc8707
[rfc9457]: https://datatracker.ietf.org/doc/html/rfc9457

## 60-Second Setup

```bash
pip install authgent-server
authgent-server run
```

That's it. Full OAuth 2.1 server at `localhost:8000`. No account signup, no dashboard, no Java.
First run auto-generates a secret key and `.env` — no separate init step needed.

What you get out of the box:

- **Delegation chain tracking** — when Agent A delegates to Agent B, every hop is recorded in the JWT
- **Scope enforcement per hop** — agents can only give away permissions they have, never escalate
- **MCP auth server** — OAuth discovery, dynamic client registration, scoped tool access
- **Human-in-the-loop** — require human approval for sensitive operations mid-chain
- **DPoP token binding** — tokens are bound to the sender's key, useless if stolen from logs
- **Bridge from Auth0/Okta** — exchange external id_tokens to start a delegation chain

<details>
<summary><b>How delegation chains work inside the JWT</b></summary>

When agents delegate to other agents, the token at each hop answers: *who is acting, on behalf of whom, with what scope, and can we prove it?*

**Hop 1 — Human authorizes Orchestrator:**
```json
{ "sub": "user:alice", "scope": "read write search db:query",
  "cnf": { "jkt": "dpop-key-thumbprint" } }
```

**Hop 2 — Orchestrator delegates to Search Agent (scope narrowed):**
```json
{ "sub": "user:alice", "scope": "search:execute",
  "act": { "sub": "client:orchestrator" },
  "cnf": { "jkt": "search-agent-dpop-key" } }
```

**Hop 3 — Search Agent delegates to DB Agent (scope narrowed again):**
```json
{ "sub": "user:alice", "scope": "db:read",
  "act": { "sub": "client:search-agent",
           "act": { "sub": "client:orchestrator" } },
  "cnf": { "jkt": "db-agent-dpop-key" } }
```

At each hop: scope can only shrink, the `act` chain grows, DPoP rebinds the token to a new key, and a **signed delegation receipt** commits to the chain state so it can't be forged.

**Why chain integrity matters:** RFC 8693 token exchange has a [structural weakness](http://www.mail-archive.com/oauth@ietf.org/msg25680.html) — a compromised intermediary can splice tokens from different chains. authgent mitigates this with per-step signed receipts, the first open-source implementation of this defense.

</details>

## Quick Start

### Option 1: pip — [pypi.org/project/authgent-server](https://pypi.org/project/authgent-server/)

```bash
pip install authgent-server
authgent-server run     # auto-initializes on first run, starts on http://localhost:8000
```

> Defaults to SQLite for dev. For production, set `AUTHGENT_DATABASE_URL=postgresql+asyncpg://...` — see [Configuration](#configuration-authgent-environment-variables).

### Option 2: Docker

```bash
curl -O https://raw.githubusercontent.com/authgent/authgent/main/server/docker-compose.yml
docker compose up -d
```

### Option 3: From source

```bash
git clone https://github.com/authgent/authgent.git
cd authgent/server
pip install -e ".[dev]"
authgent-server run
```

Auto-discovery endpoints:
- `GET /.well-known/oauth-authorization-server` — server metadata (RFC 8414)
- `GET /.well-known/oauth-protected-resource` — resource server metadata (RFC 9728)
- `GET /.well-known/openid-configuration` — OIDC discovery alias
- `GET /.well-known/jwks.json` — public signing keys (RFC 7517)
- `GET /openapi.json` — full OpenAPI spec with `securitySchemes` for automated parsing
- `GET /docs` — interactive API docs (Swagger UI with PKCE support)

### Foreign Agent Auto-Discovery

A foreign agent with **zero prior configuration** can fully bootstrap itself against authgent. Here's the complete flow:

**Step 1 — Hit a protected endpoint, get pointed to the auth server:**
```bash
curl -i https://your-mcp-server.example.com/tools/search
# HTTP/1.1 401 Unauthorized
# WWW-Authenticate: Bearer realm="authgent",
#   authorization_uri="http://localhost:8000/token",
#   resource_metadata="http://localhost:8000/.well-known/oauth-protected-resource",
#   error="invalid_token"
```

**Step 2 — Fetch server metadata to learn capabilities:**
```bash
curl -s http://localhost:8000/.well-known/oauth-authorization-server | jq .
# {
#   "issuer": "http://localhost:8000",
#   "token_endpoint": "http://localhost:8000/token",
#   "registration_endpoint": "http://localhost:8000/register",
#   "grant_types_supported": ["client_credentials", "authorization_code",
#     "urn:ietf:params:oauth:grant-type:token-exchange", ...],
#   "code_challenge_methods_supported": ["S256"],
#   ...
# }
```

**Step 3 — Dynamically register (RFC 7591):**
```bash
curl -s -X POST http://localhost:8000/register \
  -H "Content-Type: application/json" \
  -d '{
    "client_name": "foreign-search-bot",
    "grant_types": ["client_credentials"],
    "scope": "search:execute",
    "client_uri": "https://foreign-agent.example.com",
    "contacts": ["admin@foreign-agent.example.com"]
  }' | jq .
# { "client_id": "agnt_xxx", "client_secret": "sec_xxx", ... }
```

**Step 4 — Request a scoped token and call the protected resource:**
```bash
TOKEN=$(curl -s -X POST http://localhost:8000/token \
  -d "grant_type=client_credentials&client_id=agnt_xxx&client_secret=sec_xxx&scope=search:execute" \
  | jq -r .access_token)

curl -s https://your-mcp-server.example.com/tools/search \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"query": "latest AI papers"}'
```

No SDK required. No hardcoded URLs. The entire flow is discoverable from a single 401 response.

### Register an Agent & Get a Token

```bash
# Option A: CLI (recommended)
authgent-server create-agent --name search-bot --scopes search:execute
authgent-server get-token --client-id agnt_xxx --client-secret sec_xxx --scope search:execute

# Option B: curl
curl -s -X POST http://localhost:8000/agents \
  -H "Content-Type: application/json" \
  -d '{"name": "search-bot", "allowed_scopes": ["search:execute"]}' | jq .

curl -s -X POST http://localhost:8000/token \
  -d "grant_type=client_credentials&client_id=agnt_xxx&client_secret=sec_xxx&scope=search:execute"
```

### Inspect a Token & See the Delegation Chain

```bash
# CLI — shows claims table, expiry, delegation tree
authgent-server inspect-token eyJhbGci...

# API — returns structured JSON with delegation chain
curl -s "http://localhost:8000/tokens/inspect?token=eyJhbGci..." | jq .
```

### Delegate to Another Agent

```bash
# Agent B exchanges Agent A's token for a narrower one
curl -s -X POST http://localhost:8000/token \
  -d "grant_type=urn:ietf:params:oauth:grant-type:token-exchange" \
  -d "subject_token=$AGENT_A_TOKEN" \
  -d "audience=https://agent-b.example.com" \
  -d "scope=search:execute" \
  -d "client_id=$AGENT_B_ID&client_secret=$AGENT_B_SECRET"
```

### Identity Chaining Across Trust Domains

When an agent in your domain needs to call a resource owned by **another
organisation**, nested `act` chains stop at the trust boundary. authgent
implements [draft-ietf-oauth-identity-chaining-14][icn] (Approved-announcement
in IESG), so a Domain A token becomes a short-lived JWT authorization grant
for Domain B's authorization server, and Domain B redeems it for a Domain B
access token via [RFC 7523][rfc7523] `jwt-bearer`.

[rfc7523]: https://datatracker.ietf.org/doc/html/rfc7523

```bash
# Domain A: mint a JWT authorization grant bound to Domain B's AS.
curl -s -X POST https://as.a.example/token \
  -d "grant_type=urn:ietf:params:oauth:grant-type:token-exchange" \
  -d "subject_token=$DOMAIN_A_TOKEN" \
  -d "subject_token_type=urn:ietf:params:oauth:token-type:access_token" \
  -d "requested_token_type=urn:ietf:params:oauth:token-type:jwt" \
  -d "audience=https://as.b.example/token" \
  -d "client_id=$CLIENT_ID&client_secret=$CLIENT_SECRET"
# → { "access_token": "<JWT-grant>",
#     "issued_token_type": "urn:ietf:params:oauth:token-type:jwt", ... }

# Domain B: redeem the grant for a Domain B access token.
curl -s -X POST https://as.b.example/token \
  -d "grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer" \
  -d "assertion=<JWT-grant>" \
  -d "client_id=$DOMAIN_B_CLIENT_ID&client_secret=$DOMAIN_B_SECRET"
```

The grant is **single-use** (assertion `jti` blocked on consumption per §5.5),
**audience-bound** (§2.3.3), **short-lived** (60s default, §5.5), and **never
issues a refresh token** (§5.4). Configure trust boundaries with
`AUTHGENT_TRUSTED_CHAINING_TARGETS` (Domain A allow-list) and
`AUTHGENT_TRUSTED_CHAINING_ISSUERS` (Domain B allow-list).

Both SDKs ship helpers: Python `client.start_identity_chain(...)` /
`client.consume_identity_chain(...)`, TypeScript `client.startIdentityChain()`
/ `client.consumeIdentityChain()`.

### Transaction Tokens (intra-domain call chains)

When a request enters your trust domain (e.g. through an API gateway) and
fans out to internal services, you want every hop to carry **the same
authorization context** without re-querying the authorization server.
authgent implements [draft-ietf-oauth-transaction-tokens-08][txntok] (in WG
Last Call): the gateway exchanges an external access token at the
Transaction Token Service for a short-lived **Txn-Token** carrying a unique
`txn` id, immutable transaction context (`tctx`), and requester context
(`rctx`). Each downstream service validates the JWT signature and trusts
the embedded context.

```bash
# Gateway → TTS: mint a Txn-Token for a stock-buy transaction.
curl -s -X POST http://localhost:8000/token \
  -d "grant_type=urn:ietf:params:oauth:grant-type:token-exchange" \
  -d "subject_token=$EXTERNAL_ACCESS_TOKEN" \
  -d "subject_token_type=urn:ietf:params:oauth:token-type:access_token" \
  -d "requested_token_type=urn:ietf:params:oauth:token-type:txn_token" \
  -d "audience=https://trust-domain.example/" \
  -d "scope=trade.stocks" \
  --data-urlencode 'request_details={"action":"BUY","ticker":"MSFT","quantity":"100"}' \
  -d "client_id=$GATEWAY_ID&client_secret=$GATEWAY_SECRET"
```

The Txn-Token is `typ: txntoken+jwt`, audience-bound to the Trust Domain,
short-lived (120s default per §7), and scope-narrowed (§7.2 enforces
`requested_scope ⊆ subject_token.scope`). Refresh tokens are never issued
(§11). Both SDKs ship `issue_transaction_token` /
`issueTransactionToken` helpers.

### Bridge from Auth0 / Okta / Any OIDC Provider

Already using Auth0? See [Already using Auth0/Okta?](#already-using-auth0okta) — exchange external id_tokens to start a delegation chain.

Configure trusted issuers: `AUTHGENT_TRUSTED_OIDC_ISSUERS='["https://your-tenant.auth0.com/"]'`

## CLI Commands

The `authgent-server` CLI provides rich-formatted output for managing agents, tokens, and the server.

| Command | Description |
|:--------|:------------|
| `authgent-server run` | Start the OAuth 2.1 server (auto-initializes on first run) |
| `authgent-server init` | Explicitly initialize (custom DB URL, force-regenerate config) |
| `authgent-server create-agent` | Register a new agent with scoped capabilities |
| `authgent-server list-agents` | Table of all agents with status, scopes, owner |
| `authgent-server get-token` | Issue a token directly from the CLI |
| `authgent-server inspect-token` | Decode any JWT — claims, expiry, DPoP, delegation chain tree |
| `authgent-server audit` | Color-coded audit log with filtering (`--action`, `--client-id`) |
| `authgent-server status` | Dashboard — DB health, agent count, signing keys, config |
| `authgent-server rotate-keys` | Generate a new ES256 signing key |
| `authgent-server quickstart` | Interactive guided setup — init → create agent → get token |
| `authgent-server --version` | Show version |

```bash
# Example: create an agent and immediately get a token
authgent-server create-agent --name orchestrator --scopes "read write search"
authgent-server get-token --client-id agnt_xxx --client-secret sec_xxx --scope "read search"

# Example: inspect a delegated token — see the full chain
authgent-server inspect-token eyJhbGciOiJFUzI1NiJ9...

# Example: view recent audit events
authgent-server audit --limit 20
```

## How to Actually Use This

### Protect an existing endpoint (3 lines)

```diff
  from fastapi import FastAPI, Depends
+ from authgent.middleware.fastapi import AgentAuthMiddleware, get_agent_identity
+ from authgent.models import AgentIdentity

  app = FastAPI()
+ app.add_middleware(AgentAuthMiddleware, issuer="http://localhost:8000")

  @app.post("/search")
- async def search(query: str):
-     # Who is calling this? No idea.
+ async def search(query: str, identity: AgentIdentity = Depends(get_agent_identity)):
+     print(identity.subject)            # "user:alice"
+     print(identity.scopes)             # ["search:execute"]
+     print(identity.delegation_chain)   # who delegated to whom
      return {"results": [...]}
```

### Add delegation to agent-to-agent calls (3 lines per call)

```python
from authgent import AgentAuthClient

auth = AgentAuthClient("http://localhost:8000")

# Before calling another agent: exchange your token for a scoped one
delegated = await auth.exchange_token(
    subject_token=my_token,                      # your current token
    audience="https://search-agent.example.com",  # who you're calling
    scopes=["search:execute"],                    # only what they need
    client_id=MY_CLIENT_ID,
    client_secret=MY_CLIENT_SECRET,
)

# Call the other agent with the delegated token
resp = httpx.post(
    "https://search-agent.example.com/search",
    json={"query": "latest AI papers"},
    headers={"Authorization": f"Bearer {delegated.access_token}"},
)
```

### Where does authgent-server run?

| Scenario | Where | How |
|:---------|:------|:----|
| **Local dev** | Same machine | `authgent-server run` (SQLite, zero config) |
| **Team / staging** | Shared VM or container | Docker + PostgreSQL |
| **Production** | Dedicated service | `docker compose up` behind a load balancer |
| **With Auth0/Okta** | Same infra | Exchange external id_tokens via token exchange |

One server per environment. All agents point to the same authgent-server — it's the shared identity layer.

### Examples

| Example | What it shows | Run it |
|:--------|:-------------|:-------|
| **[Quickstart](examples/quickstart/)** | 60-second demo — register, delegate, revoke | `python examples/quickstart/demo.py` |
| **[FastAPI Before/After](examples/fastapi_protected/)** | 3-line diff to protect an endpoint | Side-by-side `before.py` vs `after.py` |
| **[3-Agent Pipeline](examples/pipeline/)** | Orchestrator → Search → DB with scope narrowing | `python examples/pipeline/run_pipeline.py` |
| **[MCP Server](examples/mcp_server/)** | MCP server with authgent as OAuth provider | `uvicorn mcp_server:app --port 9002` |
| **[LangChain Tool](examples/langchain_tool/)** | AuthgentToolWrapper for automatic token management | `python examples/langchain_tool/langchain_agent.py` |
| **[OpenAI Agents SDK](examples/openai_agents/)** | Auth pattern for multi-agent orchestration + handoffs | `python examples/openai_agents/openai_agents_demo.py` |
| **[CrewAI](examples/crewai/)** | Per-agent identity + scoped tokens for crew members | `python examples/crewai/crewai_demo.py` |
| **[OpenClaw](examples/openclaw/)** | 5 drop-in skills for secure agent delegation (zero code changes) | `python examples/openclaw/demo_openclaw_authgent.py` |
| **[Interactive Playground](playground/)** | 7-step visual demo with HITL approval | [Try it live](https://authgent.github.io/authgent/) or `docker compose up` → [localhost:3000](http://localhost:3000) |

## SDKs

### Python — [pypi.org/project/authgent](https://pypi.org/project/authgent/)

```bash
pip install authgent
```

```python
from authgent import verify_token

# Verify any agent's token — get identity + delegation chain
identity = await verify_token(token="eyJ...", issuer="http://localhost:8000")
print(identity.subject)           # "user:alice"
print(identity.scopes)            # ["search:execute"]
print(identity.delegation_chain)  # DelegationChain(depth=2, human_root=True)
print(identity.delegation_chain.actors)  # [{"sub": "client:search-agent"}, ...]

# Protect a FastAPI app — one line
from authgent.middleware.fastapi import AgentAuthMiddleware
app.add_middleware(AgentAuthMiddleware, issuer="http://localhost:8000")

# Enforce delegation policy
from authgent.delegation import verify_delegation_chain
verify_delegation_chain(
    identity.delegation_chain,
    max_depth=3,                    # max 3 hops
    require_human_root=True,        # chain must start with a human
    allowed_actors=["client:orchestrator", "client:search-agent"],
)
```

See the full [Python SDK documentation](sdks/python/README.md).

### TypeScript / JavaScript — [npmjs.com/package/authgent](https://www.npmjs.com/package/authgent)

```bash
npm install authgent
```

```typescript
import { verifyToken } from "authgent";

const identity = await verifyToken({
  token: "eyJ...",
  issuer: "http://localhost:8000",
});

// Express middleware
import { agentAuth, requireAgentAuth } from "authgent/middleware/express";
app.use(agentAuth({ issuer: "http://localhost:8000" }));
app.post("/tools/search", requireAgentAuth(["search:execute"]), handler);

// Hono middleware (Cloudflare Workers, Bun, Deno)
import { agentAuth } from "authgent/middleware/hono";
app.use("*", agentAuth({ issuer: "http://localhost:8000" }));
```

See the full [TypeScript SDK documentation](sdks/typescript/README.md).

## Security

### Token Theft Protection (DPoP)

Agents log aggressively — LangChain traces, AutoGen histories, CrewAI logs all contain HTTP headers. Bearer tokens in those logs are replayable by anyone with log access.

authgent supports [DPoP (RFC 9449)](https://tools.ietf.org/html/rfc9449): tokens are cryptographically bound to the sender's ephemeral key. Stolen from a log? Useless without the private key.

```python
from authgent.dpop import DPoPClient

dpop = DPoPClient()  # ephemeral key, never leaves memory
headers = dpop.create_proof_headers(
    access_token=token,
    http_method="POST",
    http_uri="https://api.example.com/tools/search",
)
# {"Authorization": "DPoP eyJ...", "DPoP": "eyJ...proof"}
```

### Defense in Depth

| Layer | What It Prevents |
|:------|:-----------------|
| **DPoP sender binding** | Token replay from logs |
| **Scope reduction enforcement** | Downstream agents escalating privileges |
| **Signed delegation receipts** | Delegation chain forgery ([chain splicing](http://www.mail-archive.com/oauth@ietf.org/msg25680.html)) |
| **Refresh token family tracking** | Token reuse → revokes entire family |
| **Audience restriction (RFC 8707)** | Token used against wrong API |
| **ES256 asymmetric JWTs** | Token forgery |
| **HKDF + AES-256-GCM** | Secret compromise at rest |
| **Structured log redaction** | Credentials leaking to log aggregators |

See [SECURITY.md](SECURITY.md) for the full security architecture and vulnerability reporting.

## Grant Types

| Grant | Use Case |
|:------|:---------|
| **Client Credentials** | Agent authenticates with its own identity |
| **Authorization Code + PKCE** | Human delegates to agent via browser consent |
| **Token Exchange (RFC 8693)** | Agent-to-agent delegation with scope reduction |
| **Refresh Token** | Long-lived sessions with rotation + reuse detection |
| **Device Authorization** | Headless/CLI agent gets human approval via separate device |

## Architecture

```
┌──────────────────────────────────────────────────────┐
│                    authgent-server                     │
│         FastAPI · async SQLAlchemy · ES256             │
│         SQLite (dev) · PostgreSQL (prod)               │
├──────────────────────────────────────────────────────┤
│  Endpoints        Services          Providers          │
│  ─────────        ────────          ─────────          │
│  /token           TokenService      Attestation        │
│  /authorize       DelegationSvc     Policy             │
│  /register        DPoPService       HITL               │
│  /introspect      JWKSService       KeyStore           │
│  /revoke          AuditService      Events             │
│  /device          AgentService      ClaimEnricher      │
│  /stepup          ConsentService    HumanAuth          │
│  /agents          ClientService                        │
│  /audit                                                │
│  /tokens/inspect                                       │
│  /.well-known/*                                        │
├──────────────────────────────────────────────────────┤
│  All providers are Python Protocol interfaces —        │
│  swap in OPA policies, TEE attestation, Slack HITL,    │
│  or anything else without touching core code.          │
└──────────────┬──────────────────────┬────────────────┘
               │                      │
          ┌────┴─────┐          ┌─────┴────┐
          │  Python  │          │   Node   │
          │   SDK    │          │   SDK    │
          └──────────┘          └──────────┘
```

<details>
<summary><b>Project Structure</b></summary>

```
authgent/
├── server/                      # authgent-server (PyPI: authgent-server)
│   ├── authgent_server/
│   │   ├── endpoints/           # FastAPI routers — thin HTTP layer
│   │   ├── services/            # Business logic — stateless, testable
│   │   ├── models/              # SQLAlchemy ORM — 12 models
│   │   ├── providers/           # Pluggable providers — 7 Protocol interfaces
│   │   ├── middleware/          # Error handler, CORS, rate limit, request ID
│   │   ├── schemas/             # Pydantic request/response validation
│   │   ├── templates/           # Jinja2 consent page
│   │   ├── app.py               # App factory + lifespan (cleanup jobs)
│   │   ├── cli.py               # Typer CLI (13 commands — see CLI Commands)
│   │   ├── config.py            # Pydantic Settings (AUTHGENT_* env vars)
│   │   ├── crypto.py            # HKDF + AES-256-GCM
│   │   └── errors.py            # RFC 9457 Problem Details hierarchy
│   ├── tests/                   # 464 tests — unit, integration, security, E2E
│   ├── migrations/              # Alembic (SQLite dev → PostgreSQL prod)
│   └── Dockerfile
├── sdks/
│   ├── python/                  # authgent SDK (PyPI: authgent)
│   │   └── tests/               # 48 tests
│   └── typescript/              # authgent SDK (npm: authgent)
│       └── tests/               # 47 vitest tests
├── examples/                    # Runnable integration examples
│   ├── quickstart/              # 60-second demo script
│   ├── fastapi_protected/       # Before/after endpoint protection
│   ├── pipeline/                # 3-agent delegation chain demo
│   ├── mcp_server/              # MCP server with authgent OAuth
│   ├── langchain_tool/          # LangChain AuthgentToolWrapper demo
│   ├── openai_agents/           # OpenAI Agents SDK auth patterns
│   ├── crewai/                  # CrewAI per-agent identity demo
│   └── openclaw/                # OpenClaw skills — zero code changes
├── playground/                  # Interactive browser-based demo
│   └── index.html               # Delegation chain visualizer
├── ARCHITECTURE.md
├── SECURITY.md
├── CONTRIBUTING.md
└── LICENSE                      # Apache 2.0
```

</details>

<details>
<summary><b>Configuration (AUTHGENT_* environment variables)</b></summary>

| Variable | Default | Description |
|:---------|:--------|:------------|
| `AUTHGENT_SECRET_KEY` | *generated by init* | Master secret for HKDF key derivation |
| `AUTHGENT_DATABASE_URL` | `sqlite+aiosqlite:///./authgent.db` | Database (SQLite dev, PostgreSQL prod) |
| `AUTHGENT_HOST` | `0.0.0.0` | Server bind address |
| `AUTHGENT_PORT` | `8000` | Server bind port |
| `AUTHGENT_ACCESS_TOKEN_TTL` | `900` | Access token lifetime (seconds) |
| `AUTHGENT_REFRESH_TOKEN_TTL` | `86400` | Refresh token lifetime (seconds) |
| `AUTHGENT_MAX_DELEGATION_DEPTH` | `5` | Maximum delegation chain hops |
| `AUTHGENT_REQUIRE_DPOP` | `false` | Require DPoP proofs on all token requests |
| `AUTHGENT_CONSENT_MODE` | `auto_approve` | `auto_approve`, `ui`, `headless` |
| `AUTHGENT_REGISTRATION_POLICY` | `open` | `open`, `token`, `admin` |
| `AUTHGENT_TRUSTED_OIDC_ISSUERS` | `[]` | Trusted external IdP issuer URLs (Auth0/Clerk/Okta) |
| `AUTHGENT_TRUSTED_OIDC_AUDIENCE` | *none* | Expected `aud` in external id_tokens |

See [`server/.env.example`](server/.env.example) for the complete list.

</details>

<details>
<summary><b>Standards Compliance</b></summary>

| Standard | Coverage |
|:---------|:---------|
| [OAuth 2.1](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-11) | Core framework, PKCE required |
| [RFC 7591](https://tools.ietf.org/html/rfc7591) | Dynamic Client Registration |
| [RFC 7636](https://tools.ietf.org/html/rfc7636) | PKCE (S256) |
| [RFC 7662](https://tools.ietf.org/html/rfc7662) | Token Introspection |
| [RFC 8628](https://tools.ietf.org/html/rfc8628) | Device Authorization Grant |
| [RFC 8693](https://tools.ietf.org/html/rfc8693) | Token Exchange (delegation) |
| [RFC 8707](https://tools.ietf.org/html/rfc8707) | Resource Indicators |
| [RFC 9449](https://tools.ietf.org/html/rfc9449) | DPoP Sender-Constrained Tokens |
| [RFC 9457](https://tools.ietf.org/html/rfc9457) | Problem Details for HTTP APIs |
| [RFC 8414](https://tools.ietf.org/html/rfc8414) | OAuth Server Metadata |
| [RFC 9728](https://tools.ietf.org/html/rfc9728) | Protected Resource Metadata |
| [MCP Auth Spec](https://modelcontextprotocol.io/specification/2025-06-18/basic/authorization) | MCP authorization flow |
| [Google A2A](https://google.github.io/A2A/) | Agent-to-Agent protocol alignment |
| [draft-klrc-aiagent-auth-00](https://datatracker.ietf.org/doc/draft-klrc-aiagent-auth/) | IETF AI Agent Auth model (WIMSE + OAuth 2.0 delegation) |
| [OIDC-A 1.0](https://arxiv.org/html/2509.25974v1) | OpenID Connect for Agents — agent attestation alignment |

</details>

## Roadmap

- [x] Core OAuth 2.1 server with all grant types
- [x] Agent identity registry + lifecycle management
- [x] Multi-hop delegation with nested `act` claims + signed receipts
- [x] DPoP sender-constrained tokens with stateless HMAC nonces
- [x] Human-in-the-loop step-up authorization
- [x] Python SDK with FastAPI/Flask middleware + MCP adapter
- [x] TypeScript SDK with Express/Hono middleware + MCP adapter
- [ ] Go SDK
- [ ] Admin dashboard UI
- [ ] OpenTelemetry distributed tracing
- [ ] TEE attestation providers (SGX/TDX/Nitro)

## Contributing

We welcome contributions! See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup, code style, and PR process.

```bash
git clone https://github.com/authgent/authgent.git
cd authgent/server
pip install -e ".[dev]"
pytest -v   # 464 tests
```

## License

[Apache 2.0](LICENSE)
