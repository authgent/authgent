<div align="center">

# authgent

### The open-source auth server built for AI agents

Auth0 and Keycloak issue the first token. But when Agent A delegates to Agent B delegates to Agent C — **who authorized what?** authgent is a complete OAuth 2.1 server that gives every agent its own identity, tracks delegation chains across hops, and enforces scope reduction at every step.

[![CI](https://github.com/authgent/authgent/actions/workflows/ci.yml/badge.svg)](https://github.com/authgent/authgent/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-3776AB.svg)](https://python.org)
[![Node 20+](https://img.shields.io/badge/node-20+-339933.svg)](https://nodejs.org)

[Quick Start](#quick-start) · [Why authgent?](#why-authgent) · [SDKs](#sdks) · [Architecture](ARCHITECTURE.md) · [Contributing](CONTRIBUTING.md)

</div>

---

## 30-Second Version

```bash
pip install authgent-server
authgent-server init && authgent-server run
```

You now have a full OAuth 2.1 authorization server at `localhost:8000` that:
- **Issues and manages tokens** — client credentials, authorization code + PKCE, refresh tokens, device flow
- **Gives each agent its own identity** — per-agent credentials, scoped capabilities, lifecycle management
- **Tracks multi-hop delegation** — when agents delegate to other agents, every hop is recorded in the token
- **Enforces scope reduction** — agents can only give away permissions they have, never escalate
- **Prevents token replay** — DPoP binds tokens to the sender's key, even if stolen from logs
- **Human-in-the-loop** — require human approval for sensitive operations mid-chain
- **Works as your MCP auth server** out of the box

## Why authgent?

Auth0, Keycloak, and Ory are great auth servers — for humans and apps. But multi-agent systems have a problem they don't solve:

```
Human → Agent A → Agent B → Agent C → Database
                                          ↑
              Who authorized THIS access?
              Was scope reduced at each hop?
              Can we prove the chain wasn't forged?
              Is this token stolen from a log?
```

**Auth0 issues the first token. It doesn't know about the rest of the chain.** Keycloak doesn't either. Neither does Ory. authgent does — because it was built for this.

### Feature Comparison

| | Auth0 / Okta | Keycloak / Ory | Arcade.dev | Agent Auth Protocol | **authgent** |
|:--|:--:|:--:|:--:|:--:|:--:|
| Full OAuth 2.1 server | ✅ | ✅ | — (runtime) | — (protocol) | **✅** |
| Token issuance + refresh + revocation | ✅ | ✅ | — | — | **✅** |
| Dynamic client registration (RFC 7591) | ✅ | ✅ | — | ✅ | **✅** |
| Per-agent identity + lifecycle | ⚠️ add-on | ❌ | ✅ | ✅ | **✅** |
| Multi-hop delegation chains (`act`) | ❌ | ❌ | ❌ | ❌ | **✅** |
| Scope enforcement per hop | ❌ | ❌ | ❌ | ❌ | **✅** |
| Verifiable delegation receipts | ❌ | ❌ | ❌ | ❌ | **✅** |
| DPoP sender-constrained tokens | ❌ | ❌ | ❌ | ❌ | **✅** |
| Human-in-the-loop mid-chain | ⚠️ add-on | ❌ | ❌ | ❌ | **✅** |
| Token introspection (RFC 7662) | ✅ | ✅ | — | — | **✅** |
| MCP auth spec compliant | ⚠️ add-on | ❌ | ✅ | ✅ | **✅** |
| Bridge from existing IdP (token exchange) | — | — | ✅ | — | **✅** |
| Self-hosted, open source | ❌ | ✅ | ❌ | ✅ | **✅** |
| Python-native (FastAPI) | ❌ | ❌ (Java) | ❌ | ❌ (TS) | **✅** |

**The bottom half of this table is why you'd choose authgent. The top half is why you can.**

authgent is a complete auth server — use it standalone, or bridge from your existing Auth0/Okta/Keycloak via token exchange to start a delegation chain.

## The Delegation Chain Problem

When agents delegate to other agents, the token at each hop should answer: *who is acting, on behalf of whom, with what scope, and can we prove it?*

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

## Quick Start

### Option 1: pip

```bash
pip install authgent-server
authgent-server init    # generates secret, creates DB, signing key
authgent-server run     # starts on http://localhost:8000
```

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
authgent-server init && authgent-server run
```

Auto-discovery endpoints:
- `GET /.well-known/oauth-authorization-server` — server metadata
- `GET /.well-known/oauth-protected-resource` — resource server metadata (RFC 9728)
- `GET /.well-known/jwks.json` — public signing keys
- `GET /docs` — interactive API docs (Swagger)

### Register an Agent & Get a Token

```bash
# Register
curl -s -X POST http://localhost:8000/agents \
  -H "Content-Type: application/json" \
  -d '{"name": "search-bot", "allowed_scopes": ["search:execute"]}' | jq .

# Get token (client_credentials)
curl -s -X POST http://localhost:8000/token \
  -d "grant_type=client_credentials&client_id=agnt_xxx&client_secret=sec_xxx&scope=search:execute"
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

### Bridge from Auth0 / Okta / Any OIDC Provider

```bash
# Exchange an external id_token to start a delegation chain
curl -s -X POST http://localhost:8000/token \
  -d "grant_type=urn:ietf:params:oauth:grant-type:token-exchange" \
  -d "subject_token=$AUTH0_ID_TOKEN" \
  -d "subject_token_type=urn:ietf:params:oauth:token-type:id_token" \
  -d "client_id=$AGENT_ID&client_secret=$AGENT_SECRET"
```

Configure trusted issuers: `AUTHGENT_TRUSTED_OIDC_ISSUERS='["https://your-tenant.auth0.com/"]'`

## See It In Action

3 agents, scope narrowing, escalation attack blocked, human-in-the-loop, revocation — all live against a real server:

<p align="center">
  <img src="docs/assets/demo.gif" alt="authgent terminal demo — multi-hop agent delegation with scope narrowing" width="720">
</p>

> **Run it yourself:** `pip install rich httpx && python demo_showcase.py` (requires a running server)

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
| **[Interactive Playground](playground/)** | Visual delegation chain builder in the browser | Open `playground/index.html` |

## SDKs

### Python

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

### TypeScript / JavaScript

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
│   │   ├── cli.py               # Typer CLI (init, run, migrate, create-agent)
│   │   ├── config.py            # Pydantic Settings (AUTHGENT_* env vars)
│   │   ├── crypto.py            # HKDF + AES-256-GCM
│   │   └── errors.py            # RFC 9457 Problem Details hierarchy
│   ├── tests/                   # 320 tests — unit, integration, security, E2E
│   ├── migrations/              # Alembic (SQLite dev → PostgreSQL prod)
│   └── Dockerfile
├── sdks/
│   ├── python/                  # authgent SDK (PyPI: authgent)
│   │   └── tests/               # 29 tests
│   └── typescript/              # authgent SDK (npm: authgent)
│       └── tests/               # 47 vitest tests
├── examples/                    # Runnable integration examples
│   ├── quickstart/              # 60-second demo script
│   ├── fastapi_protected/       # Before/after endpoint protection
│   ├── pipeline/                # 3-agent delegation chain demo
│   ├── mcp_server/              # MCP server with authgent OAuth
│   └── langchain_tool/          # LangChain AuthgentToolWrapper demo
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
pytest -v   # 320 tests
```

## License

[Apache 2.0](LICENSE)
