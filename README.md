<div align="center">

# authgent

### The open-source identity layer for AI agents

OAuth 2.1 authorization server with multi-agent delegation, DPoP sender-constrained tokens, and human-in-the-loop step-up — built for MCP, A2A, and the agentic web.

[![CI](https://github.com/authgent/authgent/actions/workflows/ci.yml/badge.svg)](https://github.com/authgent/authgent/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-3776AB.svg)](https://python.org)
[![Node 20+](https://img.shields.io/badge/node-20+-339933.svg)](https://nodejs.org)

[Quick Start](#quick-start) · [Why authgent?](#why-authgent) · [SDKs](#sdks) · [Architecture](ARCHITECTURE.md) · [Contributing](CONTRIBUTING.md)

</div>

---

## The Problem

Your AI agent calls another agent. That agent calls a third. Each hop needs:
- **Authentication** — who is this agent?
- **Authorization** — what can it do?
- **Delegation** — who authorized it to act?
- **Proof-of-possession** — is this token stolen from a log?
- **Human oversight** — can a human intervene mid-chain?

Auth0, Keycloak, and Ory handle the first token. They have **no concept** of nested `act` claims, scope reduction across hops, DPoP for agents, or step-up authorization mid-workflow.

authgent fills exactly this gap.

## Why authgent?

| Capability | authgent | Auth0 / Keycloak | API Keys |
|:-----------|:--------:|:-----------------:|:--------:|
| OAuth 2.1 + PKCE | ✅ | ✅ | — |
| MCP auth spec compliant | ✅ | — | — |
| Agent identity registry | ✅ | — | — |
| Multi-hop delegation (`act` nesting) | ✅ | — | — |
| Scope reduction enforcement | ✅ | — | — |
| DPoP sender-constrained tokens | ✅ | — | — |
| Human-in-the-loop step-up | ✅ | — | — |
| Device authorization (headless) | ✅ | ✅ | — |
| Zero-config dev start | ✅ | — | ✅ |

## Real-World Use Case

```
Customer → Chat UI → Orchestrator Agent → [Search Agent, DB Agent, Email Agent]
```

1. **Customer authenticates** via Chat UI (auth code + PKCE) → gets scoped token
2. **Orchestrator** exchanges token for Search Agent with reduced scope (`search:execute`) — authgent records delegation via nested `act` claim
3. **Search Agent** validates the 2-hop chain, verifies DPoP proof (token can't be replayed from logs), executes search
4. **Search Agent** hits PII → requests **step-up authorization** → human approves
5. **Orchestrator** delegates to DB Agent with `db:read` → authgent validates the 3-hop chain, enforces scope reduction
6. **Session ends** → token revoked → **all downstream tokens cascade-invalidated**
7. **Six months later** → compliance asks "who accessed PII?" → audit trail has every hop

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

The server starts with auto-discovery at:
- `GET /.well-known/oauth-authorization-server` — server metadata
- `GET /.well-known/jwks.json` — public signing keys
- `GET /docs` — interactive API docs (Swagger)

### Register an Agent & Get a Token

```bash
# Register
curl -s -X POST http://localhost:8000/agents \
  -H "Content-Type: application/json" \
  -d '{"name": "search-bot", "allowed_scopes": ["search:execute"]}' | jq .

# Get token
curl -s -X POST http://localhost:8000/token \
  -d "grant_type=client_credentials&client_id=agnt_xxx&client_secret=sec_xxx&scope=search:execute"
```

### Delegate Between Agents (Token Exchange)

```bash
# Agent B exchanges Agent A's token for a narrower one
curl -s -X POST http://localhost:8000/token \
  -d "grant_type=urn:ietf:params:oauth:grant-type:token-exchange" \
  -d "subject_token=$AGENT_A_TOKEN" \
  -d "audience=https://agent-b.example.com" \
  -d "scope=search:execute" \
  -d "client_id=$AGENT_B_ID&client_secret=$AGENT_B_SECRET"
```

The resulting token contains nested `act` claims tracing the full delegation chain.

## SDKs

### Python

```bash
pip install authgent
```

```python
from authgent import verify_token, AgentAuthClient

# Verify a token from any agent
identity = await verify_token(token="eyJ...", issuer="http://localhost:8000")
print(identity.subject)           # "client:agnt_xxx"
print(identity.scopes)            # ["search:execute"]
print(identity.delegation_chain)  # DelegationChain(depth=2, human_root=True)

# Middleware — one line to protect your FastAPI app
from authgent.middleware.fastapi import AgentAuthMiddleware
app.add_middleware(AgentAuthMiddleware, issuer="http://localhost:8000")
```

See the full [Python SDK documentation](sdks/python/README.md).

### TypeScript / JavaScript

```bash
npm install authgent
```

```typescript
import { verifyToken, AgentAuthClient } from "authgent";

const identity = await verifyToken({
  token: "eyJ...",
  issuer: "http://localhost:8000",
});

// Middleware for Express
import { agentAuth, requireAgentAuth } from "authgent/middleware/express";
app.use(agentAuth({ issuer: "http://localhost:8000" }));
app.post("/tools/search", requireAgentAuth(["search:execute"]), handler);

// Middleware for Hono (Cloudflare Workers, Bun, Deno)
import { agentAuth } from "authgent/middleware/hono";
app.use("*", agentAuth({ issuer: "http://localhost:8000" }));
```

See the full [TypeScript SDK documentation](sdks/typescript/README.md).

## Grant Types

| Grant | Use Case | RFC |
|:------|:---------|:----|
| **Client Credentials** | Agent authenticates with its own identity | OAuth 2.1 |
| **Authorization Code + PKCE** | Human delegates to agent via browser consent | RFC 7636 |
| **Token Exchange** | Agent delegates to another agent with scope reduction | RFC 8693 |
| **Refresh Token** | Long-lived sessions with rotation + reuse detection | OAuth 2.1 |
| **Device Authorization** | Headless agent gets human approval via separate device | RFC 8628 |

## Security

authgent implements 10 layers of defense-in-depth:

| Layer | Mechanism |
|:------|:----------|
| **Signing** | ES256 (ECDSA P-256) asymmetric JWTs with automatic key rotation |
| **Sender binding** | DPoP (RFC 9449) with stateless HMAC nonces — tokens can't be replayed from logs |
| **Audience restriction** | Resource Indicators (RFC 8707) — tokens scoped to specific APIs |
| **Scope enforcement** | Downstream delegation cannot escalate scope — strict reduction only |
| **Delegation control** | `may_act` authorization + configurable depth limits |
| **Chain integrity** | Signed delegation receipts prevent chain splicing |
| **Refresh security** | Single-use rotation with family-based reuse detection |
| **Revocation** | Token blocklist with JTI tracking + cascade to downstream tokens |
| **Secrets** | HKDF key derivation, bcrypt (cost 12) hashing, AES-256-GCM encryption at rest |
| **Logging** | Structured logs with automatic secret redaction — no credentials in output |

See [SECURITY.md](SECURITY.md) for the full security architecture and vulnerability reporting.

## Architecture

```
┌──────────────────────────────────────────────────────┐
│                    authgent-server                     │
│         FastAPI · OAuth 2.1 · ES256 · SQLite / PG     │
├──────────────────────────────────────────────────────┤
│  Endpoints        Services          Models             │
│  ─────────        ────────          ──────             │
│  /token           TokenService      OAuthClient        │
│  /authorize       JWKSService       Agent              │
│  /register        ClientService     SigningKey         │
│  /introspect      DelegationSvc     RefreshToken       │
│  /revoke          DPoPService       AuthCode           │
│  /device          AuditService      TokenBlocklist     │
│  /stepup          ConsentService    AuditLog           │
│  /agents          AgentService      StepUpRequest      │
│  /.well-known/*                     DeviceCode         │
├──────────────────────────────────────────────────────┤
│  Pluggable Providers (Python Protocol interfaces)      │
│  Attestation · Policy · HITL · KeyStore · Events       │
│  ClaimEnricher · HumanAuth                             │
└──────────────┬──────────────────────┬────────────────┘
               │                      │
          ┌────┴─────┐          ┌─────┴────┐
          │  Python  │          │   Node   │
          │   SDK    │          │   SDK    │
          └──────────┘          └──────────┘
```

### Project Structure

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
│   ├── tests/                   # 244 tests — unit, integration, E2E
│   ├── migrations/              # Alembic (SQLite dev → PostgreSQL prod)
│   └── Dockerfile
├── sdks/
│   ├── python/                  # authgent SDK (PyPI: authgent)
│   │   ├── authgent/
│   │   │   ├── verify.py        # JWT verification against JWKS
│   │   │   ├── delegation.py    # Chain validation + policy enforcement
│   │   │   ├── dpop.py          # DPoP proof generation + verification
│   │   │   ├── middleware/      # FastAPI + Flask middleware
│   │   │   └── adapters/        # MCP adapter, RFC 9728 metadata
│   │   └── tests/
│   └── typescript/              # authgent SDK (npm: authgent)
│       ├── src/
│       │   ├── verify.ts        # JWT verification (jose library)
│       │   ├── delegation.ts    # Chain validation
│       │   ├── dpop.ts          # DPoP client + verification
│       │   ├── middleware/      # Express + Hono middleware
│       │   └── adapters/        # MCP adapter, RFC 9728 metadata
│       └── tests/               # 47 vitest tests
├── ARCHITECTURE.md              # Full implementation architecture
├── SECURITY.md                  # Security design + vulnerability reporting
├── CONTRIBUTING.md              # Dev setup, code style, PR process
├── CHANGELOG.md
└── LICENSE                      # Apache 2.0
```

## Configuration

All configuration via `AUTHGENT_*` environment variables:

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

See [`server/.env.example`](server/.env.example) for the complete list including provider configuration.

## Standards Compliance

authgent implements or aligns with:

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

## Roadmap

- [x] Core OAuth 2.1 server with all grant types
- [x] Agent identity registry
- [x] Multi-hop delegation with nested `act` claims
- [x] DPoP sender-constrained tokens
- [x] Human-in-the-loop step-up authorization
- [x] Device authorization grant
- [x] Python SDK (verify, delegate, DPoP, middleware, adapters)
- [x] TypeScript SDK (verify, delegate, DPoP, Express + Hono middleware)
- [ ] Go SDK
- [ ] Admin dashboard UI
- [ ] OpenTelemetry tracing integration
- [ ] Attestation provider: SGX/TDX support
- [ ] Managed cloud offering

## Contributing

We welcome contributions! See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup, code style, and PR process.

```bash
git clone https://github.com/authgent/authgent.git
cd authgent/server
pip install -e ".[dev]"
pytest -v   # 320 tests (244 server + 29 SDK-py + 47 TS)
```

## License

[Apache 2.0](LICENSE) — Use it commercially, modify it, distribute it. No strings attached.
