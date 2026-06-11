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

Apache 2.0, 469 tests, 3 published packages.

[icn]: https://datatracker.ietf.org/doc/draft-ietf-oauth-identity-chaining/
[rfc8693]: https://datatracker.ietf.org/doc/html/rfc8693
[rfc9449]: https://datatracker.ietf.org/doc/html/rfc9449

[![CI](https://github.com/authgent/authgent/actions/workflows/ci.yml/badge.svg)](https://github.com/authgent/authgent/actions/workflows/ci.yml)
[![PyPI - Server](https://img.shields.io/pypi/v/authgent-server?label=authgent-server&color=blue)](https://pypi.org/project/authgent-server/)
[![PyPI - SDK](https://img.shields.io/pypi/v/authgent?label=authgent%20SDK&color=blue)](https://pypi.org/project/authgent/)
[![npm](https://img.shields.io/npm/v/authgent?label=authgent%20npm&color=CB3837)](https://www.npmjs.com/package/authgent)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Cite](https://img.shields.io/badge/cite-CITATION.cff-9cf.svg)](CITATION.cff)
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
| **Enterprise agent platform** — *"I need delegation receipts, DPoP, and an audit chain that proves which agent did what on whose behalf."* | RFC 8693 nested-`act` chains, signed delegation receipts, RFC 9449 DPoP supported (opt-in via `AUTHGENT_REQUIRE_DPOP=true`), and the cross-domain identity-chaining flow. | [Architecture](ARCHITECTURE.md) |
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
   chains, signed delegation receipts, RFC 9449 DPoP supported (opt-in via `AUTHGENT_REQUIRE_DPOP=true`), RFC 8693
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

## Run the server

```bash
pip install authgent-server
authgent-server run     # auto-init, listens on http://localhost:8000
```

Full OAuth 2.1 server. Auto-generates `.env` + signing keys on first run.
SQLite by default; set `AUTHGENT_DATABASE_URL=postgresql+asyncpg://…` for
production. Docker / Helm / Render / Fly templates in
[`server/`](server/) and the [server-infra setup](docs/operations/).

### Audit any MCP server

```bash
authgent-server lint https://your-mcp-server.example.com
authgent-server lint https://your-mcp-server.example.com --format github
```

CLI is the same code path as the [hosted scanner](https://authgent.github.io/authgent/scan/)
and [GitHub Action](.github/actions/mcp-lint/README.md) — three surfaces,
one set of findings.

### Deeper docs (deliberately not inlined here)

- [MCP client quickstart](docs/mcp-quickstart.md) — Claude Desktop /
  Cursor / Continue / VS Code MCP / ChatGPT configs.
- [Identity chaining](docs/identity-chaining.md) — cross-domain JWT
  grants + `jwt-bearer` consumer flow with worked examples.
- [Transaction tokens](docs/transaction-tokens.md) — `txntoken+jwt`
  with `tctx`/`rctx` claims.
- [Scanner methodology](docs/methodology.md) — every check, every RFC
  clause, weighted grade math.
- [Calibration set](docs/calibration.md) — published expected grades
  for 6 known-good and known-bad shapes, asserted by CI.
- [Disclosure policy](docs/disclosure-policy.md) — embargo, opt-out,
  correction process for the registry.

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

## Examples

Working integrations live in [`examples/`](examples/) — FastAPI middleware,
3-agent pipeline with scope narrowing, MCP server with stdio + HTTP
transport, LangChain tool wrapper, OpenAI Agents handoff, CrewAI per-agent
identity, OpenClaw skills.

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
│   ├── tests/                   # 469 tests — unit, integration, security, E2E
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
pytest -v   # 469 tests
```

## License

[Apache 2.0](LICENSE)
