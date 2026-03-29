# Product Requirements Document: authgent
## The Open-Source Identity Provider for AI Agents

**Author:** Dhruv Agnihotri | **Version:** 2.0 | **Date:** March 28, 2026

---

## 1. Executive Summary

**authgent** is the **open-source "Supabase for agent auth"** — a comprehensive platform for AI agent identity, authorization, and secure resource access. It provides:

1. A **lightweight OAuth 2.1 Authorization Server** (FastAPI) that issues and manages tokens for AI agents, compliant with MCP auth spec and Google A2A.
2. An **MCP Gateway** that wraps any existing MCP server with OAuth 2.1 authentication in a single command — zero code changes to the upstream server.
3. A **Credential Vault** that stores sensitive credentials (database URIs, API keys, cloud tokens) and proxies agent requests so agents never see raw secrets.
4. A **Developer Dashboard** (React) for visual management of agents, tokens, delegation chains, vault credentials, and audit trails.
5. **Multi-language SDKs** (Python, TypeScript, Go) for token validation, delegation chain enforcement, and framework middleware.
6. **AI Framework Integrations** — drop-in plugins for LangChain, CrewAI, OpenAI Agents SDK, Google ADK, AutoGen, and Vercel AI SDK.
7. An **Agent Identity Registry** for lifecycle management of agent identities.

**Vision:** Just as Supabase made PostgreSQL accessible by wrapping it with Auth, Realtime, Storage, and a Dashboard, authgent makes agent auth accessible by wrapping a production-grade OAuth 2.1 server with a Gateway, Vault, Dashboard, and framework integrations. The core OAuth server is the "PostgreSQL" — already built and production-ready. The platform layers are what make it 10x easier to use than rolling your own agent security.

**Positioning:** authgent is the **only open-source project that is BOTH OAuth 2.1 / MCP-spec-compliant AND agent-aware, AND provides a zero-code gateway + credential vault.** AIM (OpenA2A) is agent-native but not OAuth 2.1 compliant — it can't serve as an MCP auth server. Keycloak/Ory are OAuth-compliant but not agent-aware. Grantex (the closest direct competitor) provides an agent authorization protocol but is TypeScript-first, has no credential vault, no zero-code gateway wrapping, and no self-hosted dashboard. authgent occupies the intersection that nobody else does — and does it Python-first, where the AI ecosystem lives.

---

## 2. Problem Statement

### 2.1 The Broken Delegation Chain
When Human delegates to Agent A → Agent B → Database API, the identity chain snaps. The database cannot answer: which human authorized this? Was Agent A allowed to delegate to Agent B?

### 2.2 No Open-Source Agent Auth Server (for Python)
MCP mandates OAuth 2.1. A2A uses OAuth via Agent Cards. But Auth0/Stytch = paid SaaS, Keycloak = 500MB Java monolith, MCP SDK = client-side only. Better Auth (TypeScript) is now a full OAuth 2.1 Provider with MCP compatibility — this closes the gap for the TS ecosystem. But for the Python ecosystem (where most AI agents live), there is no turnkey open-source MCP-compliant auth server.

### 2.3 Token Leakage
Agents log extensively. Bearer tokens in logs are trivially replayable. No agent framework implements DPoP.

### 2.4 No Standardized Agent Identity
Agent identities are ad-hoc. No registry, no credential rotation, no lifecycle management.

### 2.5 No Agent Attestation
Identity alone doesn't prove integrity. A compromised agent can claim to be "search-bot" but run malicious code. No open-source agent auth system provides attestation — proof that an agent is the code it claims to be, running in the environment it claims to be in.

### 2.6 No Runtime Step-Up Authorization
Agents encounter sensitive operations mid-execution (delete production data, send money, access PII). There's no standard mechanism for agents to request runtime human approval for specific actions. The HITL (human-in-the-loop) pattern is discussed in IETF drafts (AAuth/Rosenberg) and commercial products (AIM) but has zero open-source implementations.

### 2.7 Zero-Code Credential Protection Gap
Developers want AI agents (Windsurf, Claude Code, Cursor) to query databases and call APIs without exposing credentials. Today this requires building a custom proxy/MCP server that holds the credentials and validates tokens — significant engineering effort for every resource. There is no open-source tool that says: "Give me your database URI, I'll handle the rest." Auth0's Token Vault addresses this for SaaS but is closed-source, cloud-only, and expensive. The gap is a **self-hosted, open-source credential vault with built-in resource proxying**.

### 2.8 No Zero-Code MCP Auth Gateway
The MCP spec mandates OAuth 2.1, but most existing MCP servers ship without authentication. Adding auth requires modifying source code — impractical for third-party or community servers. Developers on Reddit (r/mcp, 34-96 upvote threads) repeatedly ask: "How do I add auth to an MCP server without changing its code?" The `mcp-oauth-gateway` project (TypeScript) attempts this but is minimal. There is no production-grade, Python-native gateway that wraps arbitrary MCP servers with OAuth 2.1 in a single CLI command.

### 2.9 No Unified Agent Management Dashboard
All existing open-source agent auth solutions are CLI/API-only. Developers and team leads need visual management: see which agents are active, what tokens are issued, visualize delegation chains, manage vault credentials, and review audit trails. Supabase's dashboard was the #1 driver of its adoption over raw PostgreSQL. Agent auth needs the same treatment.

### 2.10 No Framework-Native Agent Auth Integrations
Agent developers use LangChain (98k stars), CrewAI (25k), OpenAI Agents SDK (15k), AutoGen (40k). None of these frameworks have built-in auth integration. Developers must manually wire token acquisition, validation, and scope checking. Grantex offers framework adapters; no open-source project matches this. authgent needs drop-in integrations for every major framework.

---

## 3. Target Users

| User | Pain | Solution |
|---|---|---|
| **Devs building remote MCP servers** | MCP spec requires OAuth 2.1 but no server exists | `pip install authgent-server` → 60 seconds |
| **Devs with existing MCP servers** | Need to add auth without modifying server code | `authgent-server gateway --upstream http://localhost:3000` |
| **Devs using AI coding assistants** | Want Windsurf/Claude Code to query DB without exposing credentials | `authgent-server vault add --type postgresql --uri "postgresql://..."` |
| **Teams building multi-agent systems** | Can't trace delegation chains across agent chains | RFC 8693 token exchange with nested `act` claims |
| **LangChain/CrewAI/OpenAI SDK devs** | No built-in auth for agent tools | `from authgent.integrations.langchain import authgent_guard` |
| **Team leads & security engineers** | Can't visualize agent permissions, tokens, and audit trails | authgent Dashboard at `localhost:8000/ui` |
| **Enterprises with existing IdPs** | Auth0/Okta don't enforce agent delegation policies | SDK in "validator mode" adds agent rules on top |
| **A2A agent developers** | Agent Cards require manual security setup | Auto-generated A2A Agent Cards |

---

## 4. Architecture

### 4.1 Platform Layers

authgent is organized as a **layered platform**, inspired by Supabase's architecture. Each layer can be used independently or together:

```
┌──────────────────────────────────────────────────────────────┐
│                    Developer Dashboard (React)                │  ← Layer 5: Visual Management
│  Agents │ Tokens │ Delegation Chains │ Vault │ Audit Logs     │
├──────────────────────────────────────────────────────────────┤
│              AI Framework Integrations                        │  ← Layer 4: Discovery
│  LangChain │ CrewAI │ OpenAI Agents │ ADK │ AutoGen │ Vercel │
├──────────────────────────────────────────────────────────────┤
│                    Credential Vault                           │  ← Layer 3: Secret Management
│  Store DB URIs, API keys, cloud tokens. Proxy agent requests. │
│  Agents get scoped tokens, never see raw credentials.         │
├──────────────────────────────────────────────────────────────┤
│                    MCP Gateway                                │  ← Layer 2: Zero-Code Auth
│  Wraps ANY MCP server with OAuth 2.1. Single CLI command.    │
│  Reverse proxy: validate token → forward to upstream.         │
├──────────────────────────────────────────────────────────────┤
│              OAuth 2.1 Authorization Server (FastAPI)          │  ← Layer 1: Core (BUILT)
│  Token issuance │ Delegation chains │ DPoP │ HITL │ Registry  │
│  SDKs: Python, TypeScript, Go │ Middleware: FastAPI, Express   │
└──────────────────────────────────────────────────────────────┘
```

**Layer 1 (Core Auth)** is fully implemented and tested (155+ tests). Layers 2-5 are the platform expansion.

### 4.2 Three Operating Modes

**Mode 1: Full Platform Mode** — Deploy authgent-server with Gateway + Vault + Dashboard. Everything works together. For indie devs, startups, open-source projects.

**Mode 2: Server-Only Mode** — Deploy just the OAuth 2.1 server. Use SDK middleware on your own MCP servers. No Gateway or Vault needed.

**Mode 3: Validator-Only Mode** — No server. SDK validates tokens from Auth0/Okta/Keycloak and adds agent-specific enforcement. For enterprises.

### 4.3 Component Overview

| Component | Package | Language | Purpose |
|---|---|---|---|
| Server + Gateway + Vault | `authgent-server` | Python (FastAPI) | OAuth 2.1 Auth Server + Gateway + Vault + Dashboard |
| Python SDK | `authgent` | Python | Token validation, middleware, delegation enforcement |
| TypeScript SDK | `authgent` | TypeScript | Token validation, Express/Hono/MCP middleware |
| Go SDK | `authgent-go` | Go | Token validation, HTTP middleware |
| LangChain integration | `authgent-langchain` | Python | Tool guards, agent auth for LangChain |
| CrewAI integration | `authgent-crewai` | Python | Agent permission middleware for CrewAI |
| OpenAI Agents integration | `authgent-openai` | Python | Tool guard decorators for OpenAI Agents SDK |
| Google ADK integration | `authgent-adk` | Python | Auth plugin for Google Agent Development Kit |
| CLI | Built into server | Python | `authgent-server init/run/gateway/vault/create-agent` |
| Dashboard | Built into server | React + TailwindCSS | Served as static files from FastAPI at `/ui` |

### 4.4 Core Auth Flow (Layer 1 — Implemented)

```
Human/Orchestrator
    │ 1. Authenticate (OAuth 2.1)
    ▼
authgent-server (FastAPI)
    │ 2. Issues ES256 JWT with scopes, act claims, cnf (DPoP)
    ▼
Agent A (uses authgent SDK)
    │ 3. Needs to call Agent B → exchanges token via POST /token
    │    (grant_type=token-exchange, RFC 8693)
    │    Gets downstream token with act: { sub: "agent:A" }
    ▼
Agent B (uses authgent SDK middleware)
    │ 4. Validates JWT locally (cached JWKS, no server call)
    │    Verifies chain: Human → Agent A → Agent B
    │    Verifies DPoP proof, checks scopes
    │    Proceeds with tool execution
    ▼
```

### 4.5 MCP Gateway Flow (Layer 2 — New)

```
Claude Desktop / Windsurf / Any MCP Client
    │
    │  MCP request (with Bearer token)
    ▼
authgent-server gateway (reverse proxy)
    │ 1. Extract Bearer token from Authorization header
    │ 2. Validate JWT (signature, exp, iss, aud, scopes)
    │ 3. Verify DPoP proof (if cnf.jkt present)
    │ 4. Check token not revoked (blocklist)
    │ 5. If valid → forward request to upstream MCP server
    │ 6. If invalid → return 401/403
    ▼
Upstream MCP Server (UNMODIFIED — no auth code needed)
    │ Receives request as if no auth exists
    │ Returns response
    ▼
authgent-server gateway
    │ Forwards response to client
    ▼
MCP Client receives response
```

**CLI usage:**
```bash
# Wrap an HTTP MCP server:
authgent-server gateway --upstream http://localhost:3000 --scopes "tools:read,tools:execute"

# Wrap a stdio MCP server:
authgent-server gateway --stdio "npx @modelcontextprotocol/server-postgres postgresql://..." --scopes "db:read"
```

The gateway also serves `/.well-known/oauth-authorization-server` and `/.well-known/oauth-protected-resource` automatically, making it fully MCP-spec-compliant.

### 4.6 Credential Vault Flow (Layer 3 — New)

```
Developer (one-time setup)
    │
    │  authgent-server vault add --name "prod-db" --type postgresql \
    │    --uri "postgresql://admin:s3cret@db.example.com/myapp" \
    │    --read-scopes "db:read" --write-scopes "db:write"
    │
    ▼
authgent-server (stores encrypted credential)
    │
    │  Credential encrypted at rest with AES-256-GCM (KEK from HKDF)
    │  Never exposed in API responses, logs, or tokens
    │
    ▼

Agent (runtime)
    │
    │  1. Agent has token with scope "db:read"
    │  2. POST /vault/prod-db/query  { "sql": "SELECT * FROM users LIMIT 10" }
    │     Authorization: Bearer eyJ...
    │
    ▼
authgent-server vault proxy
    │  3. Validate token + check scope "db:read"
    │  4. Validate SQL (SELECT-only for db:read scope)
    │  5. Decrypt stored credential
    │  6. Execute query using REAL credentials (agent never sees them)
    │  7. Return results to agent
    ▼
Agent receives query results (never saw the password)
```

**Supported resource types (Phase 1):**
- **PostgreSQL** — SQL query proxy with scope-based read/write enforcement
- **HTTP API** — Header injection proxy (add API key/Bearer token to upstream requests)

**Future resource types:**
- MySQL, MongoDB, Redis, S3, GCS, Azure Blob
- OAuth 2.0 token broker (like Auth0 Token Vault — store refresh tokens, auto-rotate)

### 4.7 Dashboard (Layer 5 — New)

```
┌─────────────────────────────────────────────────────────────────┐
│  authgent Dashboard                            localhost:8000/ui │
├─────────────┬───────────────────────────────────────────────────┤
│             │                                                   │
│  ● Agents   │  ┌─ orchestrator-agent ─────────────────────┐    │
│  ● Tokens   │  │  Client ID: agnt_abc123                  │    │
│  ● Chains   │  │  Scopes: db:read, db:write, tools:exec   │    │
│  ● Vault    │  │  Active tokens: 3                        │    │
│  ● Audit    │  │  Last activity: 2 min ago                │    │
│  ● Gateway  │  │  [Revoke All] [Edit Scopes] [Delete]     │    │
│  ● Settings │  └──────────────────────────────────────────┘    │
│             │                                                   │
│             │  Delegation Chain Viewer:                          │
│             │  user:alice → orchestrator → db-reader             │
│             │  scopes: db:read,db:write → db:read               │
│             │  ✓ human_root  ✓ receipts valid  depth: 2/5       │
│             │                                                   │
│             │  Vault Credentials:                                │
│             │  ┌─ prod-db (PostgreSQL) ──── Active ────┐        │
│             │  │  Scopes: db:read, db:write            │        │
│             │  │  Last used: 5 min ago                 │        │
│             │  │  [Rotate] [Disable] [Delete]          │        │
│             │  └───────────────────────────────────────┘        │
│             │                                                   │
└─────────────┴───────────────────────────────────────────────────┘
```

**Technology:** React + TailwindCSS + shadcn/ui, built as static files, served from FastAPI at `/ui`. The dashboard calls the same REST API endpoints that the CLI uses — no special backend. Optionally disabled via `AUTHGENT_DASHBOARD=false` for headless deployments.

---

## 5. Technology Decisions

### 5.1 Why FastAPI (Not Flask)

| Factor | FastAPI | Flask |
|---|---|---|
| OpenAPI spec | Auto-generated (critical for SDK gen) | Requires extensions |
| Async | Native async/await | Workarounds needed |
| Type safety | Pydantic models | Manual validation |
| Modern standard | Standard for new APIs (2024-2026) | Showing age for pure APIs |

### 5.2 Relationship to Flask-Headless-Auth

Our existing `flask-headless-auth` library handles human browser auth (email/password, OAuth social login, MFA, cookies) using Flask-JWT-Extended (HS256). authgent is a fundamentally different system — M2M OAuth 2.1 with ES256/JWKS, DPoP, and delegation chains — requiring FastAPI for native OpenAPI generation and async SQLAlchemy. No code is directly reusable, but design patterns (audit logging, token blacklisting, RBAC decorators, stateless state handling) informed the architecture.

### 5.3 Core Dependencies

```
Server: fastapi, uvicorn, sqlalchemy[asyncio], aiosqlite, asyncpg (optional),
        cryptography, PyJWT, pydantic, pydantic-settings, httpx, typer, alembic

Python SDK: PyJWT, cryptography, httpx, pydantic

TypeScript SDK: jose (no other runtime deps)
```

### 5.4 Crypto Choices

| Function | Algorithm | Rationale |
|---|---|---|
| JWT signing | ES256 (ECDSA P-256) | Faster than RS256, smaller tokens. Used by Apple/Google. |
| DPoP proofs | ES256 | Consistency with token signing |
| Secret hashing | bcrypt (cost 12) | Industry standard |
| Key encryption at rest | AES-256-GCM | Encrypts private keys in DB |
| IDs | ULID | Sortable, URL-safe, 128-bit entropy |

**Post-Quantum Migration Path:** ES256 is secure for the foreseeable future (NIST estimates ECDSA safe through 2030+). However, the server's `AUTHGENT_SIGNING_ALGORITHM` config and the `signing_keys` table are algorithm-agnostic by design. When ML-DSA (FIPS 204) libraries stabilize in Python's `cryptography` package, we can add ML-DSA-44/65/87 as supported algorithms without schema changes. AIM already lists PQC support — we note this as a v2 migration target. The `KeyProvider` interface also allows plugging in PQC-capable HSMs before native library support lands.

### 5.5 Storage

- **Default:** SQLite (zero config, single file)
- **Production:** PostgreSQL via `DATABASE_URL` env var
- **No Redis** in v1. Token revocation via DB blocklist with TTL auto-cleanup. v2: optional Redis adapter for high-volume revocation (>10K revocations/sec).

---

## 6. Server Endpoints

### 6.1 POST /token — OAuth 2.1 Token Endpoint

Three grant types:

**`client_credentials`** — Agent authenticates with client_id/secret, gets access token. **Note:** The latest MCP spec moved `client_credentials` to an extension (`io.modelcontextprotocol/oauth-client-credentials`). Core MCP auth only mandates `authorization_code` + PKCE. The server metadata endpoint advertises extension support, and the server negotiates extensions per the MCP spec. This doesn't change our architecture — we support both.

**`authorization_code` + PKCE** — Human delegates to agent via browser consent. MCP-compliant.

**`urn:ietf:params:oauth:grant-type:token-exchange`** (RFC 8693) — Agent exchanges token for downstream token with nested `act` claims preserving full delegation chain. Supports two `subject_token_type` values:
- `urn:ietf:params:oauth:token-type:access_token` — exchange an authgent-issued token (agent-to-agent delegation)
- `urn:ietf:params:oauth:token-type:id_token` — exchange an external IdP token (Auth0/Clerk/Okta) to start a delegation chain with a human root (`human_root=true`). The server validates the id_token against the IdP's JWKS via `AUTHGENT_TRUSTED_OIDC_ISSUERS` allowlist. See ARCHITECTURE.md §4.7.

**Resource Indicators (RFC 8707) — MANDATORY for MCP compliance:**
All token requests MUST include the `resource` parameter identifying the target MCP server the token is intended for. The MCP auth spec requires this: *"The resource parameter MUST be included in both authorization requests and token requests."* The server validates the `resource` against the client's registered `allowed_resources` (explicit column in `oauth_clients` — distinct from `redirect_uris`, which control where auth code responses go). The issued token's `aud` claim is set to the requested `resource` value. This prevents tokens issued for one MCP server from being used at another.

```
POST /token
  grant_type=client_credentials
  &client_id=agnt_search_01
  &client_secret=sec_...
  &scope=tools:execute
  &resource=https://mcp-server.example.com/   <-- RFC 8707 REQUIRED
```

Token exchange example — decoded downstream token:
```json
{
  "sub": "user:dhruv@example.com",
  "aud": "agent:database-reader",
  "scope": "db:read",
  "agent_type": "autonomous",
  "agent_model": "gpt-4o",
  "agent_version": "1.2.0",
  "agent_provider": "acme-corp",
  "agent_instance_id": "agnt_a1b2c3d4e5f6",
  "act": {
    "sub": "agent:search-bot",
    "act": { "sub": "agent:orchestrator" }
  },
  "delegation_receipt": "eyJ...signed-by-previous-actor..."
}
```

Note: `agent_*` claims align with the emerging **OIDC-A** (OpenID Connect for Agents) specification. These are optional, populated from agent registry metadata when available. `delegation_receipt` is a signed receipt from the previous actor in the chain — see Section 11 (Security) for the chain splicing mitigation.

### 6.2 POST /register — Client Registration

**Dynamic Client Registration (RFC 7591)** — Agents self-register, get client_id + client_secret. Policy: open/token/admin.

**Client ID Metadata Documents (Phase 2)** — The November 2025 MCP spec update made CIMD (`draft-ietf-oauth-client-id-metadata-document-00`) the **default registration path**, downgrading Dynamic Client Registration from SHOULD to MAY. The priority order is now: (1) pre-registration, (2) CIMD, (3) DCR (optional). VS Code, Claude Desktop, and ChatGPT already use CIMD. Implementation: the `oauth_clients` table stores a `metadata_url` column; the server fetches the client's metadata document URL, validates it, and creates/updates the client record. This is a fetch-and-validate pattern — not a massive lift. **Ships in Phase 2 alongside auth_code flow.**

### 6.3 CRUD /agents — Agent Identity Registry
- `POST /agents` — Register agent with name, owner, scopes, capabilities, metadata
- `GET /agents` — List (paginated, filterable by status/owner)
- `GET /agents/{id}` — Get details
- `PATCH /agents/{id}` — Update scopes, rotate credentials (with grace period)
- `DELETE /agents/{id}` — Soft deactivate, revoke all tokens

### 6.4 POST /revoke — Token Revocation (RFC 7009)
Adds JTI to blocklist table. Entries auto-expire after token TTL.

### 6.5 Discovery Endpoints
- `GET /.well-known/oauth-authorization-server` (RFC 8414) — MCP auto-discovery. Includes `resource_indicators_supported: true` per RFC 8707.
- `GET /.well-known/openid-configuration` — **OIDC Discovery alias** (same metadata as RFC 8414 endpoint, superset with OIDC fields). Many MCP clients try this path first. Added Phase 2 for maximum compatibility.
- `GET /.well-known/jwks.json` (RFC 7517) — Public signing keys
- `GET /.well-known/oauth-protected-resource` (RFC 9728) — **Protected Resource Metadata.** MCP servers serve this endpoint to tell clients which authorization server(s) to use and what scopes/resources are supported. When authgent is deployed alongside an MCP server, the SDK generates this metadata document automatically. This is a mandatory MCP spec endpoint.

### 6.6 GET /agents/{id}/agent-card — A2A Agent Card
Auto-generates A2A-compatible Agent Card with security schemes.

### 6.7 GET /authorize — Authorization Code Flow
Minimal consent page. Configurable: `ui` | `headless` | `auto_approve` (dev only). The `resource` parameter (RFC 8707) MUST be included in authorization requests per MCP spec. The consent page displays the target resource to the human for informed consent.

### 6.8 POST /device — Device Authorization Grant (RFC 8628)
For CLI tools and headless agents that cannot open a browser. Agent requests a device code, polls for completion while human authorizes on a separate device. This is the production-grade alternative to `auto_approve` for headless environments. Supported by Ory Hydra and referenced in the AAuth IETF draft.

### 6.9 POST /stepup — Human-in-the-Loop Step-Up Authorization
Runtime step-up authorization for sensitive agent actions. When an agent encounters a high-risk operation (e.g., deleting data, financial transactions, PII access), it calls this endpoint to request human approval. The server notifies the human via a configured `HITLProvider` (webhook, WebSocket, email, Slack). The agent polls or receives a callback when approved/denied. Returns a short-lived, scope-restricted step-up token.

**MCP Scope Challenge alignment:** The MCP spec (Nov 2025) formally defines the Step-Up Authorization Flow: resource server returns `403` with `WWW-Authenticate: Bearer ... scope="needed:scope" error="insufficient_scope"` and the client re-authorizes with the additional scope. Our HITL step-up flow maps directly to this: (1) MCP server returns 403 with required scope, (2) SDK middleware auto-detects the scope challenge and checks if the scope is in `AUTHGENT_HITL_SCOPES`, (3) if yes, calls `POST /stepup` automatically, (4) human approves via `HITLProvider`, (5) server issues step-up token with the additional scope. This makes HITL a natural extension of MCP's existing auth flow, not a custom invention. The SDK middleware handles the entire scope challenge → HITL → retry cycle transparently.

Configurable per-scope: `AUTHGENT_HITL_SCOPES=db:delete,finance:transfer`.

### 6.10 Health
`GET /health`, `GET /ready`

---

## 7. Competitive Analysis

### 7.1 authgent vs AIM (OpenA2A) — Primary OSS Competitor

AIM is the closest open-source competitor and already shipping. Detailed comparison:

| Feature | authgent (planned) | AIM (shipping) |
|---|---|---|
| **OAuth 2.1 compliant** | **Yes** — drop-in MCP auth server | **Partial** — JWT-bearer grant + RFC 8628 device auth, but no auth_code, no PKCE, no dynamic client reg, no resource indicators |
| **MCP-native auth** | **Yes** — `/.well-known/oauth-authorization-server`, RFC 8707 Resource Indicators, RFC 9728 PRM, PKCE, all MCP flows | **No** — cannot serve as MCP auth provider |
| **Delegation chains** | RFC 8693 `act` claims + signed delegation receipts | Ed25519-signed delegation with trust attenuation (custom, non-standard) |
| **DPoP (RFC 9449)** | **Yes** — sender-constrained tokens | **No** |
| **Token exchange** | **Yes** (RFC 8693) | **No** |
| **Dynamic Client Reg** | **Yes** (RFC 7591) | **No** |
| **Crypto** | ES256 (ECDSA P-256) | Ed25519 + ML-DSA (post-quantum claim — verify if real or aspirational) |
| **Capability enforcement** | Scopes + `PolicyProvider` interface | Native capability engine with YAML policies |
| **Trust scoring** | `AttestationProvider` interface (v1: NullProvider) | 8-factor weighted algorithm (shipping) |
| **Attestation** | `AttestationProvider` interface | MCP attestation with multi-agent consensus |
| **Audit** | DB-backed + `EventEmitter` (OTel-ready) | Append-only tamper-evident log |
| **Dashboard** | Not planned (headless v1) | Full web dashboard |
| **SDKs** | Python, TypeScript, Go | Python, TypeScript, Java |
| **Server language** | Python (FastAPI) | TypeScript (Node.js) |
| **License** | Apache 2.0 | Apache 2.0 |

**Where authgent wins over AIM:**
1. **Full standards compliance** — OAuth 2.1, RFC 8693, RFC 9449, RFC 7591, RFC 8628, RFC 8707, RFC 9728. AIM has partial OAuth (JWT-bearer + device auth) but not full OAuth 2.1. Any MCP server needing a compliant OAuth 2.1 provider cannot use AIM.
2. **MCP-native** — authgent is a drop-in MCP auth server. AIM is not.
3. **Python-first** — Most AI agents (LangChain, AutoGen, CrewAI, Google ADK) are Python. AIM's server is TypeScript.
4. **Lightweight** — SQLite default, single Docker command. AIM requires more infrastructure.
5. **Signed delegation receipts** — Cryptographic chain splicing protection. AIM's delegation is custom, not RFC-based.

**Where AIM wins over authgent:**
1. **Already shipping** — AIM has working code; authgent is in PRD phase.
2. **Native capabilities + trust scoring** — More sophisticated authz model than scopes.
3. **Post-quantum claim** — If real, this is forward-looking.
4. **Dashboard** — Visual management vs CLI-only.

**Strategic implication:** authgent's #1 differentiator is **MCP-native OAuth 2.1 compliance**. This is not a minor edge — it means authgent is the only open-source project that can serve as an auth server for the MCP ecosystem, which is the fastest-growing agent protocol.

### 7.2 authgent vs Grantex — Primary Direct Competitor

Grantex is the closest direct competitor — an agent authorization protocol with SDK integrations. Appeared in early 2026.

| Feature | authgent (current + roadmap) | Grantex |
|---|---|---|
| **OAuth 2.1 compliant** | **Yes** — full MCP auth server | **Yes** — authorization protocol |
| **Delegation chains** | RFC 8693 `act` claims + **signed delegation receipts** | Token exchange + delegation |
| **DPoP (RFC 9449)** | **Yes** — sender-constrained tokens + nonces | Unknown |
| **MCP Gateway (zero-code)** | **Yes (Phase 2)** — `authgent-server gateway` wraps any MCP server | **No** — SDK adapters only, requires code changes |
| **Credential Vault** | **Yes (Phase 3)** — self-hosted encrypted vault + resource proxy | **No** |
| **Dashboard** | **Yes (Phase 3)** — self-hosted React UI | Cloud-only playground + dev portal |
| **Framework integrations** | Phase 4: LangChain, CrewAI, OpenAI, ADK, AutoGen | **Yes** — LangChain, CrewAI, OpenAI, ADK, MCP |
| **Self-hosted** | **Yes** — pip install, Docker, single binary | Yes (Docker) |
| **Language** | **Python-first** (where AI devs are) | **TypeScript-first** |
| **IETF draft** | Delegation receipts (candidate individual I-D) | Agent authorization protocol draft |
| **Stars** | Unpublished (0) | ~13 |
| **Signed delegation receipts** | **Yes** — chain splicing mitigation | No |
| **HITL step-up** | **Yes** — MCP scope challenge alignment | Unknown |
| **License** | Apache 2.0 | Apache 2.0 |

**Where authgent wins over Grantex:**
1. **Zero-code gateway** — Grantex requires code changes (SDK adapters). authgent wraps any MCP server in one CLI command.
2. **Credential vault** — Grantex has no secret management. authgent stores credentials and proxies requests.
3. **Python-first** — The AI ecosystem (LangChain, CrewAI, AutoGen, Google ADK) is overwhelmingly Python. Grantex is TypeScript.
4. **Signed delegation receipts** — Cryptographic chain splicing protection that Grantex doesn't have.
5. **Self-hosted dashboard** — Grantex's UI is cloud-only. authgent's dashboard ships with the server.

**Where Grantex wins over authgent:**
1. **Already has framework integrations** — authgent has zero (planned for Phase 4).
2. **IETF draft published** — Establishes protocol authority.
3. **13 GitHub stars** — authgent is unpublished.

**Strategic implication:** The race is still at zero traction for both projects. authgent's Python-first positioning + zero-code gateway + credential vault = fundamentally different value proposition. Grantex is a protocol; authgent is a platform.

### 7.3 Competitive Position Matrix

```
       LIGHTWEIGHT ←──────────────────────────→ HEAVYWEIGHT
             │                                      │
PLATFORM     │                                      │
(auth +      │  ★ authgent ★                       │  Auth0 for AI Agents (SaaS)
gateway +    │  (gateway + vault + dashboard)        │  WorkOS AgentKit (SaaS)
vault +      │                                      │
dashboard)   │                                      │
─────────────┼──────────────────────────────────────┤
             │                                      │
AUTH SERVER  │  Grantex (TS, protocol-focused)      │  Keycloak (Java, not agent-aware)
ONLY         │  Better Auth (TS, full OAuth 2.1)    │  Ory Hydra (Go, no delegation)
             │                                      │
─────────────┼──────────────────────────────────────┤
             │                                      │
AGENT-NATIVE │  AIM/OpenA2A (NOT OAuth 2.1)         │  agentgateway (Rust/K8s)
(custom      │  Agentic-IAM (vaporware)             │
 protocols)  │                                      │
─────────────┼──────────────────────────────────────┤
             │                                      │
VALIDATOR    │  mcp-auth (Python, validator only)   │  Scalekit (SaaS)
ONLY         │                                      │  Stytch Connected Apps (SaaS)
```

authgent's unique position: the ONLY open-source **platform** (not just auth server) that combines OAuth 2.1 compliance, agent-awareness, zero-code gateway, credential vault, and self-hosted dashboard. Every other player is either auth-server-only, SaaS-only, or not agent-aware.

### 7.4 Other Notable Projects

- **mcp-auth** (`pip install mcpauth`, mcp-auth.dev) — Python library for validating tokens from existing providers (Auth0, Keycloak, etc.) on MCP servers. This is a **validator/middleware library**, not an auth server. It does not issue tokens, manage agent identities, or handle delegation chains. A developer Googling "MCP auth Python" will find it. Our differentiator: authgent is a full platform with auth server, gateway, vault, and dashboard — mcp-auth does none of these. The two are complementary: mcp-auth could validate tokens *issued by* authgent.

- **mcp-oauth-gateway** — TypeScript project that adds OAuth to MCP servers via a proxy. Minimal implementation, no credential vault, no delegation, no DPoP. authgent's gateway subsumes this with more features and Python-native implementation.

---

## 8. Pluggable Provider Interfaces

authgent is designed with extension points for capabilities we don't fully implement in v1 but must architecturally support. Each is a Python Protocol (abstract interface) with a default no-op or simple implementation.

### 8.1 AttestationProvider

Proves agent integrity, not just identity. Default: `NullAttestationProvider` (no attestation, identity-only). Pluggable for:
- Code hash verification (agent binary/container digest matches registry)
- TEE attestation (Intel SGX, ARM TrustZone, AWS Nitro)
- Runtime environment claims (container image SHA, cloud region, IP range)

```python
class AttestationProvider(Protocol):
    async def attest(self, agent_id: str, evidence: dict) -> AttestationResult:
        """Validate attestation evidence from an agent."""
        ...
    async def get_attestation_claims(self, agent_id: str) -> dict:
        """Return attestation claims to embed in tokens."""
        ...
```

When an `AttestationProvider` is configured, the server adds attestation claims to issued tokens (e.g., `attestation_level`, `code_hash`, `environment`). Validators can enforce minimum attestation levels.

### 8.2 PolicyProvider

Externalizes authorization decisions beyond scopes. Default: `ScopePolicyProvider` (scope-only checks). Pluggable for OPA, Cedar, Oso, or custom logic.

```python
class PolicyProvider(Protocol):
    async def evaluate(self, request: PolicyRequest) -> PolicyDecision:
        """Evaluate an authorization policy.
        
        PolicyRequest contains: agent_id, scopes, action, resource,
        delegation_chain, attestation_claims, context.
        PolicyDecision: allow/deny/step_up + reason.
        """
        ...
```

The SDK middleware calls `PolicyProvider.evaluate()` after token validation. If the decision is `step_up`, triggers the HITL flow (Section 6.9).

### 8.3 HITLProvider

Delivers human-in-the-loop approval requests. Default: `WebhookHITLProvider` (sends HTTP POST to configured URL). Pluggable for:
- Slack/Teams notifications
- Email approval links
- WebSocket push to dashboard
- Mobile push notifications

**Delivery guarantees:** `WebhookHITLProvider` retries failed deliveries with exponential backoff (3 attempts, 1s/5s/30s). If all retries fail, the step-up request is marked `expired` and the agent receives a clear error. Configurable timeout per request (`AUTHGENT_HITL_TIMEOUT=300` seconds default). For real-time agent workflows where polling is poor UX, the `WebSocketHITLProvider` is recommended — push notification of approval/denial without polling delay.

```python
class HITLProvider(Protocol):
    async def request_approval(
        self, agent_id: str, action: str, resource: str,
        delegation_chain: DelegationChain, context: dict,
    ) -> str:  # returns approval_request_id
        ...
    async def check_approval(self, approval_request_id: str) -> ApprovalStatus:
        """Returns: pending | approved | denied | expired"""
        ...
```

### 8.4 KeyProvider

Externalizes signing key storage. Default: `DatabaseKeyProvider` (keys in DB, encrypted at rest). Pluggable for HSM/KMS:
- AWS KMS
- Azure Key Vault
- Google Cloud KMS
- HashiCorp Vault Transit

### 8.5 EventEmitter

Structured event emission for observability. Default: `DatabaseEventEmitter` (writes to audit_log table). Pluggable for:
- **OpenTelemetry** spans and events (distributed tracing across agent chains)
- CloudEvents over HTTP/Kafka
- Custom SIEM integration

```python
class EventEmitter(Protocol):
    async def emit(self, event: AuditEvent) -> None:
        """Emit a structured event. AuditEvent contains:
        action, actor, subject, timestamp, trace_id, span_id, metadata."""
        ...
```

The server propagates `traceparent` (W3C Trace Context) headers through token exchange flows, so delegation chains are visible as distributed traces in Jaeger/Grafana.

---

*Continued in PRD_PART2.md*
