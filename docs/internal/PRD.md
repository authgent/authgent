# Product Requirements Document: authgent
## The Open-Source Identity Provider for AI Agents

**Author:** Dhruv Agnihotri | **Version:** 1.0 | **Date:** March 25, 2026

---

## 1. Executive Summary

**authgent** is an open-source identity provider (IdP) purpose-built for AI agents. It provides:

1. A **lightweight OAuth 2.1 Authorization Server** (FastAPI) that issues and manages tokens for AI agents, compliant with MCP auth spec and Google A2A.
2. **Multi-language SDKs** (Python, TypeScript, Go) for token validation, delegation chain enforcement, and framework middleware.
3. An **Agent Identity Registry** for lifecycle management of agent identities.

**Positioning:** authgent is the **only open-source project that is BOTH OAuth 2.1 / MCP-spec-compliant AND agent-aware.** AIM (OpenA2A) is agent-native but not OAuth 2.1 compliant — it can't serve as an MCP auth server. Keycloak/Ory are OAuth-compliant but not agent-aware. Better Auth is now a full OAuth 2.1 Provider (TS-only) but has no delegation chains, DPoP, or agent registry. authgent occupies the intersection that nobody else does.

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

---

## 3. Target Users

| User | Pain | Solution |
|---|---|---|
| **Devs building remote MCP servers** | MCP spec requires OAuth 2.1 but no server exists | `pip install authgent-server` → 60 seconds |
| **Teams building multi-agent systems** | Can't trace delegation chains across agent chains | RFC 8693 token exchange with nested `act` claims |
| **Enterprises with existing IdPs** | Auth0/Okta don't enforce agent delegation policies | SDK in "validator mode" adds agent rules on top |
| **A2A agent developers** | Agent Cards require manual security setup | Auto-generated A2A Agent Cards |

---

## 4. Architecture

### 4.1 Two Operating Modes

**Mode 1: Full Server Mode** — Deploy authgent-server. Handles everything: identity, tokens, registration. For indie devs, startups, open-source projects.

**Mode 2: Validator-Only Mode** — No server. SDK validates tokens from Auth0/Okta/Keycloak and adds agent-specific enforcement. For enterprises.

### 4.2 Component Overview

| Component | Package | Language | Purpose |
|---|---|---|---|
| Server | `authgent-server` | Python (FastAPI) | OAuth 2.1 Auth Server + Agent Registry |
| Python SDK | `authgent` | Python | Token validation, middleware, delegation enforcement |
| TypeScript SDK | `authgent` | TypeScript | Token validation, Express/MCP middleware |
| Go SDK | `authgent-go` | Go | Token validation, HTTP middleware |
| CLI | Built into server | Python | `authgent-server init/run/create-agent` |

### 4.3 Flow Diagram

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

### 7.2 Competitive Position Matrix

```
       LIGHTWEIGHT ←──────────────────→ HEAVYWEIGHT
             │                              │
STANDARDS    │                              │
COMPLIANT   │  ★ authgent ★               │  Keycloak (Java, not agent-aware)
(OAuth 2.1)  │                              │  Ory Hydra (Go, no delegation)
             │  Better Auth (TS, full OAuth 2.1) │
             │                              │
─────────────┼──────────────────────────────┤
             │                              │
AGENT-NATIVE │  AIM/OpenA2A (NOT OAuth 2.1) │  agentgateway (Rust/K8s)
(custom      │  Agentic-IAM (vaporware)     │
 protocols)  │                              │
             │                              │
─────────────┼──────────────────────────────┤
             │                              │
COMMERCIAL   │  Scalekit                    │  Auth0 for AI Agents
             │                              │  Stytch Connected Apps
             │                              │  WorkOS AgentKit
```

authgent's unique position: the ONLY lightweight, open-source, standards-compliant (OAuth 2.1), agent-aware auth server.

### 7.3 Other Notable Projects

- **mcp-auth** (`pip install mcpauth`, mcp-auth.dev) — Python library for validating tokens from existing providers (Auth0, Keycloak, etc.) on MCP servers. This is a **validator/middleware library**, not an auth server. It does not issue tokens, manage agent identities, or handle delegation chains. A developer Googling "MCP auth Python" will find it. Our differentiator: authgent is a full OAuth 2.1 server with delegation chains, DPoP, agent registry, and token exchange — mcp-auth does none of these. The two are complementary: mcp-auth could validate tokens *issued by* authgent.

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
