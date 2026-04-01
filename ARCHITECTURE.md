# authgent — Architecture Document

**Author:** Dhruv Agnihotri | **Version:** 2.1 | **Date:** March 28, 2026
**Focus:** Core OAuth 2.1 Authorization Server with agent delegation chains, DPoP, and HITL.
**Platform roadmap:** See [ROADMAP.md](ROADMAP.md) for future platform layers (Gateway, Vault, Dashboard, Integrations).

---

## 1. Design Principles

| Principle | Implication |
|---|---|
| **Standards-first** | Every grant, endpoint, and token format maps to an RFC. No custom protocols where a standard exists. |
| **Layered services** | Endpoints → Services → Models → DB. No endpoint touches SQLAlchemy directly. |
| **Pluggable providers** | Five extension points (Attestation, Policy, HITL, Key, Event) — all Python Protocols with defaults. |
| **Zero-config start** | `pip install authgent-server && authgent-server run` works with SQLite, auto-generated keys, no env vars. Auto-initializes on first run. |
| **Async everywhere** | All I/O is async (SQLAlchemy async, httpx async, FastAPI async endpoints). Sync wrappers only in Flask SDK middleware. |
| **12-factor config** | All config via `AUTHGENT_*` env vars. Pydantic Settings validates on startup. |
| **Defense in depth** | DPoP + short TTL + scope reduction + delegation receipts + blocklist. No single mechanism is trusted alone. |
| **Niche ownership** | authgent owns agent-to-agent delegation with cryptographic proof. Platform layers (Gateway, Vault, Dashboard) are future expansions — see [ROADMAP.md](ROADMAP.md). |

---

## 2. System Context

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                              EXTERNAL WORLD                                   │
│                                                                               │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────────┐                │
│  │  Human    │  │ MCP      │  │ Agent A  │  │ Enterprise   │                │
│  │ (Browser) │  │ Client   │  │          │  │ IdP (Auth0/  │                │
│  │           │  │ (Claude) │  │          │  │ Okta/AAD)    │                │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘  └──────┬───────┘                │
│       │              │             │                │                         │
└───────┼──────────────┼─────────────┼────────────────┼─────────────────────────┘
        │              │             │                │
        ▼              ▼             ▼                ▼
┌──────────────────────────────────────────────────────────────────────────────┐
│                   authgent — OAuth 2.1 Authorization Server (FastAPI)         │
│                                                                               │
│  ┌─────────────────────────────────────────────────────────────────────┐     │
│  │                  Endpoint Layer (Routers)                            │     │
│  │  /token  /authorize  /register  /revoke  /agents  /stepup           │     │
│  │  /device  /introspect  /audit  /tokens/inspect                      │     │
│  │  /.well-known/*  /health  /ready                                    │     │
│  └─────────────────────────┬───────────────────────────────────────────┘     │
│                             │                                                 │
│  ┌─────────────────────────▼───────────────────────────────────────────┐     │
│  │                  Service Layer                                       │     │
│  │  TokenService  JWKSService  AgentService  ClientService             │     │
│  │  DPoPService  DelegationService  AuditService  StepUpService        │     │
│  └─────────────────────────┬───────────────────────────────────────────┘     │
│                             │                                                 │
│  ┌─────────────────────────▼───────────────────────────────────────────┐     │
│  │                  Provider Layer (Protocols)                          │     │
│  │  AttestationProvider  PolicyProvider  HITLProvider                   │     │
│  │  KeyProvider  EventEmitter  HumanAuthProvider  ClaimEnricher        │     │
│  └─────────────────────────┬───────────────────────────────────────────┘     │
│                             │                                                 │
│  ┌─────────────────────────▼───────────────────────────────────────────┐     │
│  │                  Data Layer (SQLAlchemy Async)                       │     │
│  │  OAuthClient  Agent  AuthorizationCode  RefreshToken                │     │
│  │  DeviceCode  Consent  SigningKey  TokenBlocklist                     │     │
│  │  AuditLog  DelegationReceipt  StepUpRequest  User                   │     │
│  └─────────────────────────┬───────────────────────────────────────────┘     │
│                             │                                                 │
│  ┌─────────────────────────▼───────────────────────────────────────────┐     │
│  │                  Database                                            │     │
│  │  SQLite (dev) │ PostgreSQL (prod)                                   │     │
│  └─────────────────────────────────────────────────────────────────────┘     │
└──────────────────────────────────────────────────────────────────────────────┘
        │
        ▼
┌──────────────────────────────────────────────────────────────────────────────┐
│                       authgent SDK (Validator Side)                            │
│                                                                               │
│  MCP Server / API Server / Agent Runtime                                      │
│  ┌─────────────────────────────────────────────────────────────────┐         │
│  │  Middleware (FastAPI / Flask / Express / Hono)                   │         │
│  │  → verify_token() → verify_delegation_chain()                   │         │
│  │  → verify_dpop_proof() → PolicyProvider.evaluate()              │         │
│  │  → Scope challenge auto-detection → HITL trigger                │         │
│  └─────────────────────────────────────────────────────────────────┘         │
└──────────────────────────────────────────────────────────────────────────────┘
```

---

## 3. Component Architecture

### 3.1 authgent-server

The OAuth 2.1 Authorization Server. Single deployable unit.

```
authgent-server/
├── authgent_server/
│   ├── __init__.py
│   ├── app.py                    # FastAPI app factory
│   ├── config.py                 # Pydantic Settings (AUTHGENT_* env vars)
│   ├── cli.py                    # Typer CLI (13 commands — init, run, create-agent, list-agents,
│   │                            #   get-token, inspect-token, audit, status, rotate-keys,
│   │                            #   create-user, openapi, migrate, quickstart)
│   ├── db.py                     # Async engine + session factory
│   ├── dependencies.py           # FastAPI Depends() injection
│   │
│   ├── endpoints/                # Thin HTTP layer — validation + delegation to services
│   │   ├── __init__.py           # router aggregation
│   │   ├── token.py              # POST /token (all grant types)
│   │   ├── authorize.py          # GET/POST /authorize (consent page)
│   │   ├── register.py           # POST /register (DCR + CIMD)
│   │   ├── revoke.py             # POST /revoke
│   │   ├── agents.py             # CRUD /agents
│   │   ├── device.py             # POST /device, GET /device/status
│   │   ├── stepup.py             # POST /stepup, GET /stepup/{id}
│   │   ├── wellknown.py          # /.well-known/* (5 endpoints: oauth-authorization-server,
│   │   │                         #   oauth-protected-resource, openid-configuration, jwks.json)
│   │   ├── introspect.py         # POST /introspect (RFC 7662)
│   │   ├── audit.py              # GET /audit (query audit logs with filtering)
│   │   ├── token_inspect.py      # GET /tokens/inspect (decode JWT, delegation chain)
│   │   └── health.py             # GET /health, /ready
│   │
│   ├── services/                 # Business logic — stateless, testable
│   │   ├── __init__.py
│   │   ├── token_service.py      # Grant handlers, token issuance
│   │   ├── jwks_service.py       # Key generation, rotation, JWKS document
│   │   ├── agent_service.py      # Agent CRUD + lifecycle
│   │   ├── client_service.py     # OAuth client registration + CIMD
│   │   ├── dpop_service.py       # DPoP proof validation + nonce mgmt
│   │   ├── delegation_service.py # act claim nesting + receipt generation
│   │   ├── consent_service.py    # Consent grant tracking
│   │   ├── stepup_service.py     # HITL step-up flow orchestration
│   │   └── audit_service.py      # Event emission via EventEmitter
│   │
│   ├── models/                   # SQLAlchemy ORM models
│   │   ├── __init__.py
│   │   ├── base.py               # DeclarativeBase + ULID mixin + timestamps
│   │   ├── oauth_client.py       # + jwks_uri, jwks, client_uri, contacts (RFC 7591)
│   │   ├── agent.py
│   │   ├── authorization_code.py
│   │   ├── refresh_token.py
│   │   ├── device_code.py
│   │   ├── consent.py
│   │   ├── signing_key.py
│   │   ├── token_blocklist.py
│   │   ├── audit_log.py
│   │   ├── delegation_receipt.py
│   │   ├── stepup_request.py
│   │   └── user.py                # Human user (builtin auth mode only)
│   │
│   ├── providers/                # Protocol implementations
│   │   ├── __init__.py
│   │   ├── protocols.py          # Protocol definitions (5 interfaces)
│   │   ├── attestation.py        # NullAttestationProvider
│   │   ├── policy.py             # ScopePolicyProvider
│   │   ├── hitl.py               # WebhookHITLProvider
│   │   ├── keys.py               # DatabaseKeyProvider
│   │   └── events.py             # DatabaseEventEmitter + OTelEventEmitter
│   │
│   ├── middleware/
│   │   ├── error_handler.py      # RFC 9457 Problem Details JSON + RFC 6750 WWW-Authenticate
│   │   │                         # with discovery URIs (realm, authorization_uri, resource_metadata)
│   │   ├── request_id.py         # X-Request-ID + traceparent propagation
│   │   ├── cors.py               # CORS from AUTHGENT_CORS_ORIGINS
│   │   │                         # Note: /.well-known/* (including JWKS) always
│   │   │                         # allows CORS GET regardless of CORS_ORIGINS
│   │   │                         # setting — SDKs must fetch JWKS cross-origin.
│   │   └── rate_limit.py         # Per-endpoint sliding window rate limiter
│   │
│   ├── schemas/                  # Pydantic request/response models
│   │   ├── token.py              # TokenRequest, TokenResponse
│   │   ├── client.py             # RegisterRequest, RegisterResponse (RFC 7591 — includes
│   │   │                         #   jwks_uri, jwks, client_uri, contacts + mutual exclusion)
│   │   ├── agent.py              # AgentCreate, AgentUpdate, AgentResponse
│   │   └── common.py             # ErrorResponse (RFC 9457), pagination
│   │
│   └── templates/
│       └── consent.html          # Minimal Jinja2 consent page
│
├── migrations/                   # Alembic
│   ├── env.py
│   ├── versions/
│   └── alembic.ini
│
├── tests/
│   ├── conftest.py               # Fixtures: test client, in-memory SQLite, test keys
│   ├── test_token.py
│   ├── test_authorize.py
│   ├── test_register.py
│   ├── test_agents.py
│   ├── test_delegation.py
│   ├── test_dpop.py
│   ├── test_security.py          # Forgery, escalation, replay attacks
│   ├── test_wellknown.py
│   └── test_agent_discovery.py   # Foreign agent auto-discovery integration tests (29 tests)
│
├── pyproject.toml
├── Dockerfile
└── docker-compose.yml
```

### 3.2 authgent SDK (Python)

Framework-agnostic token validation library. Zero server dependency in validator mode.

```
authgent/
├── __init__.py                   # Public API: verify_token, verify_delegation_chain, verify_dpop_proof
├── verify.py                     # JWT verification with JWKS
├── delegation.py                 # Delegation chain parsing + validation
├── dpop.py                       # DPoP proof verification + DPoPClient
├── jwks.py                       # JWKS fetcher with TTL cache
├── client.py                     # AgentAuthClient (server API wrapper)
├── models.py                     # AgentIdentity, DelegationChain, TokenClaims
├── errors.py                     # AuthgentError hierarchy
├── middleware/
│   ├── fastapi.py                # AgentAuthMiddleware + require_agent_auth + get_agent_identity
│   ├── flask.py                  # Same API surface, sync wrappers
│   └── scope_challenge.py        # MCP scope challenge auto-detection + HITL trigger
└── adapters/
    ├── mcp.py                    # AgentAuthProvider for FastMCP
    └── protected_resource.py     # RFC 9728 metadata generator
```

### 3.3 Future Platform Layers

MCP Gateway (Layer 2), Credential Vault (Layer 3), AI Framework Integrations (Layer 4), and Developer Dashboard (Layer 5) are architecturally designed but not yet implemented. Full specifications are in [ROADMAP.md](ROADMAP.md).

---

## 4. Detailed Flow Diagrams

### 4.1 Client Credentials Grant

```
Agent                    authgent-server                    Database
  │                           │                                │
  │  POST /token              │                                │
  │  grant_type=client_creds  │                                │
  │  client_id + secret       │                                │
  │  resource=https://mcp...  │                                │
  │  scope=tools:execute      │                                │
  │ ─────────────────────────►│                                │
  │                           │  1. Authenticate client        │
  │                           │     (bcrypt verify secret)     │
  │                           │ ──────────────────────────────►│
  │                           │◄──────────────────────────────│
  │                           │                                │
  │                           │  2. Validate resource against  │
  │                           │     allowed_resources          │
  │                           │                                │
  │                           │  3. Validate scope ⊆ client    │
  │                           │     registered scopes          │
  │                           │                                │
  │                           │  4. Check DPoP if cnf required │
  │                           │                                │
  │                           │  5. Sign JWT (ES256)           │
  │                           │     iss, sub, aud=resource,    │
  │                           │     scope, client_id, jti,     │
  │                           │     cnf.jkt (if DPoP)          │
  │                           │                                │
  │                           │  6. Emit audit event           │
  │                           │ ──────────────────────────────►│
  │                           │                                │
  │  200 OK                   │                                │
  │  { access_token, type,    │                                │
  │    expires_in, scope }    │                                │
  │◄─────────────────────────│                                │
```

### 4.2 Authorization Code + PKCE Flow

```
Human         MCP Client       authgent-server           Database
  │               │                   │                      │
  │  1. Click     │                   │                      │
  │  "Connect"    │                   │                      │
  │ ─────────────►│                   │                      │
  │               │                   │                      │
  │               │  2. GET /authorize│                      │
  │               │  response_type=code                      │
  │               │  client_id=...    │                      │
  │               │  redirect_uri=... │                      │
  │               │  scope=...        │                      │
  │               │  resource=https://│mcp-server...         │
  │               │  code_challenge=..│(S256)                │
  │               │  state=...        │                      │
  │               │ ─────────────────►│                      │
  │               │                   │  Note: `state` is    │
  │               │                   │  opaque to server —  │
  │               │                   │  echoed back to      │
  │               │                   │  client for client-  │
  │               │                   │  side CSRF per       │
  │               │                   │  OAuth 2.1.          │
  │               │                   │                      │
  │               │                   │  3. Validate client  │
  │               │                   │  + redirect_uri      │
  │               │                   │ ────────────────────►│
  │               │                   │◄────────────────────│
  │               │                   │                      │
  │  4. Consent page (HTML)           │                      │
  │  "Allow [agent] to access         │                      │
  │   [resource] with [scopes]?"      │                      │
  │◄──────────────────────────────────│                      │
  │                                   │                      │
  │  5. User clicks "Allow"           │                      │
  │ ──────────────────────────────────►                      │
  │               │                   │                      │
  │               │                   │  6. Check existing   │
  │               │                   │  consent (skip if    │
  │               │                   │  already granted)    │
  │               │                   │ ────────────────────►│
  │               │                   │                      │
  │               │                   │  7. Store auth code  │
  │               │                   │  + code_challenge    │
  │               │                   │  + resource          │
  │               │                   │ ────────────────────►│
  │               │                   │                      │
  │               │  8. 302 redirect  │                      │
  │               │  ?code=...&state= │                      │
  │               │◄─────────────────│                      │
  │               │                   │                      │
  │               │  9. POST /token   │                      │
  │               │  grant_type=      │                      │
  │               │   authorization_code                     │
  │               │  code=...         │                      │
  │               │  code_verifier=...│                      │
  │               │  redirect_uri=... │                      │
  │               │ ─────────────────►│                      │
  │               │                   │                      │
  │               │                   │  10. Verify:         │
  │               │                   │  - code exists, not  │
  │               │                   │    used, not expired │
  │               │                   │  - PKCE: S256(       │
  │               │                   │    verifier)==        │
  │               │                   │    challenge          │
  │               │                   │  - redirect_uri      │
  │               │                   │    matches            │
  │               │                   │                      │
  │               │                   │  11. ATOMIC CAS:     │
  │               │                   │  UPDATE auth_codes   │
  │               │                   │  SET used=TRUE       │
  │               │                   │  WHERE code=:code    │
  │               │                   │  AND used=FALSE      │
  │               │                   │  AND expires_at > now│
  │               │                   │  RETURNING *         │
  │               │                   │  (0 rows = reject)   │
  │               │                   │ ────────────────────►│
  │               │                   │                      │
  │               │                   │  12. Issue tokens:   │
  │               │                   │  - Access token (JWT)│
  │               │                   │  - Refresh token     │
  │               │                   │    (stored in DB     │
  │               │                   │    with family_id)   │
  │               │                   │  - If scope=openid   │
  │               │                   │    and nonce stored:  │
  │               │                   │    include nonce in   │
  │               │                   │    ID token (OIDC     │
  │               │                   │    Core §3.1.2.1)     │
  │               │                   │ ────────────────────►│
  │               │                   │                      │
  │               │  13. 200 OK       │                      │
  │               │  { access_token,  │                      │
  │               │    refresh_token, │                      │
  │               │    token_type,    │                      │
  │               │    expires_in }   │                      │
  │               │◄─────────────────│                      │
```

### 4.3 Token Exchange (Delegation Chain)

```
Agent A               authgent-server              Database
  │                        │                          │
  │  POST /token           │                          │
  │  grant_type=           │                          │
  │   urn:ietf:params:     │                          │
  │   oauth:grant-type:    │                          │
  │   token-exchange       │                          │
  │  subject_token=eyJ...  │                          │
  │  subject_token_type=   │                          │
  │   access_token         │                          │
  │  audience=agent:db-rdr │                          │
  │  scope=db:read         │                          │
  │  [DPoP: eyJ...proof]   │                          │
  │ ──────────────────────►│                          │
  │                        │                          │
  │                        │  1. Verify subject_token │
  │                        │     (signature, exp, iss)│
  │                        │                          │
  │                        │  1b. Verify requester    │
  │                        │     owns subject_token:  │
  │                        │     - DPoP on? proof.jkt │
  │                        │       must == cnf.jkt    │
  │                        │     - DPoP off? client_id│
  │                        │       must match token's │
  │                        │       client_id or be in │
  │                        │       token's may_act    │
  │                        │                          │
  │                        │  2. Check delegation     │
  │                        │     depth < MAX (5)      │
  │                        │                          │
  │                        │  3. Enforce scope        │
  │                        │     reduction:           │
  │                        │     requested ⊆ parent   │
  │                        │                          │
  │                        │  4. Cross-audience scope │
  │                        │     mapping check        │
  │                        │                          │
  │                        │  5. Build nested act:    │
  │                        │     {                    │
  │                        │       sub: "agent:A",    │
  │                        │       act: {parent act}  │
  │                        │     }                    │
  │                        │                          │
  │                        │  6. Generate delegation  │
  │                        │     receipt:             │
  │                        │     - Signed by Agent A's│
  │                        │       DPoP key           │
  │                        │     - Contains chain_hash│
  │                        │     - Links parent_jti → │
  │                        │       child_jti          │
  │                        │                          │
  │                        │  7. Store receipt        │
  │                        │ ────────────────────────►│
  │                        │                          │
  │                        │  8. Sign new JWT:        │
  │                        │     sub=original_subject │
  │                        │     aud=agent:db-rdr     │
  │                        │     act={nested chain}   │
  │                        │     delegation_receipt=  │
  │                        │       eyJ...             │
  │                        │     delegation_purpose=  │
  │                        │     delegation_constraints│
  │                        │                          │
  │                        │  9. Emit audit event     │
  │                        │     (token.exchanged)    │
  │                        │ ────────────────────────►│
  │                        │                          │
  │  200 OK                │                          │
  │  { access_token (new), │                          │
  │    issued_token_type:  │                          │
  │    urn:...:access_token│                          │
  │    token_type,         │                          │
  │    expires_in }        │                          │
  │◄──────────────────────│                          │
```

### 4.4 Refresh Token Rotation (with Reuse Detection)

```
Client                authgent-server              Database
  │                        │                          │
  │  POST /token           │                          │
  │  grant_type=           │                          │
  │   refresh_token        │                          │
  │  refresh_token=eyJ...  │                          │
  │  client_id=...         │                          │
  │  resource=https://...  │  (RFC 8707: must match   │
  │                        │   original resource)     │
  │ ──────────────────────►│                          │
  │                        │                          │
  │                        │  1. Look up refresh      │
  │                        │     token by JTI         │
  │                        │ ────────────────────────►│
  │                        │                          │
  │                        │  1b. Verify resource     │
  │                        │     matches stored       │
  │                        │     resource binding     │
  │                        │                          │
  │                        │  CASE A: used=FALSE      │
  │                        │  ─────────────────────   │
  │                        │  2. ATOMIC compare-and-  │
  │                        │     swap:                │
  │                        │     UPDATE refresh_tokens│
  │                        │     SET used=TRUE        │
  │                        │     WHERE jti=:jti       │
  │                        │     AND used=FALSE       │
  │                        │     RETURNING *          │
  │                        │     (0 rows = race lost  │
  │                        │      → treat as reuse)   │
  │                        │ ────────────────────────►│
  │                        │                          │
  │                        │  3. Issue new refresh    │
  │                        │     token (same          │
  │                        │     family_id)           │
  │                        │ ────────────────────────►│
  │                        │                          │
  │                        │  4. Issue new access     │
  │                        │     token                │
  │                        │                          │
  │  200 OK                │                          │
  │  { access_token,       │                          │
  │    refresh_token (new)}│                          │
  │◄──────────────────────│                          │
  │                        │                          │
  │                        │  CASE B: used=TRUE       │
  │                        │  ═══ REUSE DETECTED ═══  │
  │                        │  2. REVOKE ALL tokens    │
  │                        │     with same family_id  │
  │                        │ ────────────────────────►│
  │                        │                          │
  │                        │  3. Emit security event  │
  │                        │     (token.replay_       │
  │                        │      detected)           │
  │                        │                          │
  │  400 invalid_grant     │                          │
  │◄──────────────────────│                          │
```

**DPoP binding for refresh tokens (RFC 9449 §5):** When `require_dpop=true`, the refresh token is also sender-constrained. The `refresh_tokens` table stores a `dpop_jkt` column (JWK thumbprint of the client's DPoP key). On refresh, the server verifies the DPoP proof's JWK thumbprint matches `refresh_tokens.dpop_jkt`. A stolen refresh token is useless without the client's ephemeral private key.

### 4.5 DPoP-Protected Request

```
Agent                 MCP Server (SDK)           authgent-server
  │                        │                          │
  │  1. Generate ephemeral │                          │
  │     EC P-256 key pair  │                          │
  │     (in memory)        │                          │
  │                        │                          │
  │  2. Create DPoP proof: │                          │
  │     Header: dpop+jwt,  │                          │
  │       ES256, jwk:{pub} │                          │
  │     Payload: jti, htm, │                          │
  │       htu, iat, ath,   │                          │
  │       nonce            │                          │
  │                        │                          │
  │  POST /tools/search    │                          │
  │  Authorization: DPoP   │                          │
  │    eyJ...access_token  │                          │
  │  DPoP: eyJ...proof     │                          │
  │ ──────────────────────►│                          │
  │                        │                          │
  │                        │  3. SDK middleware:       │
  │                        │  a. Decode access token  │
  │                        │  b. Check cnf.jkt exists │
  │                        │  c. Verify DPoP proof:   │
  │                        │     - Signature valid    │
  │                        │     - htm matches method │
  │                        │     - htu matches URL    │
  │                        │     - iat is recent      │
  │                        │     - ath = SHA256(token) │
  │                        │     - jkt(proof.jwk) ==  │
  │                        │       cnf.jkt            │
  │                        │     - nonce matches if   │
  │                        │       server requires    │
  │                        │  d. Check scopes         │
  │                        │  e. Verify delegation    │
  │                        │     chain (if present)   │
  │                        │                          │
  │                        │  4. If nonce expired:    │
  │  401 + DPoP-Nonce hdr  │     return 401 with     │
  │◄──────────────────────│     new DPoP-Nonce       │
  │                        │                          │
  │  5. Retry with new     │                          │
  │     nonce in proof     │                          │
  │ ──────────────────────►│                          │
  │                        │                          │
  │  200 OK (tool result)  │                          │
  │◄──────────────────────│                          │
```

### 4.6 HITL Step-Up (MCP Scope Challenge)

```
Agent              MCP Server (SDK)      authgent-server       Human
  │                     │                      │                 │
  │  POST /tools/delete │                      │                 │
  │  (scope: db:read)   │                      │                 │
  │ ───────────────────►│                      │                 │
  │                     │                      │                 │
  │                     │ 1. Middleware checks: │                 │
  │                     │    scope "db:delete"  │                 │
  │                     │    required but token │                 │
  │                     │    only has "db:read" │                 │
  │                     │                      │                 │
  │  403 Forbidden      │                      │                 │
  │  WWW-Authenticate:  │                      │                 │
  │    Bearer scope=    │                      │                 │
  │    "db:delete"      │                      │                 │
  │    error=           │                      │                 │
  │    insufficient_scope                      │                 │
  │◄───────────────────│                      │                 │
  │                     │                      │                 │
  │  2. SDK auto-detect:│                      │                 │
  │     "db:delete" is  │                      │                 │
  │     in HITL_SCOPES  │                      │                 │
  │                     │                      │                 │
  │  3. POST /stepup    │                      │                 │
  │     scope=db:delete │                      │                 │
  │     resource=...    │                      │                 │
  │     chain_snapshot  │                      │                 │
  │ ────────────────────────────────────────────►                │
  │                     │                      │                 │
  │                     │                      │  4. HITLProvider│
  │                     │                      │  .request_      │
  │                     │                      │   approval()    │
  │                     │                      │ ───────────────►│
  │                     │                      │                 │
  │  202 Accepted       │                      │  5. Human sees: │
  │  { stepup_id,       │                      │  "Agent X wants │
  │    poll_url }       │                      │   to DELETE     │
  │◄────────────────────────────────────────────                │
  │                     │                      │   from DB.      │
  │                     │                      │   Chain: Human→ │
  │  6. Poll            │                      │   Agent A→X"    │
  │  GET /stepup/{id}   │                      │                 │
  │ ────────────────────────────────────────────►  7. "Approve"  │
  │                     │                      │◄───────────────│
  │  200 { status:      │                      │                 │
  │    approved,        │                      │                 │
  │    step_up_token }  │                      │                 │
  │◄────────────────────────────────────────────                │
  │                     │                      │                 │
  │  8. Retry original  │                      │                 │
  │  POST /tools/delete │                      │                 │
  │  (with step_up_token)                      │                 │
  │ ───────────────────►│                      │                 │
  │                     │                      │                 │
  │  200 OK (deleted)   │                      │                 │
  │◄───────────────────│                      │                 │
```

### 4.7 External Identity Token Exchange (Auth0 / Clerk / Okta Bridge)

The programmatic bridge between existing identity providers and authgent's delegation chains. This is **distinct** from `external_oidc` human auth mode (§13.2.1), which handles browser-based consent. This flow is for API-first usage where a frontend already holds an external id_token.

**Use case:** Chat UI authenticates the human via Auth0/Clerk. The frontend passes the id_token to authgent, which validates it against the external IdP's JWKS and issues an authgent token with the human as the delegation chain root (`human_root=true`).

```
Chat UI (Auth0 JWT)       authgent-server              External IdP
  │                            │                          │
  │  POST /token               │                          │
  │  grant_type=               │                          │
  │   urn:ietf:params:         │                          │
  │   oauth:grant-type:        │                          │
  │   token-exchange           │                          │
  │  subject_token=eyJ...      │  (Auth0/Clerk id_token)  │
  │  subject_token_type=       │                          │
  │   urn:ietf:params:oauth:   │                          │
  │   token-type:id_token      │                          │
  │  audience=agent:orchestr   │                          │
  │  scope=tools:execute       │                          │
  │  client_id=...             │                          │
  │  client_secret=...         │                          │
  │ ──────────────────────────►│                          │
  │                            │                          │
  │                            │  1. Detect subject_token │
  │                            │     _type = id_token     │
  │                            │                          │
  │                            │  2. Decode JWT header,   │
  │                            │     extract `iss` claim  │
  │                            │                          │
  │                            │  3. Check iss ∈ trusted  │
  │                            │     issuers allowlist    │
  │                            │     (AUTHGENT_TRUSTED_   │
  │                            │      OIDC_ISSUERS)       │
  │                            │                          │
  │                            │  4. Fetch IdP JWKS       │
  │                            │ ────────────────────────►│
  │                            │    GET {iss}/.well-known │
  │                            │    /jwks.json            │
  │                            │◄────────────────────────│
  │                            │                          │
  │                            │  5. Verify id_token:     │
  │                            │     - Signature (JWKS)   │
  │                            │     - exp, iat, iss      │
  │                            │     - aud matches        │
  │                            │       AUTHGENT_TRUSTED_  │
  │                            │       OIDC_AUDIENCE      │
  │                            │     - nonce (if present) │
  │                            │                          │
  │                            │  6. Extract human        │
  │                            │     identity:            │
  │                            │     sub → user:{sub}     │
  │                            │     email, name (opt)    │
  │                            │                          │
  │                            │  7. Issue authgent token │
  │                            │     sub=user:{idp_sub}   │
  │                            │     aud=agent:orchestr   │
  │                            │     human_root=true      │
  │                            │     act=null (root hop)  │
  │                            │     scope=tools:execute  │
  │                            │     idp_iss={iss}        │
  │                            │     idp_sub={sub}        │
  │                            │                          │
  │  200 OK                    │                          │
  │  { access_token (authgent),│                          │
  │    token_type: "Bearer",   │                          │
  │    expires_in: 900 }       │                          │
  │◄──────────────────────────│                          │
  │                            │                          │
  │  Now agent can use this    │                          │
  │  token for token exchange  │                          │
  │  → delegation chains with  │                          │
  │  human_root=true           │                          │
```

**Security constraints:**
- `AUTHGENT_TRUSTED_OIDC_ISSUERS` — comma-separated allowlist of trusted issuer URLs. **Required** — no wildcard acceptance. Example: `https://dev-abc123.us.auth0.com/,https://clerk.example.com`
- `AUTHGENT_TRUSTED_OIDC_AUDIENCE` — expected `aud` claim in the external id_token (your app's client_id at the IdP). Prevents token confusion attacks.
- External JWKS is cached with the same `JWKSFetcher` strategy (§11.2): TTL cache + thundering-herd mutex + forced re-fetch on unknown kid.
- The issued authgent token carries `idp_iss` and `idp_sub` claims for audit trail — downstream validators can verify the human root's origin.
- Rate limited per client_id (same as token exchange: 200/min).

**Relationship to ExternalOIDCAuthProvider (§18.6):**
- §18.6 handles **browser consent** — redirect to Auth0, handle OIDC callback, create session cookie
- §4.7 handles **programmatic API** — frontend already has the id_token, no browser redirect needed
- Both share the JWKS validation logic but serve different integration patterns

### 4.8 Foreign Agent Auto-Discovery (RFC 6750 + RFC 8414 + RFC 7591)

A foreign agent with zero prior configuration bootstraps itself using standard HTTP discovery:

```
Foreign Agent            Resource Server (SDK)         authgent-server
  │                           │                              │
  │  1. GET /tools/search     │                              │
  │ ─────────────────────────►│                              │
  │                           │                              │
  │  401 Unauthorized         │                              │
  │  WWW-Authenticate: Bearer │                              │
  │    realm="authgent",      │                              │
  │    authorization_uri=     │                              │
  │      ".../token",         │                              │
  │    resource_metadata=     │                              │
  │      ".../.well-known/    │                              │
  │      oauth-protected-     │                              │
  │      resource"            │                              │
  │◄─────────────────────────│                              │
  │                           │                              │
  │  2. GET /.well-known/oauth-protected-resource            │
  │ ─────────────────────────────────────────────────────────►│
  │  { authorization_servers: ["http://localhost:8000"] }     │
  │◄─────────────────────────────────────────────────────────│
  │                           │                              │
  │  3. GET /.well-known/oauth-authorization-server          │
  │ ─────────────────────────────────────────────────────────►│
  │  { token_endpoint, registration_endpoint,                │
  │    grant_types_supported, ... }                          │
  │◄─────────────────────────────────────────────────────────│
  │                           │                              │
  │  4. POST /register (RFC 7591 — dynamic client reg)       │
  │  { client_name, scope, client_uri, contacts,             │
  │    jwks_uri (optional) }                                 │
  │ ─────────────────────────────────────────────────────────►│
  │  { client_id, client_secret }                            │
  │◄─────────────────────────────────────────────────────────│
  │                           │                              │
  │  5. POST /token (client_credentials)                     │
  │ ─────────────────────────────────────────────────────────►│
  │  { access_token, token_type, expires_in }                │
  │◄─────────────────────────────────────────────────────────│
  │                           │                              │
  │  6. GET /tools/search     │                              │
  │  Authorization: Bearer eyJ│...                           │
  │ ─────────────────────────►│                              │
  │  200 OK                   │                              │
  │◄─────────────────────────│                              │
```

**Key implementation points:**
- **Step 1:** SDK middleware (`fastapi.py`, `flask.py`) and server `error_handler.py` emit `WWW-Authenticate` with `resource_metadata` URI (RFC 9728 §5.1).
- **Step 3:** Server also exposes `/openapi.json` with `securitySchemes` so LLMs can parse auth requirements programmatically.
- **Step 4:** `RegisterRequest` supports RFC 7591 fields: `jwks_uri`, `jwks` (inline, mutually exclusive per §2), `client_uri`, `contacts`. Validators enforce HTTPS for `jwks_uri` (localhost excepted) and `keys` array structure for `jwks`.
- **No SDK required** — the entire flow is discoverable from a single 401 response.

### 4.9 Device Authorization Grant (RFC 8628)

```
CLI Agent          authgent-server           Human (Browser)
  │                     │                         │
  │  POST /device       │                         │
  │  client_id=...      │                         │
  │  scope=...          │                         │
  │  resource=...       │                         │
  │ ───────────────────►│                         │
  │                     │                         │
  │  200 OK             │                         │
  │  { device_code,     │                         │
  │    user_code: "ABCD-│1234",                   │
  │    verification_uri,│                         │
  │    interval: 5 }    │                         │
  │◄───────────────────│                         │
  │                     │                         │
  │  Display:           │                         │
  │  "Go to             │                         │
  │   https://...       │                         │
  │   Enter code:       │                         │
  │   ABCD-1234"        │                         │
  │                     │  1. Human visits URL     │
  │                     │◄────────────────────────│
  │                     │                         │
  │                     │  2. Shows consent page   │
  │                     │  with user_code          │
  │                     │────────────────────────►│
  │                     │                         │
  │                     │  3. Human enters code    │
  │                     │  + approves              │
  │                     │◄────────────────────────│
  │                     │                         │
  │  POST /token        │  4. Server marks device │
  │  grant_type=        │     code as "authorized"│
  │   device_code       │                         │
  │  device_code=...    │                         │
  │ ───────────────────►│                         │
  │                     │                         │
  │  200 OK             │                         │
  │  { access_token,    │                         │
  │    refresh_token }  │                         │
  │◄───────────────────│                         │
```

---

## 5. Service Layer Architecture

Each service is a class instantiated at app startup and injected via FastAPI `Depends()`. Services receive an async DB session and provider references.

### 5.1 Service Dependency Graph

```
                    ┌─────────────┐
                    │ TokenService │
                    └──────┬──────┘
                           │ depends on
              ┌────────────┼────────────┐
              ▼            ▼            ▼
     ┌────────────┐ ┌───────────┐ ┌───────────────┐
     │ JWKSService│ │ DPoPSvc   │ │DelegationSvc  │
     └────────────┘ └───────────┘ └───────┬───────┘
                                          │
                                    ┌─────▼──────┐
                                    │ AuditService│
                                    └─────┬──────┘
                                          │
                                    ┌─────▼──────┐
                                    │EventEmitter │
                                    │ (Protocol)  │
                                    └────────────┘

     ┌──────────────┐  ┌─────────────┐  ┌────────────┐
     │ClientService  │  │AgentService │  │StepUpService│
     └──────────────┘  └─────────────┘  └──────┬─────┘
                                               │
                                         ┌─────▼────┐
                                         │HITLProvider│
                                         │(Protocol) │
                                         └──────────┘

```

> **Future:** GatewayService and VaultService (platform layers) will depend on TokenService + AuditService. See [ROADMAP.md](ROADMAP.md).

### 5.2 TokenService — Grant Handler Pattern

**Client authentication** happens *before* grant dispatch. The `/token` endpoint authenticates the client via one of:
- `client_secret_post` — `client_id` + `client_secret` in request body
- `client_secret_basic` — HTTP Basic auth header
- `client_assertion` (RFC 7523) — `client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer` + signed JWT. Parsed and verified in the client auth step, NOT as a separate grant type.
- `none` — public clients (MUST use DPoP for token exchange)

Once authenticated, `TokenService` dispatches to grant handlers:

```python
class GrantHandler(Protocol):
    """Protocol for custom grant type handlers. Register via config."""
    async def handle(self, request: TokenRequest, client: OAuthClient) -> TokenResponse: ...

class TokenService:
    def __init__(self, db: AsyncSession, jwks: JWKSService,
                 dpop: DPoPService, delegation: DelegationService,
                 audit: AuditService, config: Settings):
        self._handlers: dict[str, GrantHandler] = {
            "client_credentials": self._handle_client_credentials,
            "authorization_code": self._handle_authorization_code,
            "refresh_token": self._handle_refresh_token,
            "urn:ietf:params:oauth:grant-type:token-exchange": self._handle_token_exchange,
            "urn:ietf:params:oauth:grant-type:device_code": self._handle_device_code,
        }
        # Custom grant handlers registered via AUTHGENT_CUSTOM_GRANT_HANDLERS
        for uri, dotted_path in (config.custom_grant_handlers or {}).items():
            self._handlers[uri] = _import_class(dotted_path)(config)

    async def issue_token(self, request: TokenRequest) -> TokenResponse:
        handler = self._handlers.get(request.grant_type)
        if not handler:
            raise UnsupportedGrantType(request.grant_type)
        return await handler(request)
```

**Note on token exchange security:** When DPoP is disabled, the token exchange endpoint relies on confidential client authentication (`client_secret` or `client_assertion`). Public clients (`token_endpoint_auth_method=none`) MUST use DPoP for token exchange — the server rejects exchange requests from unauthenticated public clients without DPoP proof.

**`subject_token_type` dispatch:** The token exchange handler branches on `subject_token_type` (RFC 8693 §2.1):

```python
# Inside _handle_token_exchange:
subject_token_type = kwargs.get("subject_token_type", "urn:ietf:params:oauth:token-type:access_token")

if subject_token_type == "urn:ietf:params:oauth:token-type:id_token":
    # External identity token (Auth0/Clerk/Okta) — §4.7
    parent_claims = await self._verify_external_id_token(db, str(subject_token))
    # parent_claims["sub"] becomes the human root of the delegation chain
    # Sets human_root=true in issued token
elif subject_token_type == "urn:ietf:params:oauth:token-type:access_token":
    # authgent-issued access token — §4.3 (existing flow)
    parent_claims = await self.verify_and_check_blocklist(db, str(subject_token))
else:
    raise InvalidRequest(f"Unsupported subject_token_type: {subject_token_type}")
```

The `_verify_external_id_token` method:
1. Decodes the JWT header without verification to extract `iss`
2. Checks `iss` against `AUTHGENT_TRUSTED_OIDC_ISSUERS` allowlist (reject if not trusted)
3. Fetches the IdP's JWKS from `{iss}/.well-known/jwks.json` (cached via `JWKSFetcher`)
4. Verifies signature, exp, iat, iss, and aud (must match `AUTHGENT_TRUSTED_OIDC_AUDIENCE`)
5. Returns normalized claims with `sub` prefixed as `user:{idp_sub}` to distinguish from agent subjects

### 5.3 JWKSService — Key Lifecycle

```python
class JWKSService:
    async def get_active_key(self) -> SigningKey:
        """Returns current signing key. Auto-generates on first call.
        Multi-instance safety: uses INSERT ... ON CONFLICT DO NOTHING
        so only one instance creates the initial key."""

    async def rotate_key(self) -> SigningKey:
        """Creates new key, marks old as 'rotated'. Old key stays in JWKS for TTL.
        Multi-instance safety: PostgreSQL uses pg_advisory_xact_lock(hash('jwks_rotate'))
        before rotation. SQLite is single-instance."""

    async def get_jwks_document(self) -> dict:
        """Returns JWKS JSON with all active + recently-rotated keys."""

    async def sign_jwt(self, claims: dict, headers: dict | None = None) -> str:
        """Sign claims with active key. Adds kid to header."""

    async def verify_jwt(self, token: str, audience: str | None = None) -> dict:
        """Verify JWT against JWKS. Handles key rotation gracefully."""
```

**Key generation race (B1):** On first startup against an empty DB, multiple instances call `get_active_key()` concurrently. The initial key insertion uses `INSERT INTO signing_keys (...) ON CONFLICT (status) WHERE status = 'active' DO NOTHING`. Only one row wins; all instances then SELECT the same active key.

**Key rotation race (B2):** Auto-rotation (every `jwks_rotation_days`) wraps the rotate logic in `SELECT pg_advisory_xact_lock(hashtext('authgent_key_rotation'))`. Only one instance rotates; others skip. Alternative: disable auto-rotation (`AUTHGENT_JWKS_AUTO_ROTATE=false`) and use `authgent-server rotate-keys` CLI command (safer for production, consistent with Ory Hydra's approach).

### 5.4 DelegationService — Chain Construction

```python
class DelegationService:
    async def build_delegated_token(
        self, parent_token: dict, actor_id: str,
        target_audience: str, requested_scopes: list[str],
        dpop_key: dict | None = None,
    ) -> tuple[dict, str | None]:
        """
        Returns (claims_dict, delegation_receipt_jwt).
        Enforces: depth limit, scope reduction, cross-audience policy,
        and may_act authorization (RFC 8693 §4.4).
        Builds nested act claims. Generates signed receipt.
        """

    def verify_chain(self, claims: dict, max_depth: int = 5,
                     require_human_root: bool = False,
                     allowed_actors: list[str] | None = None) -> DelegationChain:
        """Parse and validate act claim nesting."""
```

#### `may_act` Enforcement (RFC 8693 §4.4)

The `may_act` claim restricts which actors can exchange a given token. This is critical for chain splicing prevention (complementing signed delegation receipts).

**Storage:** `agents.allowed_exchange_targets` (JSON list) defines which audiences an agent can delegate *to*. `oauth_clients.may_act_subs` (JSON list) defines which `sub` values are permitted to exchange tokens issued to this client.

**Injection:** When issuing a token, if the client/agent has `may_act_subs` configured, the token includes:
```json
{ "may_act": { "sub": ["agent:search-bot", "agent:orchestrator"] } }
```

**Validation during token exchange:**
1. If `subject_token` contains `may_act`, verify `actor_id ∈ may_act.sub` — reject if not listed
2. If `actor` agent has `allowed_exchange_targets`, verify `target_audience ∈ allowed_exchange_targets` — reject if not listed
3. Both checks are enforced in `DelegationService.build_delegated_token()` before building `act` claims

### 5.5 DPoPService — Nonce Strategy

DPoP nonces (RFC 9449 §8) prevent precomputed proof attacks. Rather than storing nonces in a database table (which creates write contention and requires cross-instance coordination), we use **HMAC-based time-bucketed nonces** that are stateless and scale horizontally.

```python
class DPoPService:
    """Stateless DPoP nonce generation and validation.
    Nonce = HMAC-SHA256(server_secret, time_bucket) — no DB table needed."""

    BUCKET_DURATION = 300  # 5-minute buckets
    GRACE_BUCKETS = 1      # accept current + previous bucket

    def generate_nonce(self) -> str:
        """Generate nonce for current time bucket."""
        bucket = int(time.time()) // self.BUCKET_DURATION
        return self._hmac_nonce(bucket)

    def validate_nonce(self, nonce: str) -> bool:
        """Accept nonce from current or previous time bucket (grace period)."""
        bucket = int(time.time()) // self.BUCKET_DURATION
        return nonce in {
            self._hmac_nonce(bucket),
            self._hmac_nonce(bucket - self.GRACE_BUCKETS),
        }

    def _hmac_nonce(self, bucket: int) -> str:
        return hmac.new(
            settings._dpop_key, str(bucket).encode(), "sha256"  # HKDF-derived subkey (§9.1)
        ).hexdigest()[:32]

    async def verify_dpop_proof(self, proof_jwt: str, access_token: str,
                                 http_method: str, http_uri: str,
                                 expected_jkt: str | None = None) -> dict:
        """Full DPoP proof verification per RFC 9449 §4.3."""
        # 1. Decode proof header+payload (typ=dpop+jwt, alg=ES256)
        # 2. Verify signature with embedded jwk
        # 3. Verify htm, htu, iat (within clock skew tolerance)
        # 4. Verify ath = base64url(SHA256(access_token))
        # 5. If expected_jkt: verify JWK thumbprint matches cnf.jkt
        # 6. If nonce required: validate_nonce(proof.nonce)
        # 7. If nonce expired: raise UseDPoPNonce with fresh nonce
        ...
```

**Why HMAC nonces over DB nonces:** Every instance generates identical nonces from the shared `AUTHGENT_SECRET_KEY`. No DB writes on every DPoP request. No cleanup jobs. Horizontal scaling works without coordination. The 5-minute bucket + 1 grace bucket gives a 10-minute validity window.

---

## 6. Data Layer

### 6.1 Database Engine Strategy

```python
# db.py
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker

# SQLite needs StaticPool with pool_size=1 to avoid "database is locked" errors
if "sqlite" in settings.database_url:
    from sqlalchemy.pool import StaticPool
    engine = create_async_engine(
        settings.database_url,
        echo=settings.debug,
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
else:
    engine = create_async_engine(
        settings.database_url,
        echo=settings.debug,
        pool_pre_ping=True,              # detect stale connections
        pool_size=5,                      # PostgreSQL
        max_overflow=10,                  # PostgreSQL
    )

# expire_on_commit=False: prevents lazy-load errors when accessing ORM
# attributes after commit but outside the session context (e.g., in response serialization)
AsyncSessionLocal = async_sessionmaker(engine, expire_on_commit=False)

async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """Yields a session. Services must call session.commit() explicitly after writes.
    Read-only endpoints never trigger a commit. On unhandled exceptions the
    session is rolled back. The session is always closed in the finally block."""
    async with AsyncSessionLocal() as session:
        try:
            yield session
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()
```

### 6.2 Model Base

```python
# models/base.py
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from ulid import ULID

class Base(DeclarativeBase):
    pass

class ULIDMixin:
    id: Mapped[str] = mapped_column(
        String(26), primary_key=True, default=lambda: str(ULID())
    )

class TimestampMixin:
    created_at: Mapped[datetime] = mapped_column(default=func.now())
    updated_at: Mapped[datetime] = mapped_column(default=func.now(), onupdate=func.now())
```

### 6.3 Entity Relationship Diagram

```
users (PK: id)  — only used in builtin HUMAN_AUTH_MODE
    │
    └··· consents (logical: consents.subject = users.id when builtin mode)
         Note: consents.subject is VARCHAR, not a FK — supports external_oidc
         mode where subject is the IdP's sub claim, not a local user ID.

oauth_clients (PK: client_id)
    │
    ├──< authorization_codes (FK: client_id)
    │       └── nonce VARCHAR — OIDC nonce for ID token replay prevention
    ├──< refresh_tokens (FK: client_id)
    │       └── dpop_jkt VARCHAR — DPoP binding (RFC 9449 §5)
    ├──< device_codes (FK: client_id)
    ├──< consents (FK: client_id)
    │       └── UNIQUE(subject, client_id, resource)  — prevents duplicate grants
    │
    └──1 agents (FK: oauth_client_id, UNIQUE)
           │
           ├──< stepup_requests (FK: agent_id)
           └── (agent_id referenced in audit_log, delegation_receipts)

signing_keys (standalone — no FK)
token_blocklist (standalone — JTI-indexed)
audit_log (standalone — write-only append log)
delegation_receipts (standalone — JTI-indexed)
```

> **Future:** `vault_credentials` and `gateway_configs` tables will be added for platform layers. See [ROADMAP.md](ROADMAP.md).

### 6.4 Cleanup Jobs

Background tasks (run on server startup interval or via CLI cron):

| Table | Cleanup Rule | Frequency |
|---|---|---|
| `token_blocklist` | Delete where `expires_at < now()` | Every 1 hour |
| `authorization_codes` | Delete where `expires_at < now()` or `used = TRUE` and age > 10min | Every 15 min |
| `device_codes` | Delete where `expires_at < now()` | Every 15 min |
| `stepup_requests` | Mark `expired` where `expires_at < now()` and status = `pending`; delete non-pending rows older than 7 days (retention) | Every 1 min |
| `refresh_tokens` | Delete where `expires_at < now()` | Every 1 hour |
| `audit_log` | Optional: archive/delete after configurable retention period | Daily |

Implemented as FastAPI `lifespan` background tasks using `asyncio.create_task` with a sleep loop.

**Multi-instance coordination:** Cleanup queries are designed to be idempotent and safe under concurrent execution. PostgreSQL deployments use `DELETE ... WHERE ctid IN (SELECT ctid FROM ... WHERE expires_at < now() LIMIT 1000 FOR UPDATE SKIP LOCKED)` to avoid conflicts between instances. SQLite is single-instance by nature. No leader election needed — duplicate cleanup attempts are harmless (they delete 0 rows).

**Advisory lock optimization (B4):** To avoid N instances × 5 loops all hitting PostgreSQL every interval, each cleanup loop attempts `SELECT pg_try_advisory_lock(hashtext('authgent_cleanup_' || :table))` before executing. If the lock is held by another instance, that iteration is skipped. Zero coordination overhead, zero deadlock risk, eliminates wasted DB work.

**Graceful shutdown:** Background tasks check a `shutdown_event: asyncio.Event` on each loop iteration. When `SIGTERM` is received, the lifespan context manager sets the event, tasks break out of their sleep loop, and `asyncio.gather(*tasks)` awaits completion with a 5-second timeout before force-cancellation.

```python
# Cleanup task pattern
# Cleanup queries are explicit per-table — no string interpolation for SQL safety.
_CLEANUP_QUERIES = {
    "token_blocklist": text("DELETE FROM token_blocklist WHERE expires_at < :now"),
    "authorization_codes": text("DELETE FROM authorization_codes WHERE expires_at < :now"),
    "device_codes": text("DELETE FROM device_codes WHERE expires_at < :now"),
    "refresh_tokens": text("DELETE FROM refresh_tokens WHERE expires_at < :now"),
}

async def _cleanup_loop(table: str, interval: int,
                        shutdown: asyncio.Event, db_factory):
    query = _CLEANUP_QUERIES[table]  # KeyError = bug, not injection
    while not shutdown.is_set():
        try:
            async with db_factory() as session:
                await session.execute(query, {"now": datetime.now(datetime.UTC)})
                await session.commit()
        except Exception as e:
            logger.warning("cleanup_failed", table=table, error=str(e))
        try:
            await asyncio.wait_for(shutdown.wait(), timeout=interval)
            break  # shutdown signaled
        except asyncio.TimeoutError:
            continue  # normal loop
```

---

## 7. Provider Architecture

All providers are Python `Protocol` classes (decorated `@runtime_checkable`). The server instantiates the configured provider at startup. Providers are injected into services via the dependency container.

**Failure mode: fail-closed.** If any security-critical provider (`PolicyProvider.evaluate()`, `AttestationProvider.attest()`, `HITLProvider.request_approval()`) raises an exception or exceeds `AUTHGENT_PROVIDER_TIMEOUT` (default: 10s), the request is **denied**, not allowed. This is enforced by wrapping provider calls in `asyncio.wait_for()` with a catch-all that raises `InternalError` (500). Non-security providers (`EventEmitter`) fail-open — a broken audit emitter must not block token issuance.

### 7.1 Provider Registry

```python
# dependencies.py
from authgent_server.providers.protocols import (
    AttestationProvider, PolicyProvider, HITLProvider,
    KeyProvider, EventEmitter,
)

def get_providers(settings: Settings) -> ProviderSet:
    """Instantiate providers based on config. Returns frozen set."""
    return ProviderSet(
        attestation=_load_provider(settings.attestation_provider, NullAttestationProvider, settings),
        policy=_load_provider(settings.policy_provider, ScopePolicyProvider, settings),
        hitl=_load_provider(settings.hitl_provider, WebhookHITLProvider, settings),
        keys=_load_provider(settings.key_provider, DatabaseKeyProvider, settings),
        events=_load_provider(settings.event_emitter, DatabaseEventEmitter, settings),
    )

def _load_provider(dotted_path: str | None, default: type, settings: Settings,
                   protocol: type | None = None) -> Any:
    """Import and instantiate provider from dotted path, or use default.
    If the class has a `from_settings(settings)` classmethod, use it.
    Otherwise, try passing settings as first arg; fall back to no-arg.
    If protocol is given, validates conformance at startup (D1)."""
    cls = default if not dotted_path else _import_class(dotted_path)
    if hasattr(cls, "from_settings"):
        instance = cls.from_settings(settings)
    else:
        try:
            instance = cls(settings)
        except TypeError:
            instance = cls()
    # D1: Fail fast if provider doesn't satisfy Protocol
    if protocol and not isinstance(instance, protocol):
        raise TypeError(
            f"{cls.__name__} does not satisfy {protocol.__name__}. "
            f"Check method signatures match the Protocol definition."
        )
    return instance

def _import_class(dotted_path: str) -> type:
    module_path, class_name = dotted_path.rsplit(".", 1)
    module = importlib.import_module(module_path)
    return getattr(module, class_name)
```

Config example:
```bash
AUTHGENT_POLICY_PROVIDER=myapp.policies.OPAPolicyProvider
AUTHGENT_HITL_PROVIDER=authgent_server.providers.hitl.WebhookHITLProvider
```

---

## 8. Error Handling

All errors return RFC 9457 Problem Details JSON:

```json
{
  "type": "https://authgent.dev/errors/invalid-grant",
  "title": "Invalid Grant",
  "status": 400,
  "detail": "Authorization code has already been used",
  "instance": "/token"
}
```

### 8.1 Error Hierarchy

```python
class AuthgentError(Exception):
    type_uri: str
    status_code: int
    title: str
    error_code: str   # stable machine-readable code for SDK programmatic handling

class InvalidGrant(AuthgentError):         # 400, error_code="invalid_grant"
class InvalidClient(AuthgentError):        # 401, error_code="invalid_client"
class InsufficientScope(AuthgentError):    # 403, error_code="insufficient_scope"
class InvalidRequest(AuthgentError):       # 400, error_code="invalid_request"
class UnsupportedGrantType(AuthgentError): # 400, error_code="unsupported_grant_type"
class InvalidDPoPProof(AuthgentError):     # 401, error_code="invalid_dpop_proof"
class UseDPoPNonce(AuthgentError):         # 401, error_code="use_dpop_nonce"
class DelegationDepthExceeded(AuthgentError): # 403, error_code="delegation_depth_exceeded"
class ScopeEscalation(AuthgentError):      # 403, error_code="scope_escalation"
class MayActViolation(AuthgentError):      # 403, error_code="may_act_violation"
class TokenRevoked(AuthgentError):         # 401, error_code="token_revoked"
class StepUpRequired(AuthgentError):       # 403, error_code="step_up_required"
```

The `error_code` field is included in every error response JSON alongside the RFC 9457 `type` URI. SDKs switch on `error_code` for programmatic retry/escalation logic without parsing URIs.

OAuth error responses follow RFC 6749 §5.2 format (`error`, `error_description`) at the `/token` endpoint. All other endpoints use RFC 9457.

---

## 9. Configuration Architecture

### 9.1 Key Derivation

`AUTHGENT_SECRET_KEY` is the single master secret. To avoid the crypto anti-pattern of using one key for multiple purposes (HMAC nonces, CSRF, session cookies, key encryption), we derive **purpose-specific subkeys** using HKDF (RFC 5869):

```python
# crypto.py
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.hashes import SHA256

def derive_subkey(master: bytes, purpose: str, length: int = 32) -> bytes:
    """Derive a purpose-specific key from the master secret."""
    return HKDF(
        algorithm=SHA256(), length=length,
        info=f"authgent-{purpose}".encode(),
        salt=None,  # deterministic derivation
    ).derive(master)

# Usage in Settings post-init:
# self._dpop_key    = derive_subkey(master, "dpop-nonce")
# self._csrf_key    = derive_subkey(master, "csrf")
# self._session_key = derive_subkey(master, "session")
# self._kek_key     = derive_subkey(master, "kek")  # key-encryption-key for signing_keys at rest
```

If the CSRF key leaks (e.g., debug log of a derivation), the DPoP nonce key, session key, and KEK remain safe. Zero UX change — operators still configure a single `AUTHGENT_SECRET_KEY`.

### 9.2 Settings

```python
# config.py
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="AUTHGENT_")

    # Core
    secret_key: str = Field(default_factory=lambda: secrets.token_hex(32))
    database_url: str = "sqlite+aiosqlite:///./authgent.db"
    host: str = "0.0.0.0"
    port: int = 8000
    debug: bool = False

    # Token TTLs (global defaults)
    access_token_ttl: int = 900           # 15 min
    refresh_token_ttl: int = 86400        # 24 hours
    exchange_token_ttl: int = 300         # 5 min
    authorization_code_ttl: int = 600     # 10 min
    # Per-grant TTL overrides (None = use access_token_ttl)
    client_credentials_ttl: int | None = None  # e.g. 300 for shorter M2M tokens
    auth_code_access_ttl: int | None = None    # e.g. 900 for human-delegated tokens

    # Crypto
    signing_algorithm: str = "ES256"
    jwks_rotation_days: int = 90

    # Policy
    registration_policy: Literal["open", "token", "admin"] = "open"
    consent_mode: Literal["ui", "headless", "auto_approve"] = "ui"
    max_delegation_depth: int = 5
    delegation_scope_reduction: bool = True
    require_dpop: bool = False
    dpop_chain_policy: Literal["strict", "audit", "permissive"] = "strict"
    jwks_auto_rotate: bool = True       # False = CLI-only rotation (safer for production)

    # Provider failure timeout (§7 fail-closed policy)
    provider_timeout: int = 10          # seconds; provider calls exceeding this → deny

    # RFC 8707 resource matching algorithm
    resource_match: Literal["exact", "origin"] = "exact"
    # exact:  https://api.example.com/ matches only https://api.example.com/
    # origin: https://api.example.com/ matches https://api.example.com/v1/tools
    #         (scheme + host + port must match; path is prefix-matched)
    # Note: RFC 8707 leaves matching to implementations. We default to exact
    # for security (principle of least authority). Origin mode is opt-in for
    # deployments with versioned MCP server paths.

    # Security
    cors_origins: list[str] = Field(default_factory=list)
    hitl_timeout: int = 300
    hitl_scopes: list[str] = Field(default_factory=list)

    # Rate limiting (per client_id on /token endpoint)
    token_rate_limit: int = 100          # requests per minute per client_id
    register_rate_limit: int = 10        # requests per minute per IP

    # Webhook security (for HITLProvider callbacks)
    webhook_hmac_secret: str | None = None  # HMAC-SHA256 signing of webhook payloads
    webhook_retries: int = 3                 # retry count for failed webhooks
    webhook_backoff: str = "1,5,30"           # comma-separated seconds between retries

    # Cross-audience scope mapping for token exchange (§4.3 step 4)
    # JSON file path or inline JSON: {"agent:db-reader": {"db:read": "data:read"}}
    scope_mappings: str | None = None

    # Custom grant type handlers (§5.2 GrantHandler Protocol)
    custom_grant_handlers: dict[str, str] | None = None

    # External OIDC trust for id_token exchange (§4.7)
    trusted_oidc_issuers: list[str] = Field(default_factory=list)
    # Comma-separated issuer URLs: "https://dev-abc.us.auth0.com/,https://clerk.example.com"
    trusted_oidc_audience: str | None = None
    # Expected `aud` claim in external id_tokens (your app's client_id at the IdP)

    # Providers (dotted import paths, None = use default)
    attestation_provider: str | None = None
    policy_provider: str | None = None
    hitl_provider: str | None = None
    key_provider: str | None = None
    event_emitter: str | None = None
```

> **Future:** Platform layer settings (Gateway port, Vault timeouts, Dashboard toggle) will be added when those layers are implemented. See [ROADMAP.md](ROADMAP.md).

---

## 10. Deployment Architecture

### 10.1 Development (Zero Config)

```bash
pip install authgent-server
authgent-server run           # auto-initializes on first run, starts on :8000 with SQLite
```

### 10.2 Production (Docker)

```yaml
# docker-compose.yml
services:
  authgent:
    image: authgent/server:latest
    ports: ["8000:8000"]
    environment:
      AUTHGENT_DATABASE_URL: postgresql+asyncpg://user:pass@db:5432/authgent
      AUTHGENT_SECRET_KEY: ${SECRET_KEY}
      AUTHGENT_CORS_ORIGINS: '["https://app.example.com"]'
      AUTHGENT_REQUIRE_DPOP: "true"
      AUTHGENT_REGISTRATION_POLICY: token
    depends_on: [db]

  db:
    image: postgres:16-alpine
    environment:
      POSTGRES_DB: authgent
      POSTGRES_USER: user
      POSTGRES_PASSWORD: ${DB_PASSWORD}
    volumes: ["pgdata:/var/lib/postgresql/data"]

volumes:
  pgdata:
```

### 10.3 Dockerfile

```dockerfile
FROM python:3.12-slim
WORKDIR /app
COPY pyproject.toml .
RUN pip install --no-cache-dir .[postgres]
COPY authgent_server/ authgent_server/
EXPOSE 8000
CMD ["uvicorn", "authgent_server.app:create_app", "--factory", "--host", "0.0.0.0", "--port", "8000"]
```

### 10.4 Production Topology

```
                    ┌─────────────┐
                    │  Load       │
                    │  Balancer   │
                    │  (Caddy/    │
                    │   Nginx)    │
                    └──────┬──────┘
                           │
              ┌────────────┼────────────┐
              ▼            ▼            ▼
     ┌────────────┐ ┌────────────┐ ┌────────────┐
     │ authgent   │ │ authgent   │ │ authgent   │
     │ :8000      │ │ :8000      │ │ :8000      │
     └──────┬─────┘ └──────┬─────┘ └──────┬─────┘
            │              │              │
            └──────────────┼──────────────┘
                           │
                    ┌──────▼──────┐
                    │ PostgreSQL  │
                    │ (primary)   │
                    └─────────────┘
```

Horizontal scaling works because:
- JWT validation is stateless (JWKS cached in each instance)
- All state is in PostgreSQL
- No sticky sessions needed
- DPoP nonces are HMAC-based and stateless (§5.5) — no DB coordination needed

---

## 11. SDK Architecture (Validator Side)

### 11.1 Verification Pipeline

The SDK middleware runs this pipeline on every request:

```
Incoming Request
       │
       ▼
1. Extract token from Authorization header
   (Bearer or DPoP scheme)
       │
       ▼
2. verify_token(token, issuer, audience)
   - Fetch JWKS (cached, TTL=5min, auto-refresh on unknown kid)
   - Verify signature (ES256)
   - Verify exp, iat, iss, aud
   - Check token_blocklist (if server URL configured)
       │
       ▼
3. If token has cnf.jkt claim → verify_dpop_proof()
   - Extract DPoP header
   - Verify proof JWT signature matches cnf.jkt
   - Verify htm, htu, iat, ath, nonce
       │
       ▼
4. If token has act claim → parse delegation chain
   - Build DelegationChain object
   - Check depth ≤ max_depth
   - Optionally verify delegation receipts
       │
       ▼
5. PolicyProvider.evaluate(request)
   - Default: scope check only
   - Returns: allow | deny | step_up
       │
       ▼
6. If step_up and scope in HITL_SCOPES:
   - Trigger scope challenge (403 + WWW-Authenticate)
   - SDK auto-calls POST /stepup
   - Polls for approval
   - Retries original request with step-up token
       │
       ▼
7. Attach AgentIdentity to request context
   - identity.subject, identity.scopes, identity.delegation_chain
   - identity.claims (raw), identity.agent_* (OIDC-A)
```

### 11.2 JWKS Cache Strategy

```python
class JWKSFetcher:
    """Fetches and caches JWKS from authgent-server (or any OIDC issuer).
    Uses asyncio.Lock to prevent thundering-herd on concurrent key rotation."""

    def __init__(self, issuer: str, cache_ttl: int = 300):
        self._issuer = issuer
        self._cache_ttl = cache_ttl
        self._keys: dict[str, Any] = {}
        self._last_fetch: float = 0
        self._refresh_lock = asyncio.Lock()

    async def get_key(self, kid: str) -> Any:
        if kid in self._keys and not self._is_stale():
            return self._keys[kid]

        # Refresh: fetch from {issuer}/.well-known/jwks.json
        await self._refresh()

        if kid not in self._keys:
            # Key rotation: one forced re-fetch
            await self._refresh(force=True)

        if kid not in self._keys:
            raise InvalidToken(f"Unknown signing key: {kid}")

        return self._keys[kid]

    async def _refresh(self, force: bool = False) -> None:
        async with self._refresh_lock:
            # Double-check after acquiring lock — another coroutine may have refreshed
            if not force and not self._is_stale():
                return
            async with httpx.AsyncClient() as client:
                resp = await client.get(f"{self._issuer}/.well-known/jwks.json")
                resp.raise_for_status()
                jwks = resp.json()
            self._keys = {k["kid"]: k for k in jwks.get("keys", [])}
            self._last_fetch = time.monotonic()
```

---

## 12. Testing Architecture

### 12.1 Test Pyramid

```
        ┌─────────────┐
        │   E2E Tests  │  (Phase 5: authgent-conformance)
        │   ~10 tests  │  Full Docker Compose, real HTTP
        └──────┬──────┘
               │
        ┌──────▼──────┐
        │ Integration  │  FastAPI TestClient + in-memory SQLite
        │  ~50 tests   │  Tests full request→response cycle
        └──────┬──────┘
               │
        ┌──────▼──────┐
        │  Unit Tests  │  Service layer with mocked DB session
        │  ~150 tests  │  Pure logic: token construction, chain
        └──────┬──────┘  │  validation, scope reduction, DPoP
               │
        ┌──────▼──────┐
        │  Security    │  Specific attack vectors
        │  ~30 tests   │  Forgery, replay, escalation, splicing
        └─────────────┘
```

### 12.2 Test Fixtures

```python
# conftest.py
@pytest.fixture
async def db_session():
    """In-memory SQLite async session."""
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    session_factory = async_sessionmaker(engine, expire_on_commit=False)
    async with session_factory() as session:
        yield session

@pytest.fixture
def test_client(db_session):
    """FastAPI test client with overridden DB dependency."""
    async def override_get_db():
        yield db_session       # async generator matching get_db's signature

    app = create_app()
    app.dependency_overrides[get_db] = override_get_db
    return TestClient(app)

@pytest.fixture
def test_keys():
    """Pre-generated ES256 key pair for deterministic tests."""
    private_key = ec.generate_private_key(ec.SECP256R1())
    return {"private": private_key, "public": private_key.public_key()}
```

---

## 13. Security Architecture Summary

### 13.1 Token Security Layers

```
Layer 1: Signature (ES256)
  └── Cannot forge tokens without private key

Layer 2: Audience binding (RFC 8707)
  └── Token for MCP-server-A rejected at MCP-server-B

Layer 3: DPoP (RFC 9449)
  └── Stolen token useless without ephemeral private key

Layer 4: DPoP Nonce
  └── Precomputed proofs rejected (server-controlled nonce)

Layer 5: Short TTL (15 min)
  └── Limits window of compromised token

Layer 6: Refresh token rotation
  └── Replay detected → entire family revoked

Layer 7: Scope reduction on exchange
  └── Downstream agent cannot escalate privileges

Layer 8: Delegation receipts
  └── Chain splicing detected via signed chain_hash

Layer 9: HITL step-up
  └── Sensitive actions require human approval

Layer 10: Provider fail-closed
  └── Provider timeout/error → deny (never fail-open)
```

**Known limitation: DPoP downgrade in delegation chains.** When `require_dpop=true` and Agent A (DPoP-bound) delegates to Agent B (which does not support DPoP), the token issued to Agent B is a bearer token. If that bearer token is stolen, the DPoP sender-constraint established at hop 1 provides no protection at hop 2. Mitigation options (configurable via `AUTHGENT_DPOP_CHAIN_POLICY`):

| Policy | Behavior | When |
|---|---|---|
| `strict` (default when `require_dpop=true`) | Reject token exchange if target client has `dpop_bound_access_tokens=false` | High-security deployments |
| `audit` | Allow exchange but record `dpop_downgrade` flag in delegation receipt | Gradual rollout |
| `permissive` | Allow silently (current implicit behavior when `require_dpop=false`) | Dev/mixed environments |

**Token size with deep delegation chains:** Nested `act` claims (5 levels), OIDC-A claims, delegation receipts, and custom ClaimEnricher output can push JWTs beyond typical reverse proxy header limits (Nginx default: 8KB). Operators with `max_delegation_depth > 3` should verify `proxy_buffer_size` / `large_client_header_buffers` settings. The SDK `verify_token()` logs a warning if the decoded token exceeds 4KB.

### 13.2 Consent Page Security

The authorization code flow requires a browser-based consent page. This introduces two web security concerns that are distinct from the API token security model:

#### 13.2.1 Human Authentication

Before showing the consent page, the server must establish *who the human is*. Three modes, selected by `AUTHGENT_HUMAN_AUTH_MODE`:

| Mode | When | How |
|---|---|---|
| `builtin` (default) | Dev, small teams | Username/password stored in `users` table (bcrypt). Login page at `GET /login`. Session cookie issued on success. |
| `external_oidc` | Enterprise (Phase 2) | Redirect to external IdP (Auth0/Okta/AAD) via standard OIDC. `AUTHGENT_EXTERNAL_OIDC_ISSUER` + `CLIENT_ID` + `CLIENT_SECRET` config. Server validates ID token and creates session. |
| `api_key` | Headless/testing | `AUTHGENT_CONSENT_MODE=auto_approve` — no human authentication needed. Only for dev environments. |

**`users` table** (required for `builtin` mode):

```
users
├── id                    VARCHAR(26) PK        -- ULID
├── username              VARCHAR(255) UNIQUE NOT NULL
├── password_hash         VARCHAR(512) NOT NULL -- bcrypt (cost 12)
├── email                 VARCHAR(255)
├── status                VARCHAR(20) DEFAULT 'active'  -- active|suspended
├── failed_attempts       INT DEFAULT 0          -- brute-force protection
├── locked_until           TIMESTAMP              -- NULL = not locked
├── created_at            TIMESTAMP NOT NULL
└── updated_at            TIMESTAMP NOT NULL
```

**Brute-force protection:** After 5 consecutive failed login attempts, the account is locked for `2^(attempts-5)` minutes (exponential backoff: 1min, 2min, 4min, 8min..., capped at 60min). `failed_attempts` resets to 0 on successful login. MFA is deferred to Phase 2 `external_oidc` mode where the external IdP handles it.

In `external_oidc` mode, the `users` table is not used — the human identity comes from the external IdP's ID token `sub` claim. A future `HumanAuthProvider` protocol (§18.6) abstracts this for custom SSO (LDAP, SAML, etc.).

**Session semantics:** Sessions are **stateless signed cookies** (HMAC-SHA256 of `user_id:timestamp` using `AUTHGENT_SECRET_KEY`, 30-min TTL). This means:
- Sessions **cannot be individually revoked** — they expire by TTL only
- There is **no server-side session storage** — no `sessions` table
- The `session_id` used in CSRF tokens is derived from the cookie's `user_id:timestamp` hash
- This is acceptable for short-lived consent flows; it is NOT the mechanism for agent tokens

NOT the same as agent tokens — this is a lightweight browser session for the consent flow only.

#### 13.2.2 CSRF Protection

The consent form (`POST /authorize`) is a state-changing browser POST — classic CSRF target.

```python
# endpoints/authorize.py
def _generate_csrf_token(session_id: str) -> str:
    """HMAC(secret_key, session_id + timestamp). Embedded in consent form as hidden field."""
    ts = str(int(time.time()))
    sig = hmac.new(settings._csrf_key, f"{session_id}:{ts}".encode(), hashlib.sha256).hexdigest()  # HKDF-derived (§9.1)
    return f"{ts}.{sig}"

def _validate_csrf_token(token: str, session_id: str, max_age: int = 600) -> bool:
    """Verify CSRF token matches session and is within max_age seconds."""
    try:
        ts, sig = token.split(".", 1)
        if int(time.time()) - int(ts) > max_age:
            return False
    except (ValueError, TypeError):
        return False  # malformed token → reject, not 500
    expected = hmac.new(settings._csrf_key, f"{session_id}:{ts}".encode(), hashlib.sha256).hexdigest()  # HKDF-derived (§9.1)
    return hmac.compare_digest(sig, expected)
```

The consent HTML template includes `<input type="hidden" name="csrf_token" value="{{ csrf_token }}">`. The `POST /authorize` endpoint validates the CSRF token before processing consent.

#### 13.2.3 Content-Type Enforcement

The `/token` endpoint enforces `Content-Type: application/x-www-form-urlencoded` per OAuth 2.1 spec. JSON bodies are rejected with `415 Unsupported Media Type`. This prevents CSRF via `fetch()` with JSON (browsers enforce CORS preflight for non-simple content types).

### 13.3 Secrets Management

| Secret | Storage | Protection |
|---|---|---|
| Signing private keys | `signing_keys.private_key_pem` | AES-256-GCM encrypted, key from HKDF-derived KEK subkey (§9.1) |
| Client secrets | `oauth_clients.client_secret_hash` | bcrypt (cost 12), timing-safe comparison |
| `AUTHGENT_SECRET_KEY` | Environment variable | Never logged, never in DB |
| DPoP ephemeral keys | Client memory only | Never transmitted, never stored |
| Refresh tokens | `refresh_tokens` table | JTI-indexed, one-time-use, family-tracked |
| Consent session | Signed cookie | HMAC-SHA256 with HKDF-derived session subkey (§9.1). `HttpOnly`, `Secure`, `SameSite=Lax`. |

---

## 14. Input Validation & Request Security

All inbound data passes through Pydantic schemas with strict validators before reaching the service layer.

### 14.1 Global Constraints

```python
# schemas/common.py
MAX_STRING_LENGTH = 2048          # all string fields capped
MAX_SCOPE_LENGTH = 512            # scope parameter
MAX_REDIRECT_URIS = 10           # per client registration
SCOPE_PATTERN = re.compile(r"^[a-zA-Z0-9_:.\-]+$")  # no injection
```

### 14.2 Redirect URI Validation

Redirect URIs are the #1 OAuth attack vector (open redirect → code theft). Validation rules:
1. **Exact match only** — registered URI must match byte-for-byte. No wildcards, no path traversal, no fragment.
2. **HTTPS required** in production — `http://localhost` and `http://127.0.0.1` allowed only when `AUTHGENT_CONSENT_MODE=auto_approve` (dev).
3. **No IP addresses** in production (except loopback) — prevents DNS rebinding.
4. **No query parameters** in registered URIs — the server appends `code` and `state`.

```python
# schemas/client.py
class RegisterRequest(BaseModel):
    redirect_uris: list[AnyHttpUrl] = Field(max_length=MAX_REDIRECT_URIS)
    scope: str = Field(max_length=MAX_SCOPE_LENGTH)

    @field_validator("redirect_uris")
    @classmethod
    def validate_redirect_uris(cls, uris: list[AnyHttpUrl]) -> list[AnyHttpUrl]:
        for uri in uris:
            parsed = urlparse(str(uri))
            if parsed.fragment:
                raise ValueError("redirect_uri must not contain a fragment")
            if parsed.query:
                raise ValueError("redirect_uri must not contain query parameters")
            if parsed.scheme != "https" and parsed.hostname not in ("localhost", "127.0.0.1"):
                raise ValueError("redirect_uri must use HTTPS (except localhost)")
        return uris

    @field_validator("scope")
    @classmethod
    def validate_scope(cls, v: str) -> str:
        for s in v.split():
            if not SCOPE_PATTERN.match(s):
                raise ValueError(f"Invalid scope character in: {s}")
        return v
```

### 14.3 Rate Limiting

Rate limits are **per-grant-type** because different grant types have very different legitimate traffic patterns:

| Endpoint / Grant | Key | Default Limit | Rationale |
|---|---|---|---|
| `POST /token` — `client_credentials` | `client_id` | 500/min | Agents legitimately request tokens frequently |
| `POST /token` — `authorization_code` | `client_id` | 50/min | Human-gated, low-volume |
| `POST /token` — `refresh_token` | `client_id` | 50/min | Human-gated |
| `POST /token` — `token-exchange` | `client_id` | 200/min | Delegation chains can be chatty |
| `POST /register` | IP address | 10/min | Prevents mass registration |
| `GET /.well-known/*` | IP address | 1000/min | Generous — legitimate high-traffic |

Implementation: In-memory sliding window counter (`dict[str, deque[float]]`). Resets on restart (acceptable — persistent rate limiting is a reverse proxy concern). Returns **429 Too Many Requests** with `Retry-After` header.

```python
# middleware/rate_limit.py
class RateLimitMiddleware:
    MAX_KEYS = 10_000  # prevent memory DoS from many unique IPs/client_ids

    def __init__(self, app, rate: int, window: int = 60, key_func=None):
        self.rate = rate
        self.window = window
        self.key_func = key_func or (lambda r: r.client.host)
        self._counters: dict[str, deque[float]] = defaultdict(deque)

    def _evict_stale(self, now: float) -> None:
        """Remove keys whose newest timestamp is older than the window.
        Called periodically (every 100 requests) to bound memory."""
        cutoff = now - self.window
        stale = [k for k, v in self._counters.items() if not v or v[-1] < cutoff]
        for k in stale:
            del self._counters[k]
        # Hard cap: if still over MAX_KEYS, drop oldest
        if len(self._counters) > self.MAX_KEYS:
            excess = len(self._counters) - self.MAX_KEYS
            for k in list(self._counters)[:excess]:
                del self._counters[k]
```

---

## 15. Logging Architecture

### 15.1 Structured Logging

All server logs use `structlog` with JSON output. Every log entry includes:

```python
# app.py (startup)
import structlog

structlog.configure(
    processors=[
        structlog.contextvars.merge_contextvars,
        structlog.processors.add_log_level,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.JSONRenderer(),
    ],
    wrapper_class=structlog.make_filtering_bound_logger(logging.INFO),
)
```

### 15.2 Contextual Fields

Every request automatically binds:

| Field | Source | Example |
|---|---|---|
| `request_id` | `X-Request-ID` header or generated ULID | `01HWXYZ...` |
| `trace_id` | `traceparent` header (W3C) or generated | `4bf92f3577b34da6a3ce929d0e0e4736` |
| `client_id` | Token or request body | `01HW...` |
| `grant_type` | `/token` requests | `client_credentials` |
| `endpoint` | Route path | `POST /token` |
| `status_code` | Response | `200` |
| `duration_ms` | Request processing time | `12.4` |

### 15.3 Never-Log List

These values are **never written to logs** at any level, enforced by a `structlog` processor that redacts matching keys:

- `client_secret`, `client_secret_hash`
- `access_token`, `refresh_token`, `subject_token` (log JTI only)
- `private_key_pem`, `secret_key`
- `code_verifier`, `authorization_code`
- `DPoP` header value (log JWK thumbprint only)
- `password`, `password_hash` (consent page user auth)

```python
# middleware/logging.py
REDACTED_KEYS = {"client_secret", "access_token", "refresh_token",
                 "subject_token", "private_key_pem", "secret_key",
                 "code_verifier", "authorization_code",
                 "password", "password_hash"}

def redact_secrets(logger, method_name, event_dict):
    for key in REDACTED_KEYS:
        if key in event_dict:
            event_dict[key] = "[REDACTED]"
    return event_dict
```

---

## 16. Migration & Schema Lifecycle

### 16.1 Fresh Install

`authgent-server run` auto-initializes on first start — no separate init step needed. This is the fastest path for new users.

```bash
authgent-server run
# On first run:
# 1. Generates .env with random AUTHGENT_SECRET_KEY (if no .env and no env var)
# 2. Creates DB file (SQLite) or connects to DATABASE_URL
# 3. Runs Base.metadata.create_all() — creates all tables
# 4. Generates initial ES256 signing key
# 5. Starts serving on :8000
#
# Use `authgent-server init` explicitly for custom DB URL or force-regenerate.
```

### 16.2 Startup Schema Check

`authgent-server run` checks the schema version on every startup:

```python
async def check_schema_version(engine):
    """Compare DB schema against expected version. Refuse to start if behind."""
    async with engine.begin() as conn:
        # Check alembic_version table
        result = await conn.execute(text("SELECT version_num FROM alembic_version"))
        current = result.scalar_one_or_none()
    if current != EXPECTED_SCHEMA_VERSION:
        raise SystemExit(
            f"Schema version mismatch: DB={current}, expected={EXPECTED_SCHEMA_VERSION}. "
            f"Run: authgent-server migrate"
        )
```

### 16.3 Upgrade Path

Alembic migrations are used **only for upgrades between released versions**, not for initial setup:

```bash
authgent-server migrate           # runs alembic upgrade head
authgent-server migrate --dry-run # shows SQL without executing
```

Each release tags a migration version. Auto-migration on startup is explicitly **not supported** — too dangerous for production databases.

---

## 17. Server Lifecycle & Graceful Shutdown

### 17.1 Lifespan Context Manager

```python
# app.py
from contextlib import asynccontextmanager

@asynccontextmanager
async def lifespan(app: FastAPI):
    # ── STARTUP ──
    settings = get_settings()
    await check_schema_version(engine)

    # Start background cleanup tasks
    shutdown_event = asyncio.Event()
    cleanup_tasks = [
        asyncio.create_task(_cleanup_loop("token_blocklist", ...)),
        asyncio.create_task(_cleanup_loop("authorization_codes", ...)),
        asyncio.create_task(_cleanup_loop("device_codes", ...)),
        asyncio.create_task(_cleanup_loop("stepup_requests", ...)),
        asyncio.create_task(_cleanup_loop("refresh_tokens", ...)),
    ]

    logger.info("server_started", host=settings.host, port=settings.port)
    yield  # ── SERVER RUNNING ──

    # ── SHUTDOWN ──
    logger.info("server_shutting_down")
    shutdown_event.set()                              # signal all cleanup tasks
    done, pending = await asyncio.wait(cleanup_tasks, timeout=5.0)
    for task in pending:
        task.cancel()                                 # force-cancel stragglers
    await engine.dispose()                            # drain DB pool
    logger.info("server_stopped")

app = FastAPI(lifespan=lifespan)
```

### 17.2 Shutdown Behavior

| Signal | Behavior |
|---|---|
| `SIGTERM` | Uvicorn triggers lifespan exit. In-flight requests complete (Uvicorn's `--timeout-graceful-shutdown`, default 30s). Background tasks cancelled. DB pool drained. |
| `SIGINT` (Ctrl+C) | Same as SIGTERM in production. In dev, immediate exit is acceptable. |
| Health probes | `/ready` returns 503 during shutdown (lifespan exit started). `/health` remains 200 until process exits. |

---

## 18. Extensibility Architecture

### 18.1 ClaimEnricher Protocol

A 6th provider interface that lets users inject custom claims into tokens at issuance time, without forking `TokenService`:

```python
class ReadOnlyDataAccess(Protocol):
    """Read-only interface passed to ClaimEnricher for DB lookups.
    Prevents enrichers from mutating state while allowing tenant/org queries.
    No raw SQL — only typed accessor methods to prevent injection."""
    async def get_agent(self, agent_id: str) -> Agent | None: ...
    async def get_client(self, client_id: str) -> OAuthClient | None: ...
    async def get_consent(self, subject: str, client_id: str) -> Consent | None: ...

class ClaimEnricher(Protocol):
    async def enrich(
        self, base_claims: dict,
        client: OAuthClient,
        agent: Agent | None,
        grant_type: str,
        data_access: ReadOnlyDataAccess | None = None,
    ) -> dict:
        """Return base_claims with additional fields merged in.
        Must NOT remove or modify existing standard claims (iss, sub, aud, exp, iat, jti).
        Common uses: tenant_id, department, custom metadata, feature flags.
        data_access provides read-only DB queries for enrichers that need
        external state (e.g., tenant lookup, org hierarchy)."""
        ...

# Default: NoOpClaimEnricher (returns base_claims unchanged)
```

Config: `AUTHGENT_CLAIM_ENRICHER=myapp.claims.TenantClaimEnricher`

### 18.2 Webhook Security for HITLProvider

The default `WebhookHITLProvider` signs all outbound webhook payloads with HMAC-SHA256 so receivers can verify authenticity:

```python
class WebhookHITLProvider:
    async def request_approval(self, ...) -> str:
        payload = json.dumps({...})
        signature = hmac.new(
            settings.webhook_hmac_secret.encode(),
            payload.encode(), "sha256"
        ).hexdigest()
        headers = {
            "Content-Type": "application/json",
            "X-Authgent-Signature": f"sha256={signature}",
            "X-Authgent-Timestamp": str(int(time.time())),
        }
        # Retry with exponential backoff: 1s, 5s, 30s
        ...
```

**Idempotent delivery:** Every webhook includes `X-Authgent-Delivery-Id` (ULID) for receiver-side deduplication. Receivers should store seen delivery IDs and reject duplicates.

Receivers verify: `HMAC(secret, timestamp + "." + body) == signature`. Timestamp checked within 5-minute window to prevent replay. Delivery ID prevents re-acceptance within the timestamp window.

### 18.3 EventEmitter Webhook Mode

Beyond database audit logging, `EventEmitter` supports a webhook mode for SIEM integration:

```python
class WebhookEventEmitter(EventEmitter):
    """Fires HTTP POST on security-critical events."""
    EVENTS = [
        "token.replay_detected",       # refresh token reuse
        "delegation.depth_exceeded",    # chain too deep
        "agent.suspended",              # agent lifecycle
        "key.rotated",                  # signing key rotation
        "stepup.approved",              # HITL approval
        "stepup.denied",               # HITL denial
    ]
```

Config: `AUTHGENT_EVENT_EMITTER=authgent_server.providers.events.WebhookEventEmitter`

### 18.4 Token Format Abstraction (v2 Design Note)

The current architecture is JWT-only. The service layer should not hard-couple to JWT format. For v2, a `TokenFormat` abstraction enables:
- **Opaque tokens** (reference tokens requiring introspection) — some enterprises mandate this
- **Transaction Tokens** (draft-oauth-transaction-tokens) — for agent workloads
- The `JWKSService.sign_jwt()` method would become `TokenFormatter.create()` with a strategy pattern

This is a **v2 concern** — JWT is correct for v1. But `TokenService` should call `JWKSService` through a thin interface, not directly construct JWT strings, to make the future migration non-breaking.

### 18.5 SDK Plugin Pipeline (v2 Design Note)

The Python SDK middleware is currently monolithic. For v2, a composable plugin pattern:

```python
# v2 SDK middleware pattern
middleware = AgentAuthMiddleware(
    issuer="...",
    plugins=[
        DPoPPlugin(),
        DelegationPlugin(max_depth=3),
        RateLimitPlugin(rpm=100),
        CustomPlugin(),
    ]
)
```

For v1, the monolithic middleware is simpler and correct. The plugin boundary is designed in (each verification step is a separate method on the middleware class) so refactoring to plugins in v2 is mechanical.

### 18.6 HumanAuthProvider Protocol (7th Provider)

§13.2.1 defines three human authentication modes (`builtin`, `external_oidc`, `api_key`) as config options. To support custom SSO integrations (LDAP, SAML, enterprise-specific) without forking `endpoints/authorize.py`, human auth is abstracted as the 7th pluggable provider:

```python
class HumanAuthProvider(Protocol):
    async def authenticate(self, request: Request) -> HumanIdentity | None:
        """Authenticate the human from the HTTP request (cookies, headers, etc.).
        Returns HumanIdentity(user_id, username, email) or None if not authenticated."""
        ...

    async def login_redirect(self, request: Request, next_url: str) -> Response:
        """Return redirect response to login page/IdP.
        Called when authenticate() returns None."""
        ...

    async def handle_callback(self, request: Request) -> HumanIdentity:
        """Handle login callback (form POST for builtin, OIDC callback for external).
        Returns authenticated HumanIdentity."""
        ...
```

Defaults: `BuiltinHumanAuthProvider` (username/password + `users` table), `ExternalOIDCHumanAuthProvider` (Phase 2), `AutoApproveProvider` (dev only — skips human auth entirely).

Config: `AUTHGENT_HUMAN_AUTH_PROVIDER=myapp.auth.SAMLHumanAuthProvider`

### 18.7 Transaction Tokens (v2 Design Note)

Transaction Tokens (`draft-oauth-transaction-tokens-for-agents-04`) solve the same delegation problem as RFC 8693 token exchange but with a different model:
- **Workload-scoped** — tied to a transaction, not a client
- Carry both `principal` (human) and `actor` (current service) in a single token
- Being adopted by Amazon/Azure for microservice delegation

For v2, evaluate TxTokens as a **complementary mechanism** to RFC 8693. RFC 8693 is correct for explicit agent-to-agent delegation with signed receipts. TxTokens may suit stateless microservice architectures where the delegation chain is implicit (each service mints a new TxToken for the next hop). The `TokenFormat` abstraction (§18.4) accommodates both.

---

## 19. Health Check Semantics

| Endpoint | Type | Checks | Response |
|---|---|---|---|
| `GET /health` | **Liveness** | Process is running, event loop responsive | `200 {"status": "ok"}` always (unless process dead) |
| `GET /ready` | **Readiness** | DB reachable (`SELECT 1`), signing key exists, schema version matches | `200 {"status": "ready", "db": "ok", "keys": "ok"}` or `503 {"status": "not_ready", "db": "error: ..."}` |

`/ready` returns `503` during startup (before DB check passes) and during shutdown (after lifespan exit begins). Load balancers should probe `/ready`; Kubernetes liveness probes should use `/health`.

---

## 20. Summary

This document describes the **complete, shipped** OAuth 2.1 Authorization Server — the core of authgent. All sections (§3.1–§19) are implemented and tested with 155+ tests across server, Python SDK, and TypeScript SDK.

**What's here:** Agent identity, multi-hop delegation chains with signed receipts, DPoP sender-binding, HITL step-up authorization, 7 pluggable providers, full OAuth 2.1 grant support, and multi-language SDKs.

**What's next:** Platform layers (MCP Gateway, Credential Vault, AI Framework Integrations, Developer Dashboard) are architecturally designed and documented in [ROADMAP.md](ROADMAP.md), ready for implementation based on user demand.
