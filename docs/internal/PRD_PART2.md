# PRD Part 2: Data Models, SDK Specs, Security, Project Structure & Delivery

*Continuation of PRD.md*

---

## 9. Database Schema

### 9.1 Table: oauth_clients

**Authoritative table for all OAuth credentials.** Not every client is an agent (human MCP clients exist), but every agent gets an `oauth_client` record.

```
client_id                 VARCHAR(255) PK
client_secret_hash        VARCHAR(512) NOT NULL  -- bcrypt
previous_secret_hash      VARCHAR(512)           -- for rotation grace period
previous_secret_expires   TIMESTAMP
client_name               VARCHAR(255)
grant_types               JSON           -- ["client_credentials", "authorization_code"]
redirect_uris             JSON           -- for auth_code flow
scope                     TEXT           -- space-delimited allowed scopes
allowed_resources         JSON           -- RFC 8707: ["https://mcp-server.example.com/"] (distinct from redirect_uris)
may_act_subs              JSON           -- RFC 8693 §4.4: ["agent:search-bot"] — restricts who can exchange tokens issued to this client
metadata_url              TEXT           -- CIMD: URL to client's metadata document (draft-ietf-oauth-client-id-metadata-document)
token_endpoint_auth_method VARCHAR(50)
dpop_bound_access_tokens  BOOLEAN DEFAULT FALSE
agent_id                  VARCHAR(26) FK → agents.id  -- NULL for human MCP clients
created_at                TIMESTAMP NOT NULL
```

### 9.2 Table: agents

Agent identity metadata. Credentials live in `oauth_clients` — linked via `oauth_client_id`.

```
id                        VARCHAR(26) PK        -- ULID
oauth_client_id           VARCHAR(255) UNIQUE FK → oauth_clients.client_id
name                      VARCHAR(255) NOT NULL
description               TEXT
owner                     VARCHAR(255)           -- human or org identifier
allowed_scopes            JSON                   -- ["search:execute", "db:read"]
capabilities              JSON                   -- ["search", "summarize"]
allowed_exchange_targets  JSON                   -- ["agent:db-reader", "agent:search-bot"] — restricts token exchange audiences
status                    VARCHAR(20) DEFAULT 'active'  -- active|inactive|suspended
metadata                  JSON
-- OIDC-A compatible fields (optional, for forward compatibility)
agent_type                VARCHAR(50)            -- autonomous|supervised|interactive
agent_model               VARCHAR(255)           -- e.g. "gpt-4o", "claude-3.5"
agent_version             VARCHAR(50)            -- semantic version of agent code
agent_provider            VARCHAR(255)           -- org that built the agent
-- Agent Bill of Materials (ABOM) — supply-chain auditing
bill_of_materials         JSON                   -- CycloneDX AI-BOM aligned: {"tools": [...], "models": [...], "deps": [...]}
-- Attestation fields (populated by AttestationProvider)
attestation_level         VARCHAR(20)            -- none|self|verified|hardware
code_hash                 VARCHAR(255)           -- SHA-256 of agent binary/image
created_at                TIMESTAMP NOT NULL
updated_at                TIMESTAMP NOT NULL
```

**Design rationale:** Credentials are only in `oauth_clients`. Credential rotation, secret hashing, DPoP binding — all handled through the `oauth_clients` record. The `agents` table is purely identity metadata. This avoids the ambiguity of dual credential storage.

### 9.3 Table: authorization_codes
```
code                      VARCHAR(255) PK
client_id                 VARCHAR(255) FK → oauth_clients
redirect_uri              TEXT NOT NULL
scope                     TEXT
resource                  TEXT                   -- RFC 8707: target MCP server URL (MANDATORY)
code_challenge            VARCHAR(255) NOT NULL
code_challenge_method     VARCHAR(10) DEFAULT 'S256'
subject                   VARCHAR(255)     -- human user identifier
nonce                     VARCHAR(255)           -- OIDC nonce parameter (prevents ID token replay)
expires_at                TIMESTAMP NOT NULL
used                      BOOLEAN DEFAULT FALSE
```

### 9.4 Table: refresh_tokens

OAuth 2.1 requires refresh token rotation (one-time use). Token family tracking enables reuse detection — if a consumed refresh token is replayed, the entire family is revoked.

```
jti                       VARCHAR(255) PK
client_id                 VARCHAR(255) FK → oauth_clients
subject                   VARCHAR(255)           -- human or agent identifier
scope                     TEXT
resource                  TEXT                   -- RFC 8707
family_id                 VARCHAR(255) NOT NULL  -- groups all rotated tokens from same grant
dpop_jkt                  VARCHAR(255)           -- DPoP binding: JWK thumbprint (RFC 9449 §5)
used                      BOOLEAN DEFAULT FALSE  -- set TRUE on rotation
expires_at                TIMESTAMP NOT NULL
created_at                TIMESTAMP NOT NULL
```

**Reuse detection:** On refresh, if `used = TRUE` for the presented JTI, revoke ALL tokens with the same `family_id` (entire token family). This prevents refresh token replay attacks per OAuth 2.1 §6.1.

### 9.5 Table: device_codes

RFC 8628 Device Authorization Grant (Phase 2).

```
device_code               VARCHAR(255) PK
user_code                 VARCHAR(20) UNIQUE NOT NULL  -- short human-typeable code
client_id                 VARCHAR(255) FK → oauth_clients
scope                     TEXT
resource                  TEXT                   -- RFC 8707
status                    VARCHAR(20) DEFAULT 'pending'  -- pending|authorized|denied|expired
subject                   VARCHAR(255)           -- set when human authorizes
interval                  INTEGER DEFAULT 5      -- polling interval in seconds
expires_at                TIMESTAMP NOT NULL
created_at                TIMESTAMP NOT NULL
```

### 9.6 Table: consents

Tracks human consent grants for auth code flow. Prevents re-prompting for already-granted scopes.

```
id                        VARCHAR(26) PK         -- ULID
subject                   VARCHAR(255) NOT NULL  -- human user identifier (local user_id or external IdP sub)
client_id                 VARCHAR(255) FK → oauth_clients
scope                     TEXT NOT NULL          -- space-delimited granted scopes
resource                  TEXT                   -- RFC 8707
granted_at                TIMESTAMP NOT NULL
expires_at                TIMESTAMP              -- NULL = no expiry
UNIQUE(subject, client_id, resource)             -- prevents duplicate consent records
```

Consent upsert uses `INSERT ... ON CONFLICT (subject, client_id, resource) DO UPDATE SET scope = :scope, granted_at = :now` to merge scope grants rather than creating duplicates.

### 9.7 Table: signing_keys
```
kid                       VARCHAR(255) PK
algorithm                 VARCHAR(10) DEFAULT 'ES256'
private_key_pem           TEXT NOT NULL      -- encrypted at rest (AES-256-GCM)
public_key_jwk            JSON NOT NULL      -- published in JWKS
status                    VARCHAR(20) DEFAULT 'active'  -- active|rotated|revoked
created_at                TIMESTAMP NOT NULL
rotated_at                TIMESTAMP
```

### 9.8 Table: token_blocklist
```
jti                       VARCHAR(255) PK
expires_at                TIMESTAMP NOT NULL  -- auto-delete after this
revoked_at                TIMESTAMP NOT NULL
reason                    VARCHAR(50)         -- user_revoke|agent_deactivated|admin
```

### 9.9 Table: audit_log
```
id                        VARCHAR(26) PK     -- ULID
timestamp                 TIMESTAMP NOT NULL
action                    VARCHAR(50) NOT NULL  -- token.issued, token.exchanged, etc.
actor                     VARCHAR(255)
subject                   VARCHAR(255)
client_id                 VARCHAR(255)
ip_address                VARCHAR(45)
trace_id                  VARCHAR(64)          -- W3C Trace Context (OTel propagation)
span_id                   VARCHAR(32)          -- OTel span ID
metadata                  JSON
```

### 9.10 Table: delegation_receipts
```
id                        VARCHAR(26) PK     -- ULID
token_jti                 VARCHAR(255) NOT NULL  -- JTI of the exchanged token
parent_token_jti          VARCHAR(255) NOT NULL  -- JTI of the parent token
actor_id                  VARCHAR(255) NOT NULL  -- agent who performed the exchange
receipt_jwt               TEXT NOT NULL          -- signed receipt (see Security §13)
chain_hash                VARCHAR(255) NOT NULL  -- SHA-256 of full chain up to this point
created_at                TIMESTAMP NOT NULL
```

### 9.11 Table: stepup_requests
```
id                        VARCHAR(26) PK     -- ULID
agent_id                  VARCHAR(255) NOT NULL
action                    VARCHAR(255) NOT NULL  -- the sensitive operation requested
scope                     TEXT NOT NULL          -- OAuth scope being requested (e.g. "db:delete")
resource                  VARCHAR(255)           -- target resource (RFC 8707)
delegation_chain_snapshot JSON                   -- full chain at time of request
status                    VARCHAR(20) DEFAULT 'pending'  -- pending|approved|denied|expired
approved_by               VARCHAR(255)           -- human who approved
approved_at               TIMESTAMP
expires_at                TIMESTAMP NOT NULL
metadata                  JSON
created_at                TIMESTAMP NOT NULL
```

### 9.12 Table: users

Human user accounts for `builtin` HUMAN_AUTH_MODE. Not used in `external_oidc` mode (human identity comes from external IdP's ID token `sub` claim).

```
id                        VARCHAR(26) PK         -- ULID
username                  VARCHAR(255) UNIQUE NOT NULL
password_hash             VARCHAR(512) NOT NULL  -- bcrypt (cost 12)
email                     VARCHAR(255)
status                    VARCHAR(20) DEFAULT 'active'  -- active|suspended
failed_attempts           INT DEFAULT 0          -- brute-force protection
locked_until              TIMESTAMP              -- NULL = not locked; exponential backoff after 5 failures
created_at                TIMESTAMP NOT NULL
updated_at                TIMESTAMP NOT NULL
```

---

## 10. JWT Token Structures

**RFC 9068 Compliance:** All access tokens follow the JWT Profile for OAuth 2.0 Access Tokens (RFC 9068), which standardizes required claims: `iss`, `exp`, `aud`, `sub`, `client_id`, `iat`, `jti`. Our tokens already include all of these.

### 10.1 Standard Access Token (client_credentials)
```json
{
  "iss": "http://localhost:8000",
  "sub": "agent:search-bot",
  "aud": "https://target-api.com",
  "exp": 1711380000,
  "iat": 1711379100,
  "jti": "tok_a1b2c3d4",
  "scope": "search:execute",
  "client_id": "agnt_a1b2c3d4e5f6",
  "cnf": { "jkt": "S256-thumbprint-of-dpop-key" }
}
```

### 10.2 Delegated Token (after token exchange)
```json
{
  "iss": "http://localhost:8000",
  "sub": "user:dhruv@example.com",
  "aud": "agent:database-reader",
  "exp": 1711379400,
  "iat": 1711379100,
  "jti": "tok_e5f6g7h8",
  "scope": "db:read",
  "agent_type": "autonomous",
  "agent_model": "gpt-4o",
  "agent_version": "1.2.0",
  "agent_provider": "acme-corp",
  "agent_instance_id": "agnt_db_reader_01",
  "act": {
    "sub": "agent:search-bot",
    "act": { "sub": "agent:orchestrator" }
  },
  "delegation_purpose": "Summarize Q4 financial data",
  "delegation_constraints": { "expires_in": 300, "resources": ["https://api.example.com/finance"], "operations": ["read"] },
  "delegation_receipt": "eyJ...signed-receipt-from-search-bot..."
}
```

Note: `agent_*` claims follow emerging **OIDC-A** (OpenID Connect for Agents) spec. Optional, populated from agent registry metadata. `delegation_purpose` and `delegation_constraints` are OIDC-A claims that document intended use and operational boundaries for audit/compliance. `delegation_receipt` prevents chain splicing (see §13).

### 10.3 DPoP Proof JWT (sent in DPoP header)
```json
Header: { "typ": "dpop+jwt", "alg": "ES256", "jwk": { "kty": "EC", "crv": "P-256", "x": "...", "y": "..." } }
Payload: { "jti": "proof_id", "htm": "POST", "htu": "https://api.com/tools/search", "iat": 1711379100, "ath": "SHA256-of-access-token", "nonce": "server-provided-nonce" }
```

**DPoP Nonce (RFC 9449 §8):** The server SHOULD support server-provided nonces via the `DPoP-Nonce` response header. When present, clients MUST include the `nonce` value in subsequent DPoP proofs. This prevents precomputed proof attacks — an attacker with access to the DPoP key cannot precompute valid proofs without knowing the server's current nonce. The server returns `400` with `use_dpop_nonce` error if a required nonce is missing or stale.

```
HTTP/1.1 401 Unauthorized
DPoP-Nonce: eyJ0eXAiOiJub25jZSJ9...
WWW-Authenticate: DPoP error="use_dpop_nonce"
```

---

## 11. Python SDK Specification

### 11.1 Core Token Verification (Framework-Agnostic)

```python
from authgent import verify_token, verify_delegation_chain, verify_dpop_proof

# Pure function: verify a JWT
result = await verify_token(
    token="eyJ...",
    issuer="http://localhost:8000",      # or "https://my.auth0.com/"
    audience="https://my-api.com",
)
# result.subject, result.scopes, result.delegation_chain, result.claims

# Pure function: enforce delegation policy
verify_delegation_chain(
    chain=result.delegation_chain,
    max_depth=3,
    allowed_actors=["agent:orchestrator", "agent:search-bot"],
    require_human_root=True,
)

# Pure function: verify DPoP proof
verify_dpop_proof(
    token=result, dpop_proof="eyJ...",
    http_method="POST", http_uri="https://api.com/tools/search",
)
```

### 11.2 Server Client API

```python
from authgent import AgentAuthClient

client = AgentAuthClient(server_url="http://localhost:8000")

agent = await client.register_agent(name="search-bot", scopes=["search:execute"])
token = await client.get_token(client_id=agent.client_id, client_secret=agent.client_secret)
downstream = await client.exchange_token(subject_token=token.access_token, audience="agent:db-reader", scopes=["db:read"])
await client.revoke_token(token.access_token)
```

### 11.3 FastAPI Middleware

```python
from authgent.middleware.fastapi import AgentAuthMiddleware, require_agent_auth, get_agent_identity

app = FastAPI()
app.add_middleware(AgentAuthMiddleware, issuer="http://localhost:8000")

@app.post("/tools/search")
@require_agent_auth(scopes=["search:execute"])
async def search(identity = Depends(get_agent_identity)):
    print(identity.subject, identity.delegation_chain)
```

### 11.4 Flask Middleware

```python
from authgent.middleware.flask import AgentAuthMiddleware, require_agent_auth

app = Flask(__name__)
AgentAuthMiddleware(app, issuer="http://localhost:8000")

@app.route("/tools/search", methods=["POST"])
@require_agent_auth(scopes=["search:execute"])
def search():
    identity = get_agent_identity()
    return {"result": do_search()}
```

### 11.5 MCP Auth Provider Adapter

```python
from authgent.adapters.mcp import AgentAuthProvider
mcp = FastMCP("my-server")
mcp.auth_provider = AgentAuthProvider(server_url="http://localhost:8000")
```

### 11.6 DPoP Client

```python
from authgent.dpop import DPoPClient

dpop = DPoPClient()  # ephemeral key generated in memory
headers = dpop.create_proof_headers(
    access_token=my_token, http_method="POST",
    http_uri="https://api.com/tools/search",
)
# {"Authorization": "DPoP eyJ...", "DPoP": "eyJ..." (proof)}
```

---

## 12. TypeScript SDK Specification

### 12.1 Core API
```typescript
import { verifyToken, verifyDelegationChain } from 'authgent';

const identity = await verifyToken({
  token: 'eyJ...', issuer: 'http://localhost:8000', audience: 'https://my-api.com',
});
verifyDelegationChain({ chain: identity.delegationChain, maxDepth: 3, requireHumanRoot: true });
```

### 12.2 Express Middleware
```typescript
import { agentAuthMiddleware, requireScopes } from 'authgent/middleware/express';

app.use(agentAuthMiddleware({ issuer: 'http://localhost:8000' }));
app.post('/tools/search', requireScopes(['search:execute']), (req, res) => {
  console.log(req.agentIdentity.delegationChain);
});
```

### 12.3 MCP TypeScript Adapter
```typescript
import { AgentAuthProvider } from 'authgent/adapters/mcp';
server.setAuthProvider(new AgentAuthProvider({ serverUrl: 'http://localhost:8000' }));
```

---

## 13. Security Architecture

### 13.1 Threat Model

| Threat | Mitigation |
|---|---|
| Token leaked from agent logs | DPoP: token useless without sender's private key |
| Token replay from network | DPoP proofs include htm + htu (method + URL bound) |
| Confused deputy (agent exceeds scope) | Scope reduction on exchange: downstream ≤ parent scopes |
| Infinite delegation chains | `AUTHGENT_MAX_DELEGATION_DEPTH` (default: 5) |
| Stolen client_secret | bcrypt-hashed in DB. Never logged. Rotation with grace period |
| Signing key compromise | Encrypted at rest. Auto-rotation 90 days. Manual rotation via CLI |
| Prompt injection reads token | DPoP + short TTL (15min) limits damage |
| Full RCE on agent host | **Honest: DPoP doesn't help here.** Mitigations: ephemeral keys, short TTLs, pluggable KeyProvider for HSM/KMS. Documented in threat model. |
| **Delegation chain splicing** | **Signed delegation receipts** (see §11.3 below) |
| Agent impersonation | Pluggable `AttestationProvider` for code hash / TEE verification |
| Precomputed DPoP proofs | **DPoP-Nonce** (RFC 9449 §8): server-provided nonces prevent precomputation |
| Sensitive action without human consent | HITL step-up authorization via `HITLProvider` |

### 13.3 Delegation Chain Splicing Attack & Mitigation

**The Attack:** There is an active IETF discussion about a vulnerability in RFC 8693's `act` claim nesting. The attack: a malicious agent takes a legitimately issued token with `act` claims, strips or modifies intermediate actors, and presents a spliced chain that omits a compromised hop. Since `act` claims are just nested JSON — not individually signed — the receiver cannot verify that each hop was actually authorized by the previous actor.

Example: Real chain is `Human → Agent A → Malicious Agent → Agent C`. Malicious Agent strips itself from the chain and presents `Human → Agent A → Agent C` to Agent C.

**The Mitigation: Signed Delegation Receipts**

Each token exchange produces a **delegation receipt** — a compact JWT signed by the *requesting actor's* key (their DPoP key). The receipt contains:

```json
{
  "typ": "delegation-receipt+jwt",
  "alg": "ES256"
}
{
  "iss": "agent:search-bot",
  "sub": "agent:database-reader",
  "parent_jti": "tok_parent_123",
  "child_jti": "tok_child_456",
  "chain_hash": "SHA256(canonical-chain-up-to-this-point)",
  "iat": 1711379100
}
```

The `chain_hash` is a SHA-256 digest of the entire delegation chain serialized canonically up to that point. Each subsequent exchange includes the previous receipt. The receiver can:
1. Verify each receipt's signature matches the claimed actor's public key
2. Verify the `chain_hash` matches the actual chain in the token
3. Detect any removal, reordering, or insertion of actors

**Important nuance on novelty:** The delegation chain splicing attack and the concept of per-step delegation receipts are not invented here — Chiradeep Chhaya posted this exact attack scenario to the IETF OAuth-WG mailing list (Feb 26, 2026), proposing three mitigations that align with ours: cross-validation of `may_act`, aud/sub chaining per OIDC-A, and per-step delegation receipts. The OIDC-A spec also defines `delegation_chain` with verifiable chaining. What IS novel is being **the first to implement and ship signed delegation receipts in working, open-source code**. The concept is in the air at IETF; nobody has built it. This is actually a stronger position than pure invention — it shows alignment with standards work, not isolation. This is our strongest technical differentiator and a candidate for an IETF individual draft.

The `delegation_receipt` claim in the token contains the most recent receipt. The full chain of receipts is stored server-side in the `delegation_receipts` table and can be fetched via `GET /tokens/{jti}/receipts` for full audit.

### 13.2 What We DON'T Roll Ourselves
- JWT encode/decode: **PyJWT** (millions of downloads)
- Cryptographic primitives: **PyCA cryptography** (audited, OpenSSL bindings)
- Password hashing: **bcrypt**
- HTTP framework: **FastAPI/Starlette**

We only implement **novel agent-specific logic:** delegation chain management, token exchange with `act` claims, DPoP verification, agent registry.

---

## 14. Server Configuration

All via environment variables (12-factor):

```bash
AUTHGENT_SECRET_KEY=<random-64-char>
AUTHGENT_DATABASE_URL=sqlite+aiosqlite:///./authgent.db  # or postgresql+asyncpg://...
AUTHGENT_ACCESS_TOKEN_TTL=900           # 15 min
AUTHGENT_REFRESH_TOKEN_TTL=86400        # 24 hours
AUTHGENT_EXCHANGE_TOKEN_TTL=300         # 5 min for exchanged tokens
AUTHGENT_SIGNING_ALGORITHM=ES256
AUTHGENT_JWKS_ROTATION_DAYS=90
AUTHGENT_REGISTRATION_POLICY=open       # open | token | admin
AUTHGENT_CONSENT_MODE=ui               # ui | headless | auto_approve
AUTHGENT_MAX_DELEGATION_DEPTH=5
AUTHGENT_DELEGATION_SCOPE_REDUCTION=true
AUTHGENT_REQUIRE_DPOP=false
AUTHGENT_HOST=0.0.0.0
AUTHGENT_PORT=8000
AUTHGENT_CORS_ORIGINS=               # empty = reject all cross-origin. Set explicitly for production.
AUTHGENT_HITL_TIMEOUT=300            # seconds before step-up request expires
```

---

## 15. Project Structure

```
authgent/
├── server/                          # authgent-server (PyPI + Docker)
│   ├── authgent_server/
│   │   ├── app.py                   # FastAPI app factory
│   │   ├── config.py                # Pydantic Settings
│   │   ├── cli.py                   # Typer CLI
│   │   ├── db.py                    # Async SQLAlchemy engine
│   │   ├── endpoints/
│   │   │   ├── token.py             # POST /token (all grants)
│   │   │   ├── authorize.py         # GET/POST /authorize
│   │   │   ├── register.py          # POST /register
│   │   │   ├── revoke.py            # POST /revoke
│   │   │   ├── agents.py            # CRUD /agents
│   │   │   ├── wellknown.py         # /.well-known/*
│   │   │   └── health.py
│   │   ├── models/
│   │   │   ├── oauth_client.py, agent.py, authorization_code.py
│   │   │   ├── refresh_token.py, device_code.py, consent.py
│   │   │   ├── signing_key.py, token_blocklist.py, audit_log.py
│   │   │   ├── delegation_receipt.py, stepup_request.py
│   │   │   └── base.py             # SQLAlchemy base + ULID mixin
│   │   ├── services/
│   │   │   ├── token_service.py     # Issue, validate, exchange
│   │   │   ├── jwks_service.py      # Key gen, rotation, JWKS
│   │   │   ├── agent_service.py     # Agent CRUD
│   │   │   ├── client_service.py    # OAuth client reg
│   │   │   ├── dpop_service.py      # DPoP validation
│   │   │   ├── delegation_service.py # act claim nesting
│   │   │   └── audit_service.py
│   │   └── middleware/
│   │       ├── error_handler.py     # RFC 9457 Problem Details
│   │       └── request_id.py
│   ├── migrations/                   # Alembic
│   ├── tests/
│   ├── pyproject.toml, Dockerfile, docker-compose.yml
│
├── sdks/
│   ├── python/                       # authgent SDK (PyPI)
│   │   ├── authgent/
│   │   │   ├── verify.py, delegation.py, dpop.py, models.py, errors.py
│   │   │   ├── jwks.py, client.py
│   │   │   ├── middleware/ (fastapi.py, flask.py)
│   │   │   └── adapters/ (mcp.py)
│   │   ├── tests/
│   │   └── pyproject.toml
│   │
│   ├── typescript/                   # authgent SDK (npm)
│   │   ├── src/ (verify.ts, delegation.ts, dpop.ts, middleware/, adapters/)
│   │   ├── tests/
│   │   └── package.json
│   │
│   └── go/                           # authgent-go (Go modules)
│       ├── verify.go, delegation.go, dpop.go, client.go
│       └── go.mod
│
├── examples/
│   ├── quickstart-fastapi/
│   ├── quickstart-express/
│   ├── multi-agent-delegation/
│   └── existing-idp-auth0/
│
├── docs/
│   ├── quickstart.md, architecture.md, threat-model.md
│   ├── token-exchange.md, dpop.md, faq.md
│
├── spec/openapi.yaml                 # Committed OpenAPI 3.1
├── LICENSE (Apache 2.0)
├── README.md, CONTRIBUTING.md, SECURITY.md
```

---

## 16. Phased Delivery Plan

### Phase 1: MCP-Compliant Core (Weeks 1-4)

**Rationale for merged phase:** Core MCP auth mandates `authorization_code` + PKCE. Shipping `client_credentials`-only in Phase 1 means the server can't serve as an MCP auth server — our #1 value prop. Both grants ship together.

**Server:**
- Project scaffolding (FastAPI, async SQLAlchemy, Pydantic settings)
- DB models: oauth_clients, authorization_codes, refresh_tokens, consents, signing_keys, token_blocklist
- JWKS service: ES256 key generation, JWKS endpoint
- `POST /token` with `client_credentials` grant (MCP extension: `io.modelcontextprotocol/oauth-client-credentials`)
- `POST /token` with `authorization_code` + PKCE grant (MCP core — MANDATORY)
- Refresh token rotation with family tracking + reuse detection
- `GET/POST /authorize` with minimal consent page (configurable: `ui` | `headless` | `auto_approve`)
- `POST /register` (Dynamic Client Registration, RFC 7591)
- `GET /.well-known/oauth-authorization-server` + `GET /.well-known/jwks.json`
- `POST /revoke` (RFC 7009)
- `GET /health`, `GET /ready`
- CLI: `authgent-server init`, `authgent-server run`
- Dockerfile + docker-compose.yml
- Tests for all endpoints

**Python SDK:**
- `verify_token()` with JWKS fetching/caching
- `AgentAuthClient` (register, get_token, revoke)
- FastAPI middleware + `require_agent_auth` decorator
- Tests

**Exit Criteria:** Developer can deploy, register a client, complete `authorization_code` + PKCE flow, get a token, and validate it on an MCP server — under 5 minutes.

### Phase 2: Agent Registry + Device Grant + CIMD + OTel (Weeks 5-6)

- Full CRUD `/agents` with credential rotation + grace period
- OIDC-A compatible fields in agent registry (agent_type, agent_model, agent_version, agent_provider)
- **Client ID Metadata Documents** — `metadata_url` column in oauth_clients, fetch-and-validate registration path (MCP default registration method)
- `POST /device` (Device Authorization Grant, RFC 8628) for CLI/headless agents
- `POST /token` with `device_code` grant
- `GET /.well-known/openid-configuration` (OIDC Discovery alias for MCP client compatibility)
- Audit log table + event logging + `trace_id`/`span_id` columns
- CLI: `create-agent`, `list-agents`
- Flask middleware in SDK
- Define `EventEmitter` Protocol + `DatabaseEventEmitter` default + `OpenTelemetryEventEmitter` (optional dep: `opentelemetry-api`)
- W3C Trace Context (`traceparent`) header propagation
- OTel support ships here — agent observability is a top-3 industry pain point and the audit wiring is already happening in this phase
- **JWT Bearer Assertions (RFC 7523)** — MCP spec recommends JWT-signed assertions over client secrets for `client_credentials`. Client signs a JWT with its private key and presents it as `client_assertion`. More secure (no shared secret transmission). Adds `client_assertion` / `client_assertion_type` params to `POST /token`.

### Phase 3: Token Exchange / Delegation Chains (Weeks 7-8)

- `POST /token` with `token-exchange` grant (RFC 8693)
- **External id_token as subject_token** — Accept `subject_token_type=urn:ietf:params:oauth:token-type:id_token` with JWTs from trusted external IdPs (Auth0/Clerk/Okta). Validates against IdP's JWKS, maps `sub` to human root of delegation chain (`human_root=true`). Config: `AUTHGENT_TRUSTED_OIDC_ISSUERS` (allowlist) + `AUTHGENT_TRUSTED_OIDC_AUDIENCE`. See ARCHITECTURE.md §4.7. **This is the critical bridge that connects existing Auth0/Clerk users to authgent's delegation chains — without it, all chains start headless (machine-to-machine only).**
- Nested `act` claim construction with OIDC-A claims
- Optional `requested_actor` parameter support (draft-oauth-ai-agents-on-behalf-of-user-02)
- **Signed delegation receipts** (chain splicing mitigation) — `delegation_receipts` table + receipt JWT generation
- `delegation_purpose` and `delegation_constraints` claims in exchanged tokens (OIDC-A alignment)
- Scope reduction enforcement: downstream ≤ parent scopes
- **Cross-audience scope mapping policy:** When exchanging a token with `aud: api-A` for `aud: api-B`, scope namespaces may differ entirely. Policy: (a) if both audiences share a scope namespace (same resource server), standard reduction applies; (b) if audiences have different namespaces, the server requires an explicit scope mapping in the client's `oauth_clients.metadata` or rejects the exchange. This prevents accidental scope escalation across unrelated services.
- Max delegation depth enforcement
- `client.exchange_token()` in SDK
- `verify_delegation_chain()` in SDK (validates receipts if present)
- `GET /tokens/{jti}/receipts` — fetch full receipt chain for audit

### Phase 4: DPoP (Weeks 9-10)

- DPoP proof validation on server
- **DPoP-Nonce support** (RFC 9449 §8) — server-provided nonces to prevent precomputed proofs
- `cnf.jkt` claim injection
- `DPoPClient` class in SDK (handles nonce rotation automatically)
- `verify_dpop_proof()` in SDK
- Middleware auto-verifies if token has `cnf` claim

### Phase 5: TypeScript SDK + A2A + Providers + Polish (Weeks 11-16)

**Note:** Adjusted to 6 weeks — building TS SDK + Go SDK + provider interfaces + A2A + docs + PAR + introspection is not realistic in fewer weeks for a solo/small maintainer.

**Weeks 11-12: TypeScript SDK + Go SDK**
- TypeScript SDK: verify, delegation, dpop, Express middleware, MCP adapter
- Go SDK: verify, delegation (starter)
- npm + Go module published

**Weeks 13-14: Provider Interfaces + A2A + HITL**
- `GET /agents/{id}/agent-card` (A2A Agent Card generation)
- JWKS auto-rotation background task
- Define `AttestationProvider`, `PolicyProvider`, `HITLProvider`, `KeyProvider` Protocols
- Implement `NullAttestationProvider`, `ScopePolicyProvider`, `WebhookHITLProvider`, `DatabaseKeyProvider` defaults
- `POST /stepup` endpoint (HITL step-up authorization)
- `stepup_requests` table

**Weeks 15-16: Docs + Examples + Polish**
- Token Introspection endpoint (RFC 7662) — needed for enterprise gateways that call introspection. Lightweight: returns token claims from JWT decode + blocklist check.
- Pushed Authorization Requests (PAR, RFC 9126) — client POSTs auth parameters to AS first, then redirects with only `request_uri`. Prevents authorization request parameter tampering. Trending in OAuth 2.1 + MCP.
- OpenAPI spec committed
- Full docs (quickstart, architecture, threat-model, token-exchange, dpop, faq)
- Examples (quickstart-fastapi, quickstart-express, multi-agent-delegation, existing-idp-auth0)
- **`authgent-conformance`** — test harness that validates MCP auth server compliance. Positions authgent as reference implementation, not just a product. No other project ships this.
- README polish, CONTRIBUTING.md, SECURITY.md

**Total timeline: ~16 weeks.** Phase 1 expanded to 4 weeks (merged auth_code+PKCE). Phase 2 includes CIMD + device grant. Phases 3-4 unchanged. Phase 5 at 6 weeks for TS/Go SDKs + providers + polish.

---

## 17. Testing Strategy

- **Unit tests:** Each service tested in isolation with mocked DB
- **Integration tests:** Full endpoint tests via FastAPI TestClient + in-memory SQLite
- **Security tests:** Token forgery, expired/revoked tokens, scope escalation, delegation depth violation, DPoP replay, PKCE mismatch, timing-safe secret comparison
- **SDK tests:** verify_token, verify_delegation_chain, verify_dpop with test JWTs
- **CI:** GitHub Actions on every PR. Coverage target: 90% server, 85% SDKs

---

## 18. Distribution

| Channel | Command |
|---|---|
| PyPI (server) | `pip install authgent-server` |
| PyPI (SDK) | `pip install authgent` |
| Docker Hub | `docker pull authgent/server` |
| npm | `npm install authgent` |
| Go modules | `go get github.com/authgent/authgent-go` |

---

## 19. Non-Goals (v1)

1. **Full SCIM compliance** — Simple REST API, not a SCIM server
2. **Admin dashboard UI** — Headless only (CLI + API). AIM has a dashboard; we don't for v1.
3. **Rate limiting** — Use reverse proxy (Nginx/Caddy)
4. **Multi-tenancy** — Single-tenant v1. **Note:** This will be the #1 enterprise blocker (WorkOS, AIM both have it). Tenant isolation is a v2 priority. The DB schema uses `owner` fields that can evolve into `tenant_id` without migration.
5. **Full policy engine implementation** — `PolicyProvider` interface defined, `ScopePolicyProvider` default. Full OPA/Cedar integration is community-contributed.
6. **Full attestation implementation** — `AttestationProvider` interface defined, `NullAttestationProvider` default. TEE/SGX attestation is community-contributed.
7. **Post-quantum cryptography** — Architecture supports it (algorithm-agnostic config + KeyProvider). Implementation deferred until ML-DSA libraries stabilize. **Verify AIM's ML-DSA claim** — is it real or aspirational?
8. **Token introspection** (RFC 7662) — Moved to Phase 5 (week 14). Lightweight implementation: JWT decode + blocklist check. Needed for enterprise gateways.
9. **CIBA** (Client-Initiated Backchannel Auth) — Deferred. Device Authorization Grant (RFC 8628) covers most headless use cases.
10. **Credential brokering / Token Vault** — Agents needing outbound tokens for third-party APIs (Slack, GitHub, Jira, etc.) on behalf of users. Auth0's Token Vault and OpenA2A's "Secretless AI" address this. This is a separate concern from our OAuth server (inbound auth) — it's outbound token management. **v2 roadmap item.** Will come up in every enterprise evaluation.

---

## 20. Open Questions

1. **License:** Apache 2.0 (enterprise-friendly, includes patent grant) vs MIT
2. **⚠️ BLOCKING — Naming:** Collisions are **confirmed**: **RESOLVED — renamed to `authgent`.** PyPI, npm, and GitHub all available. The name is a portmanteau of "auth" + "agent" — instantly communicates purpose.
3. **Agentic JWT patent:** Our impl uses standard RFCs (8693, 9449) with `act` claims, NOT the paper's `agent_checksum` grant. Legal review needed.
4. **MCP auth provider interface:** Track `modelcontextprotocol/python-sdk` for breaking changes
5. **Consent page:** Server-rendered HTML (default) or redirect to external URL
6. **Delegation receipt IETF draft:** Signed delegation receipts are a first implementation of a concept actively discussed on the OAuth-WG mailing list (Chhaya, Feb 2026). Consider publishing an individual I-D (`draft-agnihotri-oauth-delegation-receipts`) to establish priority, reference the existing discussion, and drive standardization.
7. **OIDC-A tracking:** The OIDC-A spec is early. Monitor OpenID Foundation for updates. Our `agent_*` claims are optional and can be renamed to match final spec.
8. **Authlib evaluation: likely skip.** Authlib (5K+ stars) handles standard OAuth grants well but does NOT natively support RFC 8693 token exchange or custom `act` claim logic. The agent-specific features (delegation chains, receipts, DPoP nonce, HITL) are >60% of our grant logic. Authlib would cover ~30% and add an abstraction layer we'd fight for the rest. Recommendation: go raw FastAPI endpoints from the start. Revisit only if Phase 1 development reveals unexpected complexity in standard grant handling.

---

## 21. References

### RFCs
- RFC 6749 (OAuth 2.0), RFC 6750 (Bearer), RFC 7009 (Revocation)
- RFC 7517 (JWK), RFC 7519 (JWT), RFC 7591 (Dynamic Client Reg)
- RFC 7636 (PKCE), RFC 8414 (Server Metadata)
- **RFC 8693 (Token Exchange)** — core of delegation chain feature
- **RFC 8707 (Resource Indicators)** — MANDATORY for MCP compliance. `resource` param in all token/auth requests.
- **RFC 9449 (DPoP)** — core of proof-of-possession feature
- **RFC 9126 (Pushed Authorization Requests)** — PAR for auth request integrity. Phase 5.
- **RFC 9728 (Protected Resource Metadata)** — `/.well-known/oauth-protected-resource` endpoint. Mandatory for MCP.
- RFC 7523 (JWT Bearer Assertions) — MCP-recommended for client_credentials authentication
- **RFC 9068 (JWT Profile for Access Tokens)** — our tokens conform to this profile
- RFC 8628 (Device Authorization Grant)
- RFC 7662 (Token Introspection)
- OAuth 2.1 draft

### Agent-Specific
- draft-goswami-agentic-jwt-00 (Agentic JWT)
- draft-abbey-scim-agent-extension-00 (SCIM for Agents)
- draft-ni-wimse-ai-agent-identity (WIMSE)
- draft-rosenberg-aauth (AAuth — Agent Authorization)
- **draft-oauth-ai-agents-on-behalf-of-user-02** — Extends OAuth 2.0 with `requested_actor` parameter for agent delegation. Introduces `actor_token` in authorization requests. Becoming the standard approach for "human delegates to agent" flows. Consider supporting `requested_actor` as optional parameter in auth_code flow for standards alignment.
- **draft-ietf-oauth-client-id-metadata-document-00** — Client ID Metadata Documents. Now the default MCP registration path.
- draft-oauth-transaction-tokens-for-agents-04 (Ashay Raut, Amazon) — Transaction Tokens with actor/principal context for agent workloads. Complementary to RFC 8693. v2 evaluation target.
- MCP Auth Spec (modelcontextprotocol.io, revision 2025-11-25)
- MCP Enterprise-Managed Authorization extension (`io.modelcontextprotocol/enterprise-managed-authorization`) — ID-JAG grant for corporate SSO integration. v2 roadmap item for enterprise adoption.
- Google A2A Protocol

### IETF Mailing List
- Chiradeep Chhaya, OAuth-WG (Feb 26, 2026) — Delegation chain splicing attack analysis and three proposed mitigations (cross-validation, aud/sub chaining, per-step receipts)

### Competitive
- **AIM** (opena2a) — Agent Identity Management framework. Partial OAuth (JWT-bearer + device auth), not full OAuth 2.1.
- **Better Auth** — Full OAuth 2.1 Provider (auth_code, refresh_token, client_credentials, dynamic registration, PKCE, OIDC). MCP-compatible. TS-only. No delegation chains, DPoP, or agent registry.
- **mcp-auth** (mcp-auth.dev) — Python token validator library for MCP servers. Not an auth server. Complementary.
- **OIDC-A** — OpenID Connect for Agents (emerging spec)
- **WorkOS AgentKit** — Enterprise agent IAM (commercial)
- **Stytch Connected Apps** — SaaS agent auth (commercial)
