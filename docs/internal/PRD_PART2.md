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

### 9.12 Table: vault_credentials

Encrypted credential storage for the Credential Vault (Layer 3). Agents never see raw credentials — the vault proxies requests using stored credentials on behalf of authorized agents.

```
id                        VARCHAR(26) PK         -- ULID
name                      VARCHAR(255) UNIQUE NOT NULL  -- human-readable name (e.g. "prod-db")
resource_type             VARCHAR(50) NOT NULL   -- postgresql | mysql | http_api | mongodb | redis | s3
encrypted_uri             TEXT NOT NULL          -- AES-256-GCM encrypted connection URI/credentials
                                                 -- key: HKDF-derived vault subkey from AUTHGENT_SECRET_KEY
encryption_iv             VARCHAR(64) NOT NULL   -- initialization vector for AES-GCM
description               TEXT                   -- optional human-readable description
read_scopes               JSON NOT NULL          -- ["db:read"] — scopes that allow read-only access
write_scopes              JSON DEFAULT '[]'      -- ["db:write"] — scopes that allow write access
allowed_agents            JSON                   -- NULL = all agents; ["agnt_abc"] = restricted
status                    VARCHAR(20) DEFAULT 'active'  -- active | disabled | rotated
metadata                  JSON                   -- resource-specific config (e.g. max_connections, timeout)
last_used_at              TIMESTAMP
created_at                TIMESTAMP NOT NULL
updated_at                TIMESTAMP NOT NULL
```

**Design rationale:** Credentials are encrypted at rest using a vault-specific HKDF-derived subkey (`derive_subkey(master, "vault")`), separate from the KEK used for signing keys. The `encrypted_uri` contains the full connection string including username/password. On read, the vault service decrypts in memory, establishes a connection, executes the proxied query, and returns results. The decrypted URI is never logged, never returned in API responses, and never stored in plaintext.

**Scope mapping:** `read_scopes` and `write_scopes` map to authgent token scopes. When an agent presents a token with `db:read`, the vault allows SELECT queries only. With `db:write`, INSERT/UPDATE/DELETE are permitted. This provides defense-in-depth beyond what the MCP server itself enforces.

### 9.13 Table: gateway_configs

Configuration for MCP Gateway instances (Layer 2). Each row represents a gateway wrapping one upstream MCP server.

```
id                        VARCHAR(26) PK         -- ULID
name                      VARCHAR(255) UNIQUE NOT NULL  -- human-readable name (e.g. "postgres-mcp")
upstream_url              TEXT                   -- HTTP upstream URL (NULL if stdio mode)
stdio_command             TEXT                   -- stdio command (NULL if HTTP mode)
required_scopes           JSON NOT NULL          -- ["tools:read", "tools:execute"]
allowed_agents            JSON                   -- NULL = all agents; ["agnt_abc"] = restricted
require_dpop              BOOLEAN DEFAULT FALSE  -- override server-level DPoP setting
rate_limit                INTEGER                -- per-client requests/min (NULL = use server default)
status                    VARCHAR(20) DEFAULT 'active'  -- active | disabled
metadata                  JSON                   -- extra config (headers to forward, timeout, etc.)
created_at                TIMESTAMP NOT NULL
updated_at                TIMESTAMP NOT NULL
```

### 9.14 Table: users

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

## 12A. Gateway Endpoints (Layer 2)

The MCP Gateway is a reverse proxy built into `authgent-server`. It adds OAuth 2.1 authentication to any upstream MCP server without modifying the server's code.

### 12A.1 CLI: `authgent-server gateway`

```bash
# HTTP upstream:
authgent-server gateway \
  --upstream http://localhost:3000 \
  --scopes "tools:read,tools:execute" \
  --port 8001

# stdio upstream (wraps a local MCP server):
authgent-server gateway \
  --stdio "npx @modelcontextprotocol/server-postgres postgresql://..." \
  --scopes "db:read" \
  --port 8001
```

The gateway binds to `--port` (default: 8001, separate from auth server on 8000) and:
1. Serves `/.well-known/oauth-authorization-server` → points to authgent-server
2. Serves `/.well-known/oauth-protected-resource` → RFC 9728 metadata
3. Intercepts all other requests → validates Bearer token → forwards to upstream
4. Returns `401` with `WWW-Authenticate: Bearer` if no token or invalid
5. Returns `403` with `WWW-Authenticate: Bearer scope="..." error="insufficient_scope"` if scope mismatch

### 12A.2 API: Gateway Management

```
POST   /gateways           — Create a gateway config (stored in gateway_configs table)
GET    /gateways            — List all gateway configs
GET    /gateways/{id}       — Get gateway config details
PATCH  /gateways/{id}       — Update gateway config (scopes, status, rate limit)
DELETE /gateways/{id}       — Delete gateway config
```

These endpoints are used by the Dashboard and CLI. The `gateway` CLI command can also run without persisting config (ephemeral mode for quick wrapping).

---

## 12B. Vault Endpoints (Layer 3)

The Credential Vault stores encrypted credentials and proxies agent requests so agents never see raw secrets.

### 12B.1 CLI: `authgent-server vault`

```bash
# Add a credential:
authgent-server vault add \
  --name "prod-db" \
  --type postgresql \
  --uri "postgresql://admin:s3cret@db.example.com/myapp" \
  --read-scopes "db:read" \
  --write-scopes "db:write"

# List credentials:
authgent-server vault list

# Remove a credential:
authgent-server vault remove --name "prod-db"

# Rotate a credential (update URI without downtime):
authgent-server vault rotate --name "prod-db" \
  --uri "postgresql://admin:new_s3cret@db.example.com/myapp"
```

### 12B.2 API: Vault Management

```
POST   /vault/credentials           — Store an encrypted credential
GET    /vault/credentials            — List credentials (URIs never returned)
GET    /vault/credentials/{name}     — Get credential metadata (URI never returned)
PATCH  /vault/credentials/{name}     — Update credential (rotate URI, change scopes)
DELETE /vault/credentials/{name}     — Delete credential + wipe encrypted data
```

### 12B.3 API: Vault Resource Proxy

```
POST   /vault/{name}/query          — Execute a SQL query via the named credential
POST   /vault/{name}/proxy          — Proxy an HTTP request via the named credential
```

**Query endpoint (PostgreSQL):**
```
POST /vault/prod-db/query
Authorization: Bearer eyJ...
Content-Type: application/json

{
  "sql": "SELECT id, name, email FROM users WHERE department = $1 LIMIT 10",
  "params": ["engineering"]
}
```

Response:
```json
{
  "rows": [
    {"id": 1, "name": "Alice", "email": "alice@example.com"},
    {"id": 2, "name": "Bob", "email": "bob@example.com"}
  ],
  "row_count": 2,
  "duration_ms": 12
}
```

**Security enforcement:**
- Token must include a scope matching `vault_credentials.read_scopes` or `write_scopes`
- For `db:read` scope: only `SELECT` and `EXPLAIN` allowed (validated before execution)
- For `db:write` scope: `INSERT`, `UPDATE`, `DELETE` also allowed
- `DROP`, `ALTER`, `TRUNCATE`, `CREATE` always blocked (require `db:admin` scope)
- Parameterized queries only — raw string interpolation rejected
- Query timeout enforced (configurable per credential, default: 30s)
- Results capped at configurable row limit (default: 10,000 rows)

**Proxy endpoint (HTTP API):**
```
POST /vault/github-api/proxy
Authorization: Bearer eyJ...
Content-Type: application/json

{
  "method": "GET",
  "path": "/repos/authgent/authgent/issues",
  "headers": {"Accept": "application/json"}
}
```

The vault injects the stored API key/token into the upstream request headers. The agent never sees the real credentials.

---

## 12C. Dashboard Endpoints (Layer 5)

### 12C.1 Static File Serving

The dashboard is a React SPA built as static files. The server serves them from `/ui`:

```
GET /ui              — Serves index.html (React SPA)
GET /ui/*            — Serves static assets (JS, CSS, images)
```

### 12C.2 Dashboard API

The dashboard uses the same REST API as the CLI. No special backend endpoints are needed. Key APIs consumed by the dashboard:

- `GET /agents` — List agents (with pagination, filtering)
- `GET /agents/{id}` — Agent details
- `POST /introspect` — Token introspection (for active token viewer)
- `GET /vault/credentials` — Vault credential list
- `GET /gateways` — Gateway config list
- `GET /audit` — Audit log with filtering (new endpoint)

### 12C.3 New: Audit Log Query API

```
GET /audit?action=token.issued&client_id=agnt_abc&since=2026-03-01&limit=50

Response:
{
  "events": [
    {
      "id": "01HW...",
      "timestamp": "2026-03-28T06:00:00Z",
      "action": "token.issued",
      "actor": "agent:orchestrator",
      "client_id": "agnt_abc123",
      "ip_address": "192.168.1.1",
      "metadata": {"grant_type": "client_credentials", "scope": "db:read"}
    }
  ],
  "total": 142,
  "has_more": true
}
```

---

## 12D. AI Framework Integration SDK Specifications (Layer 4)

Each integration is published as a separate PyPI package with `authgent` as a dependency. All integrations follow the same pattern: wrap tool/agent execution with token acquisition and scope checking.

### 12D.1 LangChain Integration (`authgent-langchain`)

```python
from langchain.tools import Tool
from authgent.integrations.langchain import AuthgentToolGuard, AuthgentCallbackHandler

# Option 1: Decorator — guards individual tools
guard = AuthgentToolGuard(server_url="http://localhost:8000")

@guard.require_scopes(["db:read"])
def query_database(sql: str) -> str:
    """Execute a SQL query."""
    return db.execute(sql)

# Option 2: Callback handler — auto-acquires tokens for agent runs
handler = AuthgentCallbackHandler(
    server_url="http://localhost:8000",
    client_id="agnt_orchestrator",
    client_secret="sec_...",
)
agent = initialize_agent(tools=[...], callbacks=[handler])
```

### 12D.2 CrewAI Integration (`authgent-crewai`)

```python
from crewai import Agent, Task, Crew
from authgent.integrations.crewai import AuthgentPermissionMiddleware

middleware = AuthgentPermissionMiddleware(server_url="http://localhost:8000")

researcher = Agent(
    role="Researcher",
    tools=[search_tool],
    # authgent automatically scopes this agent to search:execute
    authgent_scopes=["search:execute"],
)

crew = Crew(agents=[researcher], middleware=[middleware])
```

### 12D.3 OpenAI Agents SDK Integration (`authgent-openai`)

```python
from openai_agents import Agent, tool
from authgent.integrations.openai import authgent_guard

@tool
@authgent_guard(scopes=["db:read"])
def query_database(sql: str) -> str:
    """Execute a SQL query."""
    return db.execute(sql)

agent = Agent(tools=[query_database])
```

### 12D.4 Google ADK Integration (`authgent-adk`)

```python
from google.adk import Agent
from authgent.integrations.adk import AuthgentAuthPlugin

agent = Agent(
    auth_plugin=AuthgentAuthPlugin(server_url="http://localhost:8000"),
)
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
│   │   ├── cli.py                   # Typer CLI (init, run, gateway, vault, create-agent, ...)
│   │   ├── db.py                    # Async SQLAlchemy engine
│   │   ├── endpoints/
│   │   │   ├── token.py             # POST /token (all grants)
│   │   │   ├── authorize.py         # GET/POST /authorize
│   │   │   ├── register.py          # POST /register
│   │   │   ├── revoke.py            # POST /revoke
│   │   │   ├── introspect.py        # POST /introspect
│   │   │   ├── agents.py            # CRUD /agents
│   │   │   ├── device.py            # POST /device, GET /device/status
│   │   │   ├── stepup.py            # POST /stepup, GET /stepup/{id}
│   │   │   ├── gateway.py           # /gateways CRUD + proxy catch-all (Phase 7)
│   │   │   ├── vault.py             # /vault/* CRUD + proxy endpoints (Phase 8)
│   │   │   ├── audit.py             # GET /audit (Phase 9)
│   │   │   ├── wellknown.py         # /.well-known/* (4 endpoints)
│   │   │   └── health.py
│   │   ├── models/
│   │   │   ├── oauth_client.py, agent.py, authorization_code.py
│   │   │   ├── refresh_token.py, device_code.py, consent.py
│   │   │   ├── signing_key.py, token_blocklist.py, audit_log.py
│   │   │   ├── delegation_receipt.py, stepup_request.py, user.py
│   │   │   ├── vault_credential.py  # Encrypted credential storage (Phase 8)
│   │   │   ├── gateway_config.py    # Gateway configuration (Phase 7)
│   │   │   └── base.py             # SQLAlchemy base + ULID mixin
│   │   ├── services/
│   │   │   ├── token_service.py     # Issue, validate, exchange
│   │   │   ├── jwks_service.py      # Key gen, rotation, JWKS
│   │   │   ├── agent_service.py     # Agent CRUD
│   │   │   ├── client_service.py    # OAuth client reg
│   │   │   ├── dpop_service.py      # DPoP validation
│   │   │   ├── delegation_service.py # act claim nesting
│   │   │   ├── consent_service.py   # Consent grant tracking
│   │   │   ├── stepup_service.py    # HITL step-up flow orchestration
│   │   │   ├── audit_service.py     # Event emission via EventEmitter
│   │   │   ├── gateway_service.py   # Proxy logic, upstream health (Phase 7)
│   │   │   └── vault_service.py     # Credential CRUD, encryption, proxy (Phase 8)
│   │   ├── vault/                   # Vault resource proxies (Phase 8)
│   │   │   ├── crypto.py            # AES-256-GCM encrypt/decrypt
│   │   │   ├── postgresql_proxy.py  # asyncpg query proxy + SQL validation
│   │   │   └── http_proxy.py        # httpx-based HTTP proxy
│   │   ├── middleware/
│   │   │   ├── error_handler.py     # RFC 9457 Problem Details
│   │   │   ├── request_id.py        # X-Request-ID + traceparent
│   │   │   ├── cors.py              # CORS from AUTHGENT_CORS_ORIGINS
│   │   │   └── rate_limit.py        # Per-endpoint sliding window
│   │   ├── providers/               # Protocol implementations
│   │   │   ├── protocols.py         # 7 Protocol definitions
│   │   │   ├── attestation.py, policy.py, hitl.py, keys.py, events.py
│   │   │   └── human_auth.py        # HumanAuthProvider
│   │   ├── schemas/                 # Pydantic request/response models
│   │   │   ├── token.py, client.py, agent.py, common.py
│   │   │   ├── gateway.py           # (Phase 7)
│   │   │   └── vault.py             # (Phase 8)
│   │   └── templates/
│   │       └── consent.html         # Minimal Jinja2 consent page
│   ├── migrations/                   # Alembic
│   ├── tests/
│   ├── pyproject.toml, Dockerfile, docker-compose.yml
│
├── dashboard/                       # Developer Dashboard (Phase 9)
│   ├── src/
│   │   ├── components/              # React + shadcn/ui components
│   │   ├── pages/                   # Agents, Tokens, Chains, Vault, Audit, Gateway, Settings
│   │   ├── hooks/                   # TanStack Query hooks
│   │   ├── lib/                     # API client, utils
│   │   └── App.tsx, main.tsx
│   ├── public/
│   ├── package.json
│   ├── vite.config.ts
│   └── tailwind.config.ts
│
├── sdks/
│   ├── python/                       # authgent SDK (PyPI)
│   │   ├── authgent/
│   │   │   ├── verify.py, delegation.py, dpop.py, models.py, errors.py
│   │   │   ├── jwks.py, client.py
│   │   │   ├── middleware/ (fastapi.py, flask.py, scope_challenge.py)
│   │   │   └── adapters/ (mcp.py, protected_resource.py)
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
├── integrations/                    # AI Framework Integrations (Phase 10)
│   ├── langchain/                   # authgent-langchain (PyPI)
│   │   ├── authgent_langchain/
│   │   │   ├── tool_guard.py, callback_handler.py
│   │   ├── tests/
│   │   └── pyproject.toml
│   ├── crewai/                      # authgent-crewai (PyPI)
│   ├── openai/                      # authgent-openai (PyPI)
│   ├── adk/                         # authgent-adk (PyPI)
│   └── autogen/                     # authgent-autogen (PyPI)
│
├── examples/
│   ├── quickstart-fastapi/
│   ├── quickstart-express/
│   ├── multi-agent-delegation/
│   ├── existing-idp-auth0/
│   └── windsurf-vault/             # Protect DB from AI coding assistants
│
├── docs/
│   ├── quickstart.md, architecture.md, threat-model.md
│   ├── token-exchange.md, dpop.md, faq.md
│   ├── gateway.md, vault.md        # New platform docs
│
├── spec/openapi.yaml                 # Committed OpenAPI 3.1
├── LICENSE (Apache 2.0)
├── README.md, CONTRIBUTING.md, SECURITY.md
```

---

## 16. Phased Delivery Plan

**Note on current state:** Phases 1-5 (Core Auth) are **COMPLETE**. The OAuth 2.1 server, SDKs, all grant types, delegation chains, DPoP, HITL, and provider interfaces are built and tested (155+ tests across server + Python SDK + TypeScript SDK). The delivery plan below starts from Phase 6 — the platform expansion toward the "Supabase for agent auth" vision.

### Phases 1-5: Core Auth Server — ✅ COMPLETE (Implemented)

Everything from the original delivery plan has been built:
- **Server:** All grant types (client_credentials, authorization_code+PKCE, refresh_token, token_exchange, device_code), all endpoints (token, authorize, register, revoke, introspect, agents, device, stepup, wellknown, health), all 13 models, all services, all 7 provider interfaces, cleanup jobs, structured logging, rate limiting, error handling.
- **Python SDK:** verify_token, delegation chain validation, DPoP verification + DPoPClient, JWKS cache, AgentAuthClient, FastAPI middleware, scope challenge handler, protected resource metadata adapter. 29 tests.
- **TypeScript SDK:** Full feature parity with Python SDK. Express + Hono middleware, MCP adapter, 47 tests.
- **CLI:** init, run, create-agent, create-user, rotate-keys, migrate, openapi.
- **Tests:** 79 server tests + 29 Python SDK tests + 47 TypeScript SDK tests = **155 total**.
- **Docker:** Dockerfile + docker-compose.yml.

### Phase 6: Publish & Launch (Week 1) — DO THIS FIRST

**Rationale:** Nothing else matters if nobody can install it. The core is ready. Ship it.

| Task | Effort | Deliverable |
|---|---|---|
| Publish `authgent-server` to PyPI | 1 day | `pip install authgent-server` works |
| Publish `authgent` (Python SDK) to PyPI | Same day | `pip install authgent` works |
| Publish `authgent` to npm | Same day | `npm install authgent` works |
| Push repo to public GitHub | Same day | https://github.com/Dhruvagnihotri/authgent |
| Rewrite README for platform vision | 1 day | Lead with pain point, not features |
| Launch blog post | 1 day | "Secure Your AI Agents in 60 Seconds" |
| Post on r/mcp, r/LocalLLaMA, Hacker News | Same day | First users |

**Exit Criteria:** `pip install authgent-server && authgent-server init && authgent-server run` works from PyPI on a clean machine.

### Phase 7: MCP Gateway (Weeks 2-3) — THE KILLER FEATURE

**Rationale:** This is the single feature that makes authgent immediately useful to every MCP developer. Zero code changes to existing servers. Solves the #1 Reddit pain point.

| Task | Effort | Deliverable |
|---|---|---|
| `authgent-server gateway` CLI command (Typer) | 1 day | New CLI subcommand |
| HTTP reverse proxy with token validation | 2 days | `httpx`-based async proxy |
| stdio MCP server wrapping (subprocess + pipe) | 2 days | Wraps `npx server-xxx` commands |
| Auto-serve `.well-known` endpoints on gateway port | 1 day | MCP-spec-compliant discovery |
| Gateway management API (`/gateways` CRUD) | 1 day | Dashboard-ready API |
| `gateway_configs` DB model + migration | 0.5 day | Persistent config |
| Gateway tests (proxy, auth rejection, scope check) | 1 day | 15+ tests |
| Docs + examples | 1 day | "Add auth to any MCP server in 1 command" |
| r/mcp launch post | 0.5 day | Targeted community engagement |

**Architecture:**
```
authgent_server/
├── services/
│   └── gateway_service.py       # Proxy logic, upstream health, stdio management
├── endpoints/
│   └── gateway.py               # /gateways CRUD + proxy catch-all
├── models/
│   └── gateway_config.py        # SQLAlchemy model
└── schemas/
    └── gateway.py               # Pydantic request/response models
```

**Exit Criteria:** `authgent-server gateway --upstream http://localhost:3000 --scopes "tools:execute"` wraps an unmodified MCP server with full OAuth 2.1 auth. Claude Desktop can connect via MCP with token-based auth.

### Phase 8: Credential Vault (Weeks 4-6) — SOLVES THE DAILY USE CASE

**Rationale:** This solves the user's original pain point: "I have a database URI and don't want to give my password to Windsurf." Self-hosted credential vault with resource proxying. No competitor offers this open-source.

| Task | Effort | Deliverable |
|---|---|---|
| `vault_credentials` DB model + AES-256-GCM encryption | 2 days | Encrypted credential storage |
| HKDF vault subkey derivation (`derive_subkey(master, "vault")`) | 0.5 day | Separate from KEK |
| `authgent-server vault add/list/remove/rotate` CLI | 2 days | Credential management |
| Vault management API (`/vault/credentials` CRUD) | 1 day | Dashboard-ready API |
| PostgreSQL query proxy (`/vault/{name}/query`) | 3 days | SQL proxy with scope enforcement |
| SQL validation (SELECT-only for `db:read`, parameterized queries) | 1 day | Defense-in-depth |
| HTTP API proxy (`/vault/{name}/proxy`) | 2 days | Header injection proxy |
| Connection pooling (asyncpg pool per credential) | 1 day | Performance |
| Vault tests (encryption, scope enforcement, SQL injection prevention) | 2 days | 20+ tests |
| Docs + examples | 1 day | "Protect your database in 30 seconds" |

**Architecture:**
```
authgent_server/
├── services/
│   └── vault_service.py         # Credential CRUD, encryption/decryption, proxy logic
├── endpoints/
│   └── vault.py                 # /vault/* CRUD + proxy endpoints
├── models/
│   └── vault_credential.py      # SQLAlchemy model
├── schemas/
│   └── vault.py                 # Pydantic request/response models
└── vault/
    ├── __init__.py
    ├── crypto.py                # AES-256-GCM encrypt/decrypt with vault subkey
    ├── postgresql_proxy.py      # asyncpg query proxy + SQL validation
    └── http_proxy.py            # httpx-based HTTP proxy with header injection
```

**Exit Criteria:** Developer runs `authgent-server vault add --type postgresql --uri "postgresql://admin:secret@localhost/mydb" --read-scopes "db:read"`, then an agent with a `db:read`-scoped token can `POST /vault/mydb/query` with a SELECT statement and get results — without ever seeing the database password.

### Phase 9: Developer Dashboard (Weeks 7-9) — VISUAL MANAGEMENT

**Rationale:** Supabase's dashboard was the #1 reason developers chose it over raw PostgreSQL. The dashboard makes authgent accessible to non-CLI users and provides instant visibility into the agent auth system.

| Task | Effort | Deliverable |
|---|---|---|
| React + Vite + TailwindCSS + shadcn/ui project setup | 1 day | Dashboard scaffold |
| Agents list + detail view (CRUD) | 2 days | Agent management page |
| Active tokens viewer (via introspection API) | 1 day | Token monitoring |
| Delegation chain visualizer (tree/graph view) | 2 days | Visual chain inspection |
| Vault credential manager (add/remove/rotate) | 2 days | Vault management page |
| Gateway config manager | 1 day | Gateway management page |
| Audit log viewer (filterable, paginated) | 2 days | Security monitoring |
| `GET /audit` endpoint on server | 1 day | Audit query API |
| Settings page (server config viewer) | 0.5 day | Configuration visibility |
| Build pipeline (Vite → static files → served by FastAPI) | 1 day | Single deployable |
| Dashboard tests (component + integration) | 2 days | 30+ tests |

**Technology choices:**
- **React 18** + **Vite** — fast builds, HMR for development
- **TailwindCSS** + **shadcn/ui** — consistent, modern UI without custom CSS
- **Lucide icons** — clean iconography
- **TanStack Query** — data fetching + caching
- **Recharts** — audit log graphs
- Built as static files, served from FastAPI at `/ui`
- Disabled via `AUTHGENT_DASHBOARD=false` for headless deployments

**Exit Criteria:** Developer navigates to `http://localhost:8000/ui`, sees all agents, can create/edit/delete agents, view delegation chains visually, manage vault credentials, and browse audit logs — all without touching the CLI.

### Phase 10: AI Framework Integrations (Weeks 10-12) — DISCOVERABILITY

**Rationale:** Framework integrations are how agent developers discover authgent. Each integration = a new PyPI package = a new keyword that leads developers to authgent. Grantex has these; we need them.

| Task | Effort | Deliverable |
|---|---|---|
| `authgent-langchain` — Tool guards + callback handler | 3 days | `pip install authgent-langchain` |
| `authgent-crewai` — Agent permission middleware | 2 days | `pip install authgent-crewai` |
| `authgent-openai` — Tool guard decorators | 2 days | `pip install authgent-openai` |
| `authgent-adk` — Google ADK auth plugin | 2 days | `pip install authgent-adk` |
| `authgent-autogen` — Agent capability wrapper | 2 days | `pip install authgent-autogen` |
| Tests per integration | 3 days | 10+ tests each |
| Tutorials + example repos per integration | 3 days | "authgent + LangChain in 5 minutes" |
| Publish all to PyPI | 1 day | Installable packages |

**Architecture:** Each integration lives in `integrations/` at the repo root:
```
integrations/
├── langchain/
│   ├── authgent_langchain/
│   │   ├── __init__.py
│   │   ├── tool_guard.py
│   │   └── callback_handler.py
│   ├── tests/
│   └── pyproject.toml
├── crewai/
├── openai/
├── adk/
└── autogen/
```

**Exit Criteria:** A LangChain developer can `pip install authgent-langchain`, add `@authgent_guard(scopes=["db:read"])` to a tool, and have scope-enforced auth on that tool — in under 5 minutes.

### Phase 11: Polish + Cloud Prep (Weeks 13-16)

| Task | Effort | Deliverable |
|---|---|---|
| `authgent-conformance` test harness | 3 days | MCP auth compliance testing tool |
| Go SDK (starter: verify, delegation) | 5 days | `go get github.com/authgent/authgent-go` |
| Pushed Authorization Requests (PAR, RFC 9126) | 2 days | Enhanced auth request security |
| OpenAPI spec committed + hosted docs site | 2 days | authgent.dev/docs |
| Examples (quickstart-fastapi, quickstart-express, multi-agent-delegation, existing-idp-auth0, windsurf-vault) | 3 days | Copy-paste ready examples |
| Performance benchmarks (tokens/sec, gateway latency) | 1 day | Published benchmarks |
| Security audit preparation | 2 days | Threat model review + pen test prep |

### Phase 12: Cloud + Enterprise (Month 4+)

**Later, after open-source traction is established.**

- **authgent.dev** — hosted version (Supabase Cloud equivalent)
  - Free tier: 3 agents, 1,000 token operations/month
  - Pro: unlimited agents, 100k ops/month — $29/mo
  - Enterprise: SSO, compliance, SLA — custom pricing
- Multi-tenancy (tenant isolation, team management)
- SAML/SSO for enterprise human auth mode
- SOC 2 / compliance certifications
- Advanced analytics dashboard (usage graphs, security event heatmaps)
- MySQL, MongoDB, Redis, S3 vault connectors
- Edge Functions for agents (serverless functions with built-in authgent auth)
- Realtime WebSocket channels for agent-to-agent communication + HITL notifications

**Total new timeline: ~16 weeks for Phases 6-11.** Core auth (Phases 1-5) is already complete. The platform expansion builds on the existing foundation.

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

## 19. Non-Goals (v1 Platform)

**Former non-goals now on roadmap (platform expansion):**
- ~~Full admin dashboard UI~~ → **Phase 9** (Dashboard)
- ~~Token Vault / Credential brokering~~ → **Phase 8** (Credential Vault)
- ~~Multi-tenancy~~ → **Phase 12** (Cloud + Enterprise)

**Remaining non-goals:**
1. **Full policy engine** (OPA, Cedar) — Interface provided (`PolicyProvider`), default is scope-based. Full policy engines are a separate product.
2. **Full attestation** (TPM, Intel SGX) — Interface provided (`AttestationProvider`), implementation deferred. This requires platform-specific code.
3. **CIBA** (Client-Initiated Backchannel Auth) — Device Authorization Grant covers most headless use cases.
4. **Post-quantum cryptography** — Architecture supports it (algorithm-agnostic config). Deferred until ML-DSA libraries stabilize.
5. **SAML** — Enterprise SSO via SAML is deferred. External OIDC mode covers most SSO needs. Phase 12 for enterprise.
6. **GraphQL API** — REST only. GraphQL adds complexity without clear benefit for OAuth endpoints.
7. **Mobile SDKs** (iOS, Android) — Agent auth is server-side. Mobile auth is handled by the human auth layer (Auth0/Okta integration).
8. **Built-in secrets rotation automation** — The vault supports manual rotation (`vault rotate`). Automated rotation schedules (like AWS Secrets Manager) are deferred to Cloud phase.
9. **MySQL/MongoDB/Redis vault connectors** — Phase 8 covers PostgreSQL + HTTP API only. Additional database connectors are Phase 12 (Cloud).
10. **Real-time WebSocket API** — HITL polling is sufficient for v1. WebSocket push for HITL notifications and agent-to-agent channels is Phase 12.

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
