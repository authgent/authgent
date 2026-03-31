# authgent — Platform Roadmap

**Status:** The core OAuth 2.1 Authorization Server (Layer 1) is **complete** with 155+ tests across server + Python SDK + TypeScript SDK. The platform layers below are architecturally designed and documented for future implementation based on user demand.

> **Philosophy:** Ship the core. Own the niche (delegation chains + signed receipts). Expand when users ask for it.

---

## Platform Layers Overview

| Layer | Component | Status | Description |
|---|---|---|---|
| **1** | OAuth 2.1 Authorization Server | ✅ **Shipped** | Full OAuth 2.1 + delegation chains + DPoP + HITL |
| **2** | MCP Gateway | 📋 Designed | Zero-code OAuth wrapper for any MCP server |
| **3** | Credential Vault | 📋 Designed | Encrypted credential storage + resource proxying |
| **4** | AI Framework Integrations | 📋 Designed | Drop-in plugins for LangChain, CrewAI, etc. |
| **5** | Developer Dashboard | 📋 Designed | React SPA for visual agent management |

---

## Layer 2: MCP Gateway

Zero-code OAuth 2.1 wrapper for any MCP server. Built as a reverse proxy inside `authgent-server`.

```
authgent_server/
├── endpoints/
│   └── gateway.py                   # /gateways CRUD + proxy catch-all route
├── services/
│   └── gateway_service.py           # Core proxy logic
│       ├── proxy_http(request, upstream_url)     # httpx async reverse proxy
│       ├── proxy_stdio(request, command)          # subprocess stdio bridge
│       ├── validate_and_forward(request, config)  # token validation → proxy
│       └── health_check(upstream_url)             # upstream liveness check
├── models/
│   └── gateway_config.py            # GatewayConfig SQLAlchemy model
└── schemas/
    └── gateway.py                   # GatewayCreate, GatewayUpdate, GatewayResponse
```

**Gateway modes:**
| Mode | Transport | Use Case |
|---|---|---|
| HTTP proxy | `httpx` async | Remote MCP servers (HTTP/SSE) |
| stdio bridge | `asyncio.subprocess` | Local MCP servers (`npx @modelcontextprotocol/server-*`) |

**Request flow:**
1. MCP client sends request to gateway port (default: 8001)
2. Gateway extracts `Authorization: Bearer <token>` (or `DPoP <token>`)
3. Token validated via `TokenService.verify()` (same pipeline as SDK middleware)
4. Scopes checked against `gateway_configs.required_scopes`
5. If valid → request forwarded to upstream (headers stripped of auth, `X-Agent-Identity` injected)
6. If invalid → `401`/`403` per OAuth 2.1 Bearer scheme

**Auto-discovery:** The gateway auto-serves:
- `GET /.well-known/oauth-authorization-server` → points to authgent-server URL
- `GET /.well-known/oauth-protected-resource` → RFC 9728 metadata with gateway's scopes

### Gateway Proxy Flow

```
MCP Client (Claude Desktop)     authgent Gateway (:8001)     authgent-server (:8000)     Upstream MCP Server
  │                                    │                            │                          │
  │  1. GET /.well-known/              │                            │                          │
  │     oauth-authorization-server     │                            │                          │
  │ ──────────────────────────────────►│                            │                          │
  │                                    │                            │                          │
  │  200 { issuer: "http://           │                            │                          │
  │    localhost:8000", ... }          │                            │                          │
  │◄──────────────────────────────────│                            │                          │
  │                                    │                            │                          │
  │  2. Obtain token from             │                            │                          │
  │     authgent-server via           │                            │                          │
  │     auth_code/client_creds        │                            │                          │
  │ ──────────────────────────────────────────────────────────────►│                          │
  │                                    │                            │                          │
  │  200 { access_token: eyJ... }     │                            │                          │
  │◄──────────────────────────────────────────────────────────────│                          │
  │                                    │                            │                          │
  │  3. POST /tools/list              │                            │                          │
  │     Authorization: Bearer eyJ...  │                            │                          │
  │ ──────────────────────────────────►│                            │                          │
  │                                    │                            │                          │
  │                                    │  4. Validate JWT:          │                          │
  │                                    │  - Fetch JWKS from server  │                          │
  │                                    │  - Verify sig, exp, iss    │                          │
  │                                    │  - Check scopes ⊇ required │                          │
  │                                    │  - Verify DPoP (if cnf)    │                          │
  │                                    │  - Check blocklist         │                          │
  │                                    │                            │                          │
  │                                    │  5. Strip auth headers,    │                          │
  │                                    │  inject X-Agent-Identity   │                          │
  │                                    │                            │                          │
  │                                    │  6. Forward request ──────────────────────────────────►│
  │                                    │                            │                          │
  │                                    │  7. Upstream response ◄──────────────────────────────│
  │                                    │                            │                          │
  │                                    │  8. Emit audit event       │                          │
  │                                    │     (gateway.request)  ───►│                          │
  │                                    │                            │                          │
  │  200 { tools: [...] }             │                            │                          │
  │◄──────────────────────────────────│                            │                          │
```

**stdio mode variation:** For `--stdio` gateways, step 6 writes the MCP JSON-RPC message to the subprocess stdin, and step 7 reads the response from stdout. The gateway manages subprocess lifecycle (spawn on first request, keepalive, restart on crash).

### Gateway Configuration

```python
# Settings additions for Gateway (Layer 2)
gateway_port: int = 8001                  # Gateway listens on separate port
gateway_upstream_timeout: int = 30        # seconds; timeout for upstream MCP server
gateway_stdio_restart: bool = True        # auto-restart crashed stdio subprocesses
gateway_inject_identity: bool = True      # inject X-Agent-Identity header to upstream
```

### Gateway Database Model

```
gateway_configs
├── id                        VARCHAR(26) PK         -- ULID
├── name                      VARCHAR(255) UNIQUE NOT NULL
├── upstream_url              TEXT                   -- HTTP upstream URL (NULL if stdio mode)
├── stdio_command             TEXT                   -- stdio command (NULL if HTTP mode)
├── required_scopes           JSON NOT NULL
├── allowed_agents            JSON                   -- NULL = all agents
├── require_dpop              BOOLEAN DEFAULT FALSE
├── rate_limit                INTEGER                -- per-client requests/min
├── status                    VARCHAR(20) DEFAULT 'active'
├── metadata                  JSON
├── created_at                TIMESTAMP NOT NULL
└── updated_at                TIMESTAMP NOT NULL
```

---

## Layer 3: Credential Vault

Encrypted credential storage with resource proxying. Agents interact with databases and APIs through the vault — they never see raw credentials.

```
authgent_server/
├── endpoints/
│   └── vault.py                     # /vault/credentials CRUD + /vault/{name}/query|proxy
├── services/
│   └── vault_service.py             # Credential CRUD, encryption, proxy dispatch
│       ├── store_credential(name, type, uri, scopes)  # encrypt + persist
│       ├── decrypt_credential(name)                     # in-memory only
│       ├── proxy_query(name, sql, params, token)        # SQL proxy
│       ├── proxy_http(name, method, path, headers, token) # HTTP proxy
│       └── rotate_credential(name, new_uri)             # re-encrypt with new URI
├── vault/
│   ├── __init__.py
│   ├── crypto.py                    # AES-256-GCM encrypt/decrypt
│   ├── postgresql_proxy.py          # asyncpg query execution + SQL validation
│   └── http_proxy.py               # httpx-based HTTP proxy with header injection
├── models/
│   └── vault_credential.py          # VaultCredential SQLAlchemy model
└── schemas/
    └── vault.py                     # VaultCreate, VaultUpdate, VaultResponse, QueryRequest
```

**Encryption architecture:**
```
AUTHGENT_SECRET_KEY
    │
    └── HKDF(info="authgent-vault") → vault_subkey (32 bytes)
        │
        ├── AES-256-GCM encrypt(connection_uri) → encrypted_uri + iv
        │   Stored in vault_credentials.encrypted_uri + .encryption_iv
        │
        └── On proxy request: decrypt in memory → use → discard
            Never logged, never in API response, never in token
```

**SQL validation (PostgreSQL proxy):**
```python
ALLOWED_OPS_BY_SCOPE = {
    "db:read":  {"SELECT", "EXPLAIN"},
    "db:write": {"SELECT", "EXPLAIN", "INSERT", "UPDATE", "DELETE"},
    "db:admin": {"SELECT", "EXPLAIN", "INSERT", "UPDATE", "DELETE",
                 "CREATE", "ALTER", "DROP", "TRUNCATE"},
}
```

### Vault Proxy Flow

```
Agent                  authgent-server               Vault Service              PostgreSQL DB
  │                         │                             │                          │
  │  POST /vault/prod-db/   │                             │                          │
  │    query                │                             │                          │
  │  Authorization: Bearer  │                             │                          │
  │    eyJ...               │                             │                          │
  │  Body: {                │                             │                          │
  │    "sql": "SELECT ...", │                             │                          │
  │    "params": ["eng"]    │                             │                          │
  │  }                      │                             │                          │
  │ ───────────────────────►│                             │                          │
  │                         │                             │                          │
  │                         │  1. Validate JWT             │                          │
  │                         │  2. Look up "prod-db"        │                          │
  │                         │  3. Check token scope        │                          │
  │                         │  4. Validate SQL              │                          │
  │                         │  5. Decrypt credential        │                          │
  │                         │     (IN MEMORY ONLY)         │                          │
  │                         │  6. Execute query ──────────────────────────────────────►│
  │                         │  7. Results ◄──────────────────────────────────────────│
  │                         │  8. Discard decrypted URI     │                          │
  │                         │  9. Emit audit event          │                          │
  │                         │                             │                          │
  │  200 OK                 │                             │                          │
  │  { "rows": [...],       │                             │                          │
  │    "row_count": 2 }     │                             │                          │
  │◄───────────────────────│                             │                          │
```

### Vault Configuration

```python
# Settings additions for Vault (Layer 3)
vault_query_timeout: int = 30             # seconds; max query execution time
vault_max_rows: int = 10000               # max rows returned per query
vault_max_connections: int = 10           # per-credential connection pool size
vault_sql_validation: bool = True         # enable SQL AST validation
```

### VaultResourceProxy Protocol

```python
class VaultResourceProxy(Protocol):
    """Proxy agent requests to a specific resource type using stored credentials."""

    resource_type: str  # "postgresql", "http_api", "mysql", etc.

    async def validate_request(self, request_body: dict, scope: str) -> None: ...
    async def proxy(self, decrypted_uri: str, request_body: dict, timeout: int) -> dict: ...
    async def health_check(self, decrypted_uri: str) -> bool: ...
```

---

## Layer 4: AI Framework Integrations

Each integration is a separate PyPI package. All follow the same pattern:

```python
class AuthgentToolGuard:
    """Wraps framework-specific tool execution with authgent token validation."""

    def require_scopes(self, scopes: list[str]):
        """Decorator that checks token scopes before tool execution."""
        ...
```

**Planned packages:**
- `authgent-langchain` — Tool guards + callback handler
- `authgent-crewai` — Agent permission middleware
- `authgent-openai` — Tool guard decorators
- `authgent-adk` — Google ADK auth plugin
- `authgent-autogen` — Agent capability wrapper

---

## Layer 5: Developer Dashboard

React SPA served as static files from FastAPI at `/ui`.

**Technology:**
- React 18 + Vite + TailwindCSS + shadcn/ui
- Lucide icons, TanStack Query, Recharts
- Disabled via `AUTHGENT_DASHBOARD=false`

**Pages:**
- Agent list + detail (CRUD)
- Active token viewer (introspection)
- Delegation chain visualizer (tree/graph)
- Vault credential manager
- Gateway config manager
- Audit log viewer (filterable, paginated)
- Settings (read-only config viewer)

---

## Delivery Priority

Based on competitive analysis (March 2026), the recommended order is:

1. **Ship core to PyPI/npm/GitHub** — the core is ready, unique, and tested
2. **MCP Gateway** — if user demand materializes (note: 40+ MCP gateways already exist)
3. **Framework Integrations** — when specific framework users ask for them
4. **Credential Vault** — high security responsibility; build only with strong demand
5. **Dashboard** — extend the existing playground before building a full React SPA

See `docs/internal/PRD.md` and `docs/internal/PRD_PART2.md` for full specifications.
