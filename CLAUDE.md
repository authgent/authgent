# CLAUDE.md — authgent project guide

Essential context for AI assistants working on the authgent codebase.
**Follow these rules to keep CI green and avoid breaking the build.**

---

## Project overview

**authgent** is an open-source OAuth 2.1 identity provider for AI agents.
Self-hosted server with multi-hop delegation chain tracking, scope enforcement, DPoP,
human-in-the-loop step-up, and signed delegation receipts.

Monorepo structure with three published packages:

| Package | Path | Language | Registry | URL |
|---------|------|----------|----------|-----|
| `authgent-server` | `server/` | Python 3.11+ | PyPI | [pypi.org/project/authgent-server](https://pypi.org/project/authgent-server/) |
| `authgent` (SDK) | `sdks/python/` | Python 3.11+ | PyPI | [pypi.org/project/authgent](https://pypi.org/project/authgent/) |
| `authgent` (SDK) | `sdks/typescript/` | TypeScript | npm | [npmjs.com/package/authgent](https://www.npmjs.com/package/authgent) |

**GitHub:** [github.com/authgent/authgent](https://github.com/authgent/authgent)
**License:** Apache 2.0

---

## CI pipeline (`.github/workflows/ci.yml`)

CI runs on every push/PR to `main`. **All gates must pass before pushing.**

### Server (`server/` working directory)

```bash
# 1. Lint — zero errors required
ruff check .

# 2. Format — zero diffs required
ruff format --check .

# 3. Type check — zero errors required
mypy authgent_server/ --ignore-missing-imports

# 4. Tests — all must pass, ≥80% coverage
pytest tests/ --ignore=tests/simulation_test.py --ignore=tests/agent_to_agent_simulation.py --ignore=tests/adversarial_live_test.py -v --tb=short

# 5. Coverage (CI enforces minimum)
coverage run -m pytest tests/ --ignore=tests/simulation_test.py --ignore=tests/agent_to_agent_simulation.py --ignore=tests/adversarial_live_test.py -v
coverage report --fail-under=80
```

### Python SDK (`sdks/python/` working directory)

```bash
ruff check .
pytest tests/ -v --tb=short
```

### TypeScript SDK (`sdks/typescript/` working directory)

```bash
npm ci
npm run typecheck
npm run build
npm test
```

### Pre-push checklist (copy-paste one-liner)

```bash
# From server/ directory:
ruff check . && ruff format --check . && mypy authgent_server/ --ignore-missing-imports && pytest tests/ --ignore=tests/simulation_test.py --ignore=tests/agent_to_agent_simulation.py --ignore=tests/adversarial_live_test.py -v --tb=short
```

If `ruff format --check` fails: `ruff format .`
If `ruff check` has auto-fixable errors: `ruff check --fix .`

---

## Ruff configuration

Defined in `server/pyproject.toml`:

- **Line length**: 100 characters (**NOT** the default 88)
- **Target**: Python 3.11
- **Rules**: E, F, I, N, W, UP (pycodestyle, pyflakes, isort, pep8-naming, warnings, pyupgrade)
- **Ignored**: N818 (exception naming)
- **Per-file ignores**: E501 relaxed for `tests/simulation_test.py`, `tests/agent_to_agent_simulation.py`, `migrations/**`

### Common ruff errors and fixes

| Code | Meaning | Fix |
|------|---------|-----|
| E501 | Line too long (>100) | Break line manually — wrap function args, split f-strings |
| I001 | Unsorted imports | `ruff check --fix .` or `ruff format .` |
| F401 | Unused import | Remove the import or add `# noqa: F401` if intentional |
| F541 | f-string without placeholders | Remove the `f` prefix |
| F841 | Unused variable | Remove or prefix with `_` |
| UP037 | Quoted type annotation | Remove quotes; `ruff check --fix .` handles this |

---

## Mypy configuration

Defined in `server/pyproject.toml`:

- **Strict mode** enabled
- `disallow_any_generics = false`
- `warn_unused_ignores = false`
- Model files (`models/*`): `name-defined` errors disabled (SQLAlchemy mapped columns)
- Services/endpoints: `attr-defined` errors disabled

### Common mypy patterns

- `json.loads()` returns `Any` — assign to typed variable: `result: dict[str, Any] = json.loads(...)`
- All functions need type annotations (strict mode). Use `-> Any` for truly dynamic returns.
- Use `# type: ignore[arg-type]` sparingly and only when the type stub is wrong.
- PyJWT `jwt.decode(..., options=...)` needs `# type: ignore[arg-type]` because the stub is wrong.

---

## Test conventions

- **29 test files** in `server/tests/`, auto-discovered by pytest via `tests/` directory.
- **3 excluded files**: `simulation_test.py`, `agent_to_agent_simulation.py`, `adversarial_live_test.py` (require running server).
- New test files named `test_*.py` are automatically included — **no registration needed**.
- Fixtures in `tests/conftest.py` provide `test_client`, `db_session`, `test_keys`.
- Async tests use `pytest-asyncio` with `asyncio_mode = "auto"`.
- `conftest.py` sets env vars: `AUTHGENT_SECRET_KEY`, `AUTHGENT_DATABASE_URL=sqlite+aiosqlite:///:memory:`, etc.
- Every test gets a fresh in-memory SQLite DB via `db_session` fixture.
- `test_client` fixture calls `reset_settings()` + `reset_providers()` to avoid state leaking between tests.

### Test file inventory

| File | What it tests |
|------|---------------|
| `test_token.py` | Client credentials, invalid secret, wrong content type, unsupported grant |
| `test_token_advanced.py` | Token exchange, auth code PKCE, refresh rotation, delegation receipts |
| `test_token_check.py` | `/token/check` endpoint — scope/audience validation |
| `test_token_expiry.py` | Token TTL enforcement |
| `test_token_inspect.py` | `/tokens/inspect` — JWT decode, delegation chain display |
| `test_agents.py` | Agent CRUD, token exchange grant, scope propagation |
| `test_security.py` | Forgery, escalation, replay, revocation attacks |
| `test_delegation.py` | Single/multi-hop act claims, depth limit, scope reduction |
| `test_dpop.py` | DPoP nonce, proof verification, binding |
| `test_dpop_integration.py` | DPoP end-to-end with token endpoint |
| `test_external_oidc.py` | External OIDC id_token exchange (Auth0/Clerk/Okta bridge) |
| `test_registration_policy.py` | open/token/admin registration policies |
| `test_real_world_agents.py` | Multi-agent scenarios (orchestrator, search, DB agents) |
| `test_stepup.py` | HITL step-up create/approve/deny/poll |
| `test_health.py` | `/health` and `/ready` endpoints |
| `test_wellknown.py` | OAuth/OIDC discovery metadata, JWKS, protected resource |
| `test_introspect.py` | Token introspection (RFC 7662) |
| `test_revoke.py` | Token revocation |
| `test_register.py` | Dynamic client registration (RFC 7591) |
| `test_authorize.py` | Authorization code flow + consent |
| `test_device.py` | Device authorization grant (RFC 8628) |
| `test_hitl_provider.py` | HITL provider webhook delivery |
| `test_integration_workflows.py` | Cross-cutting integration flows |
| `test_error_handler.py` | Error handler middleware |
| `test_log_redaction.py` | Secret redaction in structured logs |
| `test_crypto.py` | HKDF derivation, AES-256-GCM encrypt/decrypt |
| `test_audit_endpoint.py` | `/audit` endpoint |
| `test_cli_phase0.py` | CLI commands (init, create-agent, etc.) |
| `adversarial_live_test.py` | **Excluded from CI** — 69-test adversarial suite (requires live server) |

---

## Architecture

### Layered design: Endpoints → Services → Models → DB

**No endpoint touches SQLAlchemy directly.** Endpoints validate input and delegate to services.
Services are stateless — they receive `db: AsyncSession` per call.

### Directory structure

```
server/
├── authgent_server/
│   ├── app.py              # FastAPI app factory, lifespan, 7 background cleanup tasks
│   ├── cli.py              # Typer CLI — 14 commands (see CLI section)
│   ├── config.py           # Pydantic Settings (all AUTHGENT_* env vars)
│   ├── crypto.py           # HKDF (RFC 5869) + AES-256-GCM for signing keys at rest
│   ├── db.py               # Async SQLAlchemy engine + session factory (SQLite/PostgreSQL)
│   ├── dependencies.py     # FastAPI DI — wires services + providers + registration auth
│   ├── errors.py           # 12 error classes (RFC 9457 Problem Details + OAuth error codes)
│   ├── logging.py          # structlog + secret redaction (33 sensitive key patterns)
│   ├── endpoints/          # 13 route modules
│   ├── middleware/         # CORS, error handler, rate limit, request ID, input sanitization
│   ├── models/             # 13 SQLAlchemy ORM models
│   ├── providers/          # 7 pluggable Protocol interfaces + default implementations
│   ├── schemas/            # Pydantic request/response schemas
│   ├── services/           # 10 business logic services
│   └── templates/          # Jinja2 consent page
├── tests/                  # 29 test files, ~345 tests
├── migrations/             # Alembic (alembic.ini + env.py + versions/)
└── Dockerfile
```

### Endpoints (13 route modules)

| Module | Routes | Purpose |
|--------|--------|---------|
| `token.py` | `POST /token` | OAuth 2.1 token endpoint (all 5 grant types) |
| `token_check.py` | `POST /token/check` | Pre-flight scope/audience validation |
| `token_inspect.py` | `GET /tokens/inspect` | Decode JWT + show delegation chain (no auth) |
| `authorize.py` | `GET/POST /authorize` | Authorization code flow + consent UI |
| `register.py` | `POST /register` | Dynamic client registration (RFC 7591) |
| `introspect.py` | `POST /introspect` | Token introspection (RFC 7662) |
| `revoke.py` | `POST /revoke` | Token revocation (RFC 7009) |
| `device.py` | `POST /device/authorize`, `POST /device/verify` | Device authorization (RFC 8628) |
| `stepup.py` | `POST /stepup`, `GET /stepup/{id}`, `POST /stepup/{id}/approve` | HITL step-up |
| `agents.py` | `POST/GET/PATCH/DELETE /agents` | Agent CRUD with registration auth |
| `audit.py` | `GET /audit` | Audit log query |
| `wellknown.py` | `GET /.well-known/*` | OAuth metadata, OIDC config, JWKS, protected resource |
| `health.py` | `GET /health`, `GET /ready` | Liveness + readiness probes |

### Services (10 modules)

| Service | Purpose |
|---------|---------|
| `token_service.py` | Grant type dispatch, JWT issuance, token exchange, blocklist |
| `jwks_service.py` | ES256 key management, JWT signing/verification, key rotation |
| `delegation_service.py` | Nested `act` claim construction, depth/scope enforcement |
| `dpop_service.py` | DPoP proof verification, HMAC nonce generation/validation |
| `audit_service.py` | Audit event recording via EventEmitter provider |
| `agent_service.py` | Agent CRUD, scope management, lifecycle |
| `client_service.py` | OAuth client authentication (client_credentials verification) |
| `consent_service.py` | Authorization consent management |
| `stepup_service.py` | HITL step-up request lifecycle |
| `external_oidc.py` | External IdP JWKS fetching + id_token verification (Auth0/Clerk/Okta) |

### Models (13 SQLAlchemy tables)

`OAuthClient`, `Agent`, `AuthorizationCode`, `RefreshToken`, `DeviceCode`, `Consent`,
`SigningKey`, `TokenBlocklist`, `AuditLog`, `DelegationReceipt`, `StepUpRequest`, `User`, `Base`

All use ULIDMixin (ULID primary keys) and TimestampMixin (created_at/updated_at).

### Providers (7 pluggable Protocol interfaces)

| Protocol | Default Implementation | Failure Mode |
|----------|----------------------|--------------|
| `AttestationProvider` | `NullAttestationProvider` | Fail-closed |
| `PolicyProvider` | `ScopePolicyProvider` | Fail-closed |
| `HITLProvider` | `WebhookHITLProvider` | Fail-closed |
| `KeyProvider` | `DatabaseKeyProvider` | Fail-closed |
| `EventEmitter` | `DatabaseEventEmitter` | Fail-open |
| `ClaimEnricher` | None (optional) | Fail-open |
| `HumanAuthProvider` | Builtin (defined in protocols.py) | Fail-closed |

Providers are configured via dotted import paths in `AUTHGENT_*_PROVIDER` env vars.

### Error hierarchy (`errors.py`)

Base: `AuthgentError` → returns RFC 9457 Problem Details JSON + OAuth error codes.

Subclasses: `InvalidGrant` (400), `InvalidClient` (401), `InsufficientScope` (403),
`InvalidRequest` (400), `UnsupportedGrantType` (400), `InvalidDPoPProof` (401),
`UseDPoPNonce` (401), `DelegationDepthExceeded` (403), `ScopeEscalation` (403),
`MayActViolation` (403), `TokenRevoked` (401), `StepUpRequired` (403),
`AgentNotFound` (404), `AccessDenied` (403).

### Grant types (TokenService dispatch)

| Grant Type | Handler | RFC |
|------------|---------|-----|
| `client_credentials` | `_handle_client_credentials` | OAuth 2.1 |
| `authorization_code` | `_handle_authorization_code` | OAuth 2.1 + PKCE |
| `refresh_token` | `_handle_refresh_token` | OAuth 2.1 |
| `urn:ietf:params:oauth:grant-type:token-exchange` | `_handle_token_exchange` | RFC 8693 |
| `urn:ietf:params:oauth:grant-type:device_code` | `_handle_device_code` | RFC 8628 |

Token exchange dispatches on `subject_token_type`:
- `urn:ietf:params:oauth:token-type:access_token` → verify against internal JWKS
- `urn:ietf:params:oauth:token-type:id_token` → verify against external IdP JWKS (Auth0/Clerk/Okta)

### CLI commands (14 in `cli.py`)

`run`, `init`, `create-agent`, `list-agents`, `get-token`, `exchange-token`,
`inspect-token`, `audit`, `status`, `rotate-keys`, `create-user`, `openapi`,
`migrate`, `quickstart`

`authgent-server run` auto-initializes on first start (creates `.env` + secret key if missing).

### Background cleanup tasks (`app.py`)

7 tables cleaned on schedule: `token_blocklist` (1h), `authorization_codes` (15m),
`device_codes` (15m), `refresh_tokens` (1h), `stepup_requests` (1m),
`audit_log` (daily, 90-day retention), `delegation_receipts` (daily, 30-day retention).

### Crypto

- **Signing**: ES256 (ECDSA P-256) for JWTs
- **Key derivation**: HKDF-SHA256 from master secret → subkeys for DPoP nonces, CSRF, sessions, KEK
- **Key encryption at rest**: AES-256-GCM (nonce:ciphertext hex format)
- **Logging**: structlog with redaction of 33 sensitive patterns (tokens, secrets, passwords)

---

## Configuration (AUTHGENT_* env vars)

All config via Pydantic Settings in `config.py`. Env prefix: `AUTHGENT_`.

**Key settings**: `SECRET_KEY`, `DATABASE_URL`, `HOST`, `PORT`, `ACCESS_TOKEN_TTL`,
`REFRESH_TOKEN_TTL`, `EXCHANGE_TOKEN_TTL`, `MAX_DELEGATION_DEPTH`, `REQUIRE_DPOP`,
`REGISTRATION_POLICY` (open/token/admin), `CONSENT_MODE` (auto_approve/ui/headless),
`TRUSTED_OIDC_ISSUERS` (JSON list), `TRUSTED_OIDC_AUDIENCE`, `CORS_ORIGINS`,
`TOKEN_RATE_LIMIT`, `WEBHOOK_URL`, `HITL_SCOPES`.

See `server/.env.example` for the complete list with defaults.

---

## SDK architecture

### Python SDK (`sdks/python/authgent/`)

| Module | Purpose |
|--------|---------|
| `verify.py` | `verify_token()` — JWT verification against JWKS |
| `delegation.py` | `verify_delegation_chain()` — depth, actors, human root |
| `dpop.py` | `DPoPClient` + `verify_dpop_proof()` |
| `jwks.py` | `JWKSFetcher` with TTL cache + thundering-herd mutex |
| `client.py` | `AgentAuthClient` — register, get/exchange/refresh/revoke/introspect tokens |
| `models.py` | `AgentIdentity`, `DelegationChain`, `TokenClaims` dataclasses |
| `errors.py` | `AuthgentError` hierarchy (4 subclasses) |
| `middleware/fastapi.py` | `AgentAuthMiddleware` + `get_agent_identity` |
| `middleware/flask.py` | Flask middleware (sync wrapper) |
| `middleware/scope_challenge.py` | MCP scope challenge + HITL step-up auto-detection |
| `adapters/mcp.py` | `AgentAuthProvider` for MCP servers |
| `adapters/protected_resource.py` | RFC 9728 metadata generator |
| `adapters/langchain.py` | `AuthgentToolWrapper` for LangChain |

### TypeScript SDK (`sdks/typescript/src/`)

Mirrors the Python SDK API surface. Uses `jose` for JWT (works Node + edge + browser).
ESM-first, dual CJS compat, tree-shakeable. 1 runtime dependency (`jose`).

Modules: `verify.ts`, `delegation.ts`, `dpop.ts`, `jwks.ts`, `client.ts`, `models.ts`,
`errors.ts`, `scope-challenge.ts`, `middleware/express.ts`, `middleware/hono.ts`,
`adapters/mcp.ts`, `adapters/protected-resource.ts`.

---

## Publishing

### PyPI (authgent-server + authgent SDK)

Script: `publish.sh` at repo root.

```bash
export PYPI_TOKEN="your-token"
./publish.sh both                   # publish both, auto-increment patch
./publish.sh server --bump minor    # server only, bump minor
./publish.sh sdk                    # SDK only, auto-increment patch
```

Targets: `server/` → `authgent-server`, `sdks/python/` → `authgent`.
Version is in `pyproject.toml` + `__init__.py` for each package.

### npm (authgent TypeScript SDK)

Script: `publish_npm.sh` at repo root.

```bash
export NPM_TOKEN="your-token"
./publish_npm.sh                    # publish at current version
./publish_npm.sh --bump patch       # bump patch and publish
```

Target: `sdks/typescript/` → `authgent`.
Version is in `package.json`.

**Note:** `react-headless-auth` and `flask-headless-auth` are unrelated and not touched by these scripts.

---

## Environment & dev setup

- **Do NOT run `authgent-server init`** on an existing dev setup — it overwrites `.env`.
- `authgent-server run` auto-initializes on first start (generates `.env` + secret key if missing).
- The existing `server/.env` has `AUTHGENT_SECRET_KEY` and DB config. Use `authgent-server run` directly.
- Tests use in-memory SQLite (`sqlite+aiosqlite:///:memory:`) — no disk DB needed.

### Install dependencies

```bash
# Server
cd server && pip install -e ".[dev]"

# Python SDK
cd sdks/python && pip install -e ".[dev]"

# TypeScript SDK
cd sdks/typescript && npm ci
```

---

## Code style

- **Imports**: Always at top of file. Use `from __future__ import annotations` in typed modules.
- **Line length**: 100 chars max. Break long signatures by putting each arg on its own line.
- **Type annotations**: Required on all public functions (mypy strict).
- **Docstrings**: Triple-quoted strings. One-line for simple, multi-line for complex.
- **Comments**: Do not add or remove existing comments unless asked.
- **f-strings**: Only use when there are actual placeholders.
- **Commit messages**: Conventional Commits (`feat:`, `fix:`, `docs:`, `test:`, `chore:`).

### Line-breaking patterns

```python
# Function signatures
def my_function(
    arg1: str,
    arg2: int,
    arg3: bool = False,
) -> dict[str, Any]:

# Decorators with many args
@router.post(
    "/path",
    response_model=MyModel,
    status_code=201,
    dependencies=[Depends(my_dep)],
)

# Long f-strings — split into variables
scope_val = "enforced" if settings.flag else "disabled"
table.add_row("Label", scope_val)
```

### Architecture rules

- **Endpoints** are thin — validation + delegation to services.
- **Services** are stateless — receive `db: AsyncSession` per call.
- **Providers** use Protocol interfaces — never import concrete implementations in services.
- **Fail-closed** for security-critical providers (Policy, Attestation, HITL).
- **Fail-open** for audit/event providers.
- Never log secrets — check `logging.py` `_NEVER_LOG_KEYS` set.

---

## Dependency injection (`dependencies.py`)

FastAPI DI wires everything. Key functions:

- `get_db_session()` → `AsyncSession`
- `get_token_service()` → `TokenService` (wired with JWKS, delegation, audit, external_oidc)
- `get_agent_service()` → `AgentService`
- `get_providers()` → `ProviderSet` (loaded from config dotted paths)
- `require_registration_auth()` → enforces `registration_policy` on `/agents` and `/register`
- `reset_settings()` / `reset_providers()` — used in tests to avoid state leaking

---

## Examples (`examples/` directory)

| Example | Description |
|---------|-------------|
| `quickstart/` | 60-second demo — register, delegate, revoke |
| `fastapi_protected/` | Before/after endpoint protection (3-line diff) |
| `pipeline/` | Orchestrator → Search → DB with scope narrowing |
| `mcp_server/` | MCP server with authgent as OAuth provider |
| `langchain_tool/` | AuthgentToolWrapper for automatic token management |
| `openai_agents/` | Auth pattern for multi-agent orchestration + handoffs |
| `crewai/` | Per-agent identity + scoped tokens for crew members |

---

## Common pitfalls

1. **Forgetting `ruff format`** — `ruff check` can pass but format can still fail. Always run both.
2. **Line length 100, not 88** — This project uses 100-char lines, not the ruff default.
3. **`json.loads` and mypy** — Always assign to a typed variable to avoid `no-any-return`.
4. **New test files** — Just create `tests/test_*.py`; pytest auto-discovers. No config changes needed.
5. **Simulation tests** — `simulation_test.py` and `agent_to_agent_simulation.py` are ignored in CI.
6. **`from __future__ import annotations`** — Used in most modules. Don't remove it.
7. **`reset_settings()` in tests** — Call it when monkeypatching env vars to force config reload.
8. **`await db.commit()`** — TokenService methods need explicit commits after audit log writes.
9. **Token exchange error handling** — `_handle_token_exchange` wraps verification in try/except, re-raises `InvalidRequest`/`TokenRevoked`, converts other exceptions to `InvalidGrant`.
10. **Publishing** — Use `publish.sh` for PyPI, `publish_npm.sh` for npm. Both scripts handle version bumping, building, and uploading. Never manually edit version strings.
11. **Revoke requires client auth** — `POST /revoke` requires both `client_id` and `client_secret` (or HTTP Basic). Token ownership is enforced: only the token's issuing client can revoke it (RFC 7009 §2.1). All test helpers that call `/revoke` must pass `client_secret`.
12. **Null bytes in form data** — `InputSanitizationMiddleware` (pure ASGI) rejects requests with `\x00` or `%00` in form bodies. Without this, null bytes crash uvicorn's HTTP parser. The middleware must be registered via `app.add_middleware()` — it runs before Starlette's form parser.
13. **Agent name validation** — `AgentCreate.name` has `min_length=1` and `max_length=255`. Always validate boundary inputs in Pydantic schemas.

---

## Standards compliance

| Standard | Implementation |
|----------|---------------|
| OAuth 2.1 | Core framework, PKCE required |
| RFC 7591 | Dynamic Client Registration |
| RFC 7636 | PKCE (S256) |
| RFC 7662 | Token Introspection |
| RFC 8628 | Device Authorization Grant |
| RFC 8693 | Token Exchange (delegation) |
| RFC 8707 | Resource Indicators |
| RFC 9449 | DPoP Sender-Constrained Tokens |
| RFC 9457 | Problem Details for HTTP APIs |
| RFC 8414 | OAuth Server Metadata |
| RFC 9728 | Protected Resource Metadata |
| MCP Auth Spec | MCP authorization flow |
