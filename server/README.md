# authgent-server

The open-source OAuth 2.1 Authorization Server for AI agents — MCP-native, delegation-aware, with DPoP sender-constrained tokens and human-in-the-loop step-up authorization.

[![PyPI](https://img.shields.io/pypi/v/authgent-server.svg)](https://pypi.org/project/authgent-server/)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-3776AB.svg)](https://python.org)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](../LICENSE)

## Install

```bash
pip install authgent-server

# With PostgreSQL support
pip install authgent-server[postgres]
```

## Quick Start

```bash
# Start the server (auto-initializes on first run)
authgent-server run
```

Server starts at `http://localhost:8000`:
- `GET /.well-known/oauth-authorization-server` — server metadata
- `GET /.well-known/jwks.json` — public signing keys
- `GET /docs` — interactive Swagger UI

## CLI Commands

```bash
authgent-server run             # Start server (auto-initializes on first run)
authgent-server init            # Explicitly init (custom DB URL, force-regenerate)
authgent-server create-agent    # Register an agent interactively
authgent-server migrate         # Run Alembic migrations
authgent-server migrate --dry-run  # Preview pending migrations
```

## API Endpoints

### OAuth 2.1 Core

| Method | Path | Description |
|:-------|:-----|:------------|
| `POST` | `/register` | Dynamic client registration (RFC 7591) |
| `POST` | `/token` | Token endpoint — all grant types |
| `GET` | `/authorize` | Authorization code + PKCE (consent page) |
| `POST` | `/authorize` | Authorization code (consent submission) |
| `POST` | `/introspect` | Token introspection (RFC 7662) |
| `POST` | `/revoke` | Token revocation (RFC 7009) |

### Device Authorization (RFC 8628)

| Method | Path | Description |
|:-------|:-----|:------------|
| `POST` | `/device/authorize` | Request device + user codes |
| `POST` | `/device/approve` | Human approves device code |
| `POST` | `/device/deny` | Human denies device code |

### Step-Up Authorization (HITL)

| Method | Path | Description |
|:-------|:-----|:------------|
| `POST` | `/stepup` | Create step-up request |
| `GET` | `/stepup/{id}` | Poll step-up status |
| `POST` | `/stepup/{id}/approve` | Human approves |
| `POST` | `/stepup/{id}/deny` | Human denies |

### Agent Identity Registry

| Method | Path | Description |
|:-------|:-----|:------------|
| `POST` | `/agents` | Register agent (auto-creates OAuth client) |
| `GET` | `/agents` | List agents (paginated, filterable) |
| `GET` | `/agents/{id}` | Get agent details |
| `PATCH` | `/agents/{id}` | Update agent |
| `DELETE` | `/agents/{id}` | Deactivate agent |

### Discovery & Health

| Method | Path | Description |
|:-------|:-----|:------------|
| `GET` | `/.well-known/oauth-authorization-server` | Server metadata (RFC 8414) |
| `GET` | `/.well-known/openid-configuration` | OIDC-compatible alias |
| `GET` | `/.well-known/jwks.json` | Public signing keys |
| `GET` | `/.well-known/oauth-protected-resource` | Resource metadata (RFC 9728) |
| `GET` | `/health` | Liveness check |
| `GET` | `/ready` | Readiness (DB + signing keys) |

## Configuration

All settings via `AUTHGENT_*` environment variables. See [`.env.example`](.env.example) for the full list.

### Essential

| Variable | Default | Description |
|:---------|:--------|:------------|
| `AUTHGENT_SECRET_KEY` | *generated* | Master secret for HKDF key derivation |
| `AUTHGENT_DATABASE_URL` | `sqlite+aiosqlite:///./authgent.db` | Database URL |
| `AUTHGENT_HOST` | `0.0.0.0` | Bind address |
| `AUTHGENT_PORT` | `8000` | Bind port |

### Token Lifetimes

| Variable | Default | Description |
|:---------|:--------|:------------|
| `AUTHGENT_ACCESS_TOKEN_TTL` | `900` | Access token (15 min) |
| `AUTHGENT_REFRESH_TOKEN_TTL` | `86400` | Refresh token (24 hr) |
| `AUTHGENT_EXCHANGE_TOKEN_TTL` | `300` | Exchanged token (5 min) |

### Policy

| Variable | Default | Description |
|:---------|:--------|:------------|
| `AUTHGENT_MAX_DELEGATION_DEPTH` | `5` | Max delegation chain hops |
| `AUTHGENT_REQUIRE_DPOP` | `false` | Require DPoP on all token requests |
| `AUTHGENT_CONSENT_MODE` | `auto_approve` | `auto_approve`, `ui`, `headless` |
| `AUTHGENT_REGISTRATION_POLICY` | `open` | `open`, `token`, `admin` |

### Pluggable Providers

| Variable | Default | Description |
|:---------|:--------|:------------|
| `AUTHGENT_ATTESTATION_PROVIDER` | *null* | Dotted import path |
| `AUTHGENT_POLICY_PROVIDER` | *null* | Custom policy enforcement |
| `AUTHGENT_HITL_PROVIDER` | *webhook* | Step-up notification backend |
| `AUTHGENT_KEY_PROVIDER` | *database* | Signing key storage |
| `AUTHGENT_EVENT_EMITTER` | *database* | Audit event backend |
| `AUTHGENT_CLAIM_ENRICHER` | *null* | Custom token claim enrichment |

## Deployment

### Docker

```bash
docker compose up -d
```

The included [`docker-compose.yml`](docker-compose.yml) runs the server with PostgreSQL.

### Docker (standalone)

```bash
docker build -t authgent-server .
docker run -p 8000:8000 \
  -e AUTHGENT_SECRET_KEY=your-secret-key \
  -e AUTHGENT_DATABASE_URL=sqlite+aiosqlite:///./authgent.db \
  authgent-server
```

### Production Checklist

- [ ] Set a strong `AUTHGENT_SECRET_KEY` (64+ characters)
- [ ] Use PostgreSQL (`AUTHGENT_DATABASE_URL=postgresql+asyncpg://...`)
- [ ] Run migrations: `authgent-server migrate`
- [ ] Set `AUTHGENT_REGISTRATION_POLICY=token` or `admin`
- [ ] Set `AUTHGENT_CONSENT_MODE=ui` for human-facing flows
- [ ] Enable DPoP: `AUTHGENT_REQUIRE_DPOP=true`
- [ ] Configure CORS origins: `AUTHGENT_CORS_ORIGINS=["https://your-app.com"]`
- [ ] Put behind a reverse proxy (nginx/Caddy) with TLS
- [ ] Set up log aggregation (structured JSON output)

## Architecture

```
Endpoints → Services → Models → DB
  (thin)    (stateless)  (ORM)   (async)
```

- **Endpoints** — FastAPI routers, HTTP validation, dependency injection
- **Services** — All business logic, receive `db: AsyncSession` per call
- **Models** — SQLAlchemy 2.0 async ORM, 9 tables
- **Providers** — 7 pluggable Python Protocol interfaces (attestation, policy, HITL, keys, events, claim enricher, human auth)

See [ARCHITECTURE.md](../ARCHITECTURE.md) for the full implementation design.

## Development

```bash
# Setup
git clone https://github.com/authgent/authgent.git
cd authgent/server
pip install -e ".[dev,migrations]"
authgent-server init

# Test (192 tests)
pytest -v

# Lint + format
ruff check . && ruff format --check .

# Type check
mypy authgent_server/ --ignore-missing-imports

# Coverage
coverage run -m pytest tests/ && coverage report
```

## License

[Apache 2.0](../LICENSE)
