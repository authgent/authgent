# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-03-26

### Added

#### Server (`authgent-server`)
- OAuth 2.1 Authorization Server with FastAPI
- **Grant types**: Client Credentials, Authorization Code + PKCE, Token Exchange (RFC 8693), Refresh Token with rotation, Device Authorization (RFC 8628)
- **Agent Identity Registry** — CRUD endpoints for managing agent identities with auto-generated OAuth clients
- **Multi-hop delegation** — Nested `act` claim construction with configurable depth limits and scope reduction enforcement
- **DPoP (RFC 9449)** — Sender-constrained tokens with stateless HMAC-based nonce generation
- **Human-in-the-loop step-up** — Create, poll, approve, deny step-up authorization requests
- **Token introspection** (RFC 7662) and **revocation** (RFC 7009) with family-based cascade
- **Dynamic client registration** (RFC 7591)
- **Resource indicators** (RFC 8707) for audience restriction
- **OAuth Server Metadata** (RFC 8414) and **Protected Resource Metadata** (RFC 9728)
- **7 pluggable providers** — Attestation, Policy, HITL, Key, Events, ClaimEnricher, HumanAuth (Python Protocol interfaces)
- **ES256 JWT signing** with automatic key generation and AES-256-GCM encryption at rest
- **HKDF key derivation** — Master secret split into purpose-specific subkeys
- **Structured logging** with automatic secret redaction (structlog)
- **Alembic migrations** with CLI `migrate` command
- **Background cleanup jobs** for expired tokens, auth codes, device codes, refresh tokens, step-up requests
- **Docker** support with PostgreSQL via docker-compose
- **Typer CLI** — `init`, `run`, `create-agent`, `migrate`
- **192 tests** — unit, integration, E2E, security, DPoP, delegation, crypto, logging

#### Python SDK (`authgent`)
- `verify_token()` — JWT verification against issuer JWKS
- `verify_delegation_chain()` — Depth, actors, human root policy enforcement
- `verify_dpop_proof()` + `DPoPClient` — DPoP proof generation and verification
- `AgentAuthClient` — Full server API client (register, token, exchange, introspect, revoke)
- `JWKSFetcher` — JWKS cache with TTL and thundering-herd prevention
- **Middleware** — FastAPI (`AgentAuthMiddleware`), Flask (`agent_auth_required`)
- **Middleware** — MCP scope challenge handler with auto step-up
- **Adapters** — MCP auth provider, RFC 9728 Protected Resource Metadata, LangChain tool auth
- **29 tests**

#### TypeScript SDK (`authgent` npm)
- `verifyToken()` — JWT verification via `jose` library
- `verifyDelegationChain()` — Chain policy enforcement
- `verifyDPoPProof()` + `DPoPClient` — DPoP proof and client
- `AgentAuthClient` — Full server API client
- `JWKSFetcher` — JWKS cache with mutex
- **Middleware** — Express 4/5 (`agentAuth`, `requireAgentAuth`)
- **Middleware** — Hono (Node, Bun, Deno, Cloudflare Workers)
- **Adapters** — MCP (`AgentAuthProvider`), RFC 9728 (`ProtectedResourceMetadata`)
- ESM + CJS dual build via tsup
- **47 tests** (vitest)

#### CI/CD
- GitHub Actions: server tests (Python 3.11/3.12/3.13), Python SDK tests, TypeScript SDK tests (Node 18/20/22)
- Linting (ruff), formatting, type checking (mypy), coverage enforcement (80%)

[0.1.0]: https://github.com/authgent/authgent/releases/tag/v0.1.0
