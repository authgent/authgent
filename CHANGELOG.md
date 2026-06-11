# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.1] - 2026-06-10

### Added — IETF reference implementation + MCP-spec hardening

- **`draft-ietf-oauth-identity-chaining-14`** (IESG: Approved-announcement
  to be sent / Revised I-D Needed): cross-domain delegation. New
  `requested_token_type=urn:ietf:params:oauth:token-type:jwt` in
  token-exchange mints a short-lived audience-bound JWT authorization
  grant (§2.3). New `urn:ietf:params:oauth:grant-type:jwt-bearer`
  consumes the grant and issues a Domain-B access token (§2.4 + RFC 7523).
  Single-use replay protection via `token_blocklist` (§5.5); refresh
  tokens omitted (§5.4); pluggable claims transcription (§2.5) with
  `preserve_sub` (default) and `minimize` policies. Metadata advertises
  `identity_chaining_requested_token_types_supported` (§3).
- **`draft-ietf-oauth-transaction-tokens-08`** (in WG Last Call):
  Transaction Token Service. `requested_token_type=...:txn_token` mints
  `typ: txntoken+jwt` JWTs with `txn`, `tctx`, `rctx`, `req_wl` claims
  (§3). Scope-subset enforcement (§7.2). Short-lived TTL (§7). No refresh
  tokens (§11).
- **MCP 2026-07-28 spec compliance**:
  - **SEP-2468 / RFC 9207** — `iss=` parameter on every `/authorize`
    redirect (success and `error=access_denied`).
  - **SEP-2351 / RFC 8414 §3.1** — path-suffixed metadata at
    `/.well-known/oauth-authorization-server/{path}` and
    `/.well-known/oauth-protected-resource/{path}` with rewritten
    `issuer` / `resource`.
  - **SEP-2350 / RFC 6750 §3.1** — `WWW-Authenticate` on
    `insufficient_scope` carries `scope="..."` with the missing scopes
    so MCP clients can do client-side scope accumulation.
  - **RFC 7591** — DCR accepts and persists `software_id`,
    `software_version`, `software_statement` (alembic migration `002`).
- **`authgent-server lint <mcp-url>`** — MCP-OAuth conformance scanner
  with 10 checks mapped to known CVE-class issues (Obsidian Jan 2026
  disclosure, RFC 8707 confused-deputy, PKCE plain, RFC 9207 iss, RFC
  8693, RFC 9449, RFC 9728, DCR mirror). Three output formats: human,
  JSON, GitHub Actions workflow-command annotations. Wrappable via the
  in-repo composite Action at `.github/actions/mcp-lint`.
- **MCP example rewrite** using the official `mcp` Python SDK with both
  HTTP (`mcp_server.py`) and stdio (`stdio_server.py`) transports.
- New env vars: `AUTHGENT_TRUSTED_CHAINING_TARGETS`,
  `AUTHGENT_TRUSTED_CHAINING_ISSUERS`, `AUTHGENT_CHAINING_GRANT_TTL`,
  `AUTHGENT_CHAINING_CLAIMS_POLICY`, `AUTHGENT_TXN_TOKEN_TRUST_DOMAIN`,
  `AUTHGENT_TXN_TOKEN_TTL`.
- SDK helpers: Python `start_identity_chain` / `consume_identity_chain`
  / `issue_transaction_token`. TypeScript `startIdentityChain` /
  `consumeIdentityChain` / `issueTransactionToken`.
- New docs: `STANDARDS.md` (per-section spec → file:line map),
  `docs/identity-chaining.md`, `docs/transaction-tokens.md`,
  `docs/mcp-quickstart.md` (Claude Desktop / Cursor / Claude Code /
  Continue / VS Code MCP / ChatGPT configs), `docs/compatibility-matrix.md`,
  `docs/compare/{auth0,keycloak,ory-hydra}.md`, `CITATION.cff`,
  `OUTREACH.md`, `drafts/draft-agnihotri-oauth-agent-action-transparency-00.md`.
- 48 new tests (`test_identity_chaining.py`, `test_transaction_tokens.py`,
  `test_scanner.py`, plus regression tests for the four MCP SEPs)
  bringing the suite to 420.

### Security

- `server/.env.production` removed from git tracking; all `*.env.production`
  patterns added to `.gitignore`.

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
- **244 tests** — unit, integration, E2E, security, DPoP, delegation, crypto, logging, external OIDC

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
