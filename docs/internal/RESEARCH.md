# Agent IAM / Agent Authentication: Market Research & Open-Source Opportunity Analysis

**Date:** March 25, 2026  
**Purpose:** Identify what exists, what's missing, and where to build a high-impact open-source project in the Agent IAM space.

---

## 1. THE LANDSCAPE: Who Is Building What

### 1.1 Protocols & Standards (The Foundation Layer)

| Standard | Owner | Status | What It Does |
|---|---|---|---|
| **Google A2A (Agent2Agent)** | Google Cloud / Linux Foundation | Live, v0.2+ | Open protocol for agent-to-agent communication. Auth is via Agent Cards that declare OAuth security schemes (client_credentials, etc.). Delegates actual auth to external IdPs. |
| **MCP (Model Context Protocol)** | Anthropic | Live, spec dated June 2025 | Standardized agent-to-tool communication. Auth spec mandates **OAuth 2.1** with PKCE. MCP server = OAuth Resource Server. MCP client = OAuth Client. |
| **IETF draft-goswami-agentic-jwt-00** | Goswami et al. | Internet-Draft (new) | "Secure Intent Protocol" — extends OAuth 2.0 with agent checksums (hash of system prompt + tools + config), workflow-bound tokens, and agent-level Proof-of-Possession. Introduces `agent_checksum` grant type. **No reference implementation exists.** |
| **IETF draft-ni-wimse-ai-agent-identity** | Ni & Liu | Internet-Draft (Feb 2026) | WIMSE (Workload Identity in Multi-System Environments) applied to AI agents. Focuses on workload identity attestation. |
| **IETF draft-abbey-scim-agent-extension** | WorkOS-adjacent | Internet-Draft | Extends SCIM with `/Agents` and `/AgenticApplications` resource types for lifecycle provisioning of agent identities alongside human users. |
| **OpenID Foundation** | OpenID | Whitepaper (Oct 2025) | "Identity Management for Agentic AI" — identifies gaps in delegation chains, consent fatigue, high-velocity token issuance. No spec yet. |

### 1.2 Commercial Products (Closed-Source / SaaS)

| Company | Product | What It Does | Pricing |
|---|---|---|---|
| **Auth0 (Okta)** | Auth0 for AI Agents + Token Vault | Full agent auth platform: user auth for agents, Token Vault (secure 3rd-party token storage/exchange), A2A integration, MCP server, CIBA for headless agents. | Freemium / Enterprise |
| **Stytch** | Connected Apps + MCP Auth | OAuth 2.1 implementation for MCP, agent-to-agent OAuth, dynamic client registration, consent management. | Freemium / Enterprise |
| **Scalekit** | Auth stack for AI apps | Authentication middleware for agentic workflows. $5.5M seed. Focus on enterprise SSO + SCIM + agent auth. | Paid |
| **Aembit** | NHI (Non-Human Identity) Platform | Manages service accounts, API keys, agent credentials. Centralized policy enforcement. Hosts NHIcon conference. | Enterprise |
| **Oasis Security** | NHI Governance | Discovers and governs non-human identities (tokens, service accounts, managed identities). | Enterprise |
| **Astrix Security** | NHI Management | Controls API keys, OAuth apps, service accounts. | Enterprise |
| **Strata Identity** | Maverics | OAuth OBO (On-Behalf-Of) + Token Exchange (RFC 8693) for agent delegation chains. Zero-trust identity orchestration. | Enterprise |
| **Permit.io** | agent.security | Fine-grained authorization (RBAC/ABAC/ReBAC) for agentic workflows. Built on OPA + OPAL. Sub-millisecond decisions. | Freemium |
| **Runloop** | Agent Gateway | L7 proxy between agents and APIs. Substitutes auth at infrastructure layer so agents never see real API keys. | Commercial/Closed |
| **LoginRadius** | Agentic IAM | RFC 8693 token exchange for agent delegation. Claims to be building agentic identity architecture. | Enterprise |

### 1.3 Open-Source Projects (What Actually Exists on GitHub)

| Project | Stars | Language | What It Does | Quality Assessment |
|---|---|---|---|---|
| **agentgateway/agentgateway** (Solo.io) | ~2k+ | Rust | Agentic proxy for MCP + A2A. JWT auth, RBAC, OpenAPI-to-MCP transform. Kubernetes-native. | **Production-grade** but extremely heavy. Requires K8s. Not a library — it's infrastructure. |
| **akramIOT/Agentic-IAM** | **9 stars** | Python | Claims comprehensive agent identity framework: RBAC/ABAC/PBAC, DID support, trust scoring, federated identity, SCIM. | **Vaporware.** Massive README, 9 stars, 2 forks. Looks AI-generated. Unlikely to be production-quality. |
| **modelcontextprotocol/python-sdk** | High | Python | Official MCP Python SDK. Recently added OAuth client support (`examples/snippets/clients/oauth_client.py`). | **Official but incomplete** — only client-side OAuth. No turnkey auth server. |
| **rb58853/mcp-oauth** | Low | Python | OAuth system integrated with FastMCP. Server + client implementation. | Small project, limited scope. |
| **atrawog/mcp-oauth-gateway** | Low | Python | OAuth 2.1 Authorization Server for MCP. | Early stage, single maintainer. |
| **NapthaAI/http-oauth-mcp-server** | Low | Python | Remote MCP server with SSE + Streamable HTTP implementing MCP auth extension. | Focused on Naptha's specific use case. |
| **agentic-community/mcp-gateway-registry** | Low | Multiple | Enterprise MCP Gateway with Keycloak OAuth, dynamic tool discovery. | Requires Keycloak — heavy enterprise dependency. |
| **permitio/opal** | ~4k | Python | Policy Administration for OPA. Not agent-specific but used by Permit.io for agent authorization. | **Mature** but it's a policy engine, not an identity system. |

### 1.4 Academic Work

| Paper | Key Contribution |
|---|---|
| **"Agentic JWT" (arXiv:2509.13597)** | Defines the "intent-execution separation problem" — OAuth assumes client faithfully represents user intent, but LLM agents break this. Proposes A-JWT with `act` claims, agent checksums, and workflow-bound tokens. Has a **patent application (19/315,486)** — be careful about direct implementation. |
| **Red Hat Zero Trust for Agentic AI (Feb 2026)** | Argues current agent auth only validates at each local hop, not across the full transaction path. Proposes extending explicit identity/authorization/attestation across full A→(B+C) chains. |

---

## 2. THE GAP ANALYSIS: What Is Missing

### Gap 1: No Open-Source Agentic OAuth Server (The Biggest Gap)

**The problem:** MCP mandates OAuth 2.1. A2A uses OAuth via Agent Cards. Every agent framework needs an OAuth server. But there is **no lightweight, open-source, agent-aware OAuth 2.1 Authorization Server** that developers can `pip install` or `npm install`.

- Auth0, Stytch, Scalekit = all paid SaaS
- Keycloak = massive Java monolith, not agent-aware
- The MCP Python SDK only has the client side
- `mcp-oauth-gateway` and `rb58853/mcp-oauth` are tiny, single-maintainer, incomplete

**Who needs this:** Every developer building MCP servers or A2A agents who doesn't want to pay Auth0 or deploy Keycloak.

### Gap 2: No Reference Implementation of RFC 8693 Token Exchange for Agent Delegation

**The problem:** When Agent A calls Agent B which calls Agent C, the identity chain needs to be preserved. RFC 8693 (Token Exchange) with the `act` (actor) claim is the standard way to do this. Everyone *talks* about it (Strata, LoginRadius, the Agentic JWT paper), but **nobody has shipped an open-source implementation tailored for agents**.

**Who needs this:** Anyone building multi-agent systems (LangGraph, CrewAI, AutoGen, Google ADK) where downstream agents need to know who the original human was.

### Gap 3: No Agent Identity Registry (SCIM for Agents)

**The problem:** The IETF just drafted `draft-abbey-scim-agent-extension` defining `/Agents` and `/AgenticApplications` SCIM endpoints. WorkOS wrote about it. But **nobody has built the open-source implementation**. Today, agent identities are ad-hoc — every framework does it differently.

**Who needs this:** Enterprise teams managing fleets of agents who need lifecycle management (create, rotate credentials, deactivate, audit).

### Gap 4: No Lightweight Agent Auth Middleware for Python/Node

**The problem:** If you're building a FastAPI or Express server that agents will call, there's no `@require_agent_auth` decorator that handles:
- Validating agent JWTs
- Checking delegation chains
- Enforcing scopes per-tool
- Binding tokens to specific agent identities

The agentgateway (Rust/K8s) is overkill. There's no library-level solution.

### Gap 5: DPoP / Proof-of-Possession for Agents (RFC 9449)

**The problem:** Agents log everything. If a bearer token leaks from agent logs or prompt context, anyone can replay it. DPoP (RFC 9449) binds tokens to a sender's cryptographic key. **No agent framework implements this.** The Agentic JWT paper mentions it but has no code.

---

## 3. COMPETITIVE POSITIONING MATRIX

```
                        LIGHTWEIGHT ←────────────────→ HEAVYWEIGHT
                              │                            │
                    OPEN       │                            │
                    SOURCE     │   ★ YOUR SWEET SPOT ★     │  agentgateway (Rust/K8s)
                              │                            │  mcp-gateway-registry (Keycloak)
                              │                            │
                              │   mcp-oauth (tiny)         │
                              │   Agentic-IAM (vaporware)  │
                              │                            │
                    ──────────┼────────────────────────────┤
                              │                            │
                    CLOSED     │   Scalekit                 │  Auth0 for AI Agents
                    SOURCE     │                            │  Stytch Connected Apps
                              │                            │  Aembit / Oasis / Astrix
                              │                            │  Strata Maverics
                              │                            │  Permit.io agent.security
                              │                            │
```

**The open-source, lightweight quadrant is essentially empty.**

---

## 4. MY RECOMMENDATIONS: What To Build

### RECOMMENDATION A (Highest Impact): `agentauth` — The Open-Source Agent OAuth 2.1 Server + SDK

**One-liner:** The open-source Auth0 for AI Agents — a Python library that gives any developer a complete agent identity and auth system in under 5 minutes.

**What it includes:**
1. **OAuth 2.1 Authorization Server** (FastAPI-based) compliant with MCP auth spec
   - `/authorize`, `/token`, `/register` (Dynamic Client Registration for agents)
   - PKCE enforcement, Client Credentials for M2M, Authorization Code for human-delegated
   - CIBA (Client-Initiated Backchannel Auth) for headless agents
2. **RFC 8693 Token Exchange** for multi-agent delegation chains
   - Issues tokens with `act` (actor) claims preserving the full delegation chain
   - `Human → Agent A → Agent B` is cryptographically traceable
3. **Agent Identity Registry** (SQLite/Postgres-backed)
   - Register agents with metadata (name, capabilities, owner, allowed scopes)
   - SCIM-compatible `/Agents` endpoint (aligned with IETF draft)
   - Credential rotation, deactivation, audit log
4. **DPoP (RFC 9449)** Proof-of-Possession support
   - Agents bind tokens to ephemeral keys — leaked tokens are useless
5. **Middleware decorators** for FastAPI, Flask, Express
   - `@require_agent_auth(scopes=["read:data"])` — one line to protect an endpoint
   - Automatically validates JWT, checks delegation chain, enforces scopes
6. **MCP + A2A native integration**
   - Drop-in OAuth provider that MCP clients can discover via `/.well-known/oauth-authorization-server`
   - Generates A2A-compatible Agent Cards with security schemes

**Why it wins:**
- `pip install agentauth` → run `agentauth init` → you have a working agent auth server
- Zero vendor lock-in (SQLite default, Postgres optional)
- Implements 4 RFCs that everyone talks about but nobody has coded: OAuth 2.1 + RFC 8693 + RFC 9449 + SCIM Agent Extension
- Both MCP and A2A compatible out of the box

**Differentiation from existing:**
| vs. | Why `agentauth` wins |
|---|---|
| Auth0 for AI Agents | Free, open-source, self-hosted, no vendor lock-in |
| Stytch | Free, no SaaS dependency, full control |
| agentgateway (Rust/K8s) | Python-native, no K8s needed, library not infrastructure |
| Agentic-IAM (9 stars) | Actually works, backed by real RFCs, not vaporware |
| mcp-oauth / mcp-oauth-gateway | Complete solution vs. minimal proof-of-concept |
| Keycloak | Lightweight (~5MB vs ~500MB), agent-native, Python |

---

### RECOMMENDATION B (High Impact, Narrower): `agentjwt` — Agentic JWT Token Library

**One-liner:** A pure Python/TypeScript library for minting, validating, and chaining agent-aware JWTs with delegation tracking and proof-of-possession.

**What it includes:**
1. Mint JWTs with `act` (actor) claim chains per RFC 8693
2. Agent checksum verification (hash agent config to detect tampering)
3. DPoP key binding (RFC 9449)
4. Intent-bound scopes (scope + task_id + parameter constraints)
5. Token introspection and chain visualization

**Why it could win:** Pure library, zero infrastructure. The "PyJWT but for agents." Every other solution can use this as a building block.

**Risk:** The Agentic JWT paper has a patent application. You'd need to implement the *concepts* (delegation chains, PoP) using standard RFCs without copying their specific architecture.

---

### RECOMMENDATION C (Medium Impact, Very Buildable): `mcpauth` — MCP OAuth Server Reference Implementation

**One-liner:** The missing piece of the MCP ecosystem — a production-ready OAuth 2.1 server that any MCP server can use for authentication.

**What it includes:**
1. Full OAuth 2.1 Authorization Server compliant with `modelcontextprotocol.io/specification/draft/basic/authorization`
2. Dynamic Client Registration (RFC 7591) for MCP clients to self-register
3. `/.well-known/oauth-authorization-server` metadata endpoint
4. FastAPI middleware: `app = MCPAuthServer(app, config)`
5. Built-in token storage (SQLite), user consent UI (optional headless mode)

**Why it could win:** MCP is exploding. The official Python SDK only does the client side. There's no canonical server-side auth. You'd become the default.

**Risk:** Anthropic might ship their own. But as of today, they haven't and there's clear community demand (see Reddit threads asking for MCP OAuth examples).

---

## 5. STRATEGIC RECOMMENDATION

**Build Recommendation A (`agentauth`)** but ship it in phases:

| Phase | Deliverable | Timeline |
|---|---|---|
| **Phase 1** | MCP-compatible OAuth 2.1 server + FastAPI middleware (covers Rec C) | 2-3 weeks |
| **Phase 2** | Agent Registry + Dynamic Client Registration | 1-2 weeks |
| **Phase 3** | RFC 8693 Token Exchange with `act` claims (covers Rec B partially) | 1-2 weeks |
| **Phase 4** | DPoP (RFC 9449) support | 1 week |
| **Phase 5** | A2A Agent Card generation + SCIM Agent endpoints | 1-2 weeks |

Phase 1 alone would already be the most useful open-source project in this space. Each subsequent phase compounds the value.

**Name suggestions:** `agentauth`, `agentgate`, `agentid`, `forgeauth`, `agentsmith`

---

## 6. KEY REFERENCES

- Google A2A Protocol: https://developers.googleblog.com/en/a2a-a-new-era-of-agent-interoperability/
- MCP Auth Spec: https://modelcontextprotocol.io/specification/draft/basic/authorization
- Auth0 + A2A: https://auth0.com/blog/auth0-google-a2a/
- Auth0 Token Vault: https://auth0.com/blog/auth0-token-vault-secure-token-exchange-for-ai-agents/
- Agentic JWT IETF Draft: https://datatracker.ietf.org/doc/draft-goswami-agentic-jwt/
- Agentic JWT arXiv Paper: https://arxiv.org/html/2509.13597v1
- SCIM for Agents IETF Draft: https://www.ietf.org/archive/id/draft-abbey-scim-agent-extension-00.html
- WIMSE AI Agent Identity: https://datatracker.ietf.org/doc/draft-ni-wimse-ai-agent-identity/
- Stytch MCP Auth Guide: https://stytch.com/blog/MCP-authentication-and-authorization-guide/
- WorkOS SCIM for AI: https://workos.com/blog/scim-agents-agentic-applications
- Strata Agentic Identity: https://www.strata.io/blog/agentic-identity/oauth-agentic-identity-zero-trust-ai-6b/
- Red Hat Zero Trust for Agentic AI: https://next.redhat.com/2026/02/26/zero-trust-for-autonomous-agentic-ai-systems/
- Scalekit (Auth for AI): https://www.scalekit.com/blog/oauth-ai-agents-architecture
- agentgateway (Solo.io): https://github.com/agentgateway/agentgateway
- Permit.io OPAL: https://github.com/permitio/opal
- Agentic-IAM (9 stars): https://github.com/akramIOT/Agentic-IAM
