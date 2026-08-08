# authgent vs Auth0 (for AI Agents)

**Looking for an open-source alternative to Auth0 for AI agents?**
authgent is the closest one: a self-hosted, Apache 2.0 OAuth 2.1 server
built specifically for agent delegation, with reference implementations
of the IETF identity-chaining and transaction-tokens drafts that Auth0's
own agent-identity feature set doesn't implement. This page is a factual
comparison for teams choosing between Auth0 for AI Agents (closed-source
SaaS, GA May 2026) and authgent (open-source self-hosted, Apache 2.0).
Updated June 2026.

## TL;DR

- Pick **Auth0** if you want a fully managed control plane with social
  login, mature SaaS support, and you're comfortable with usage-based
  pricing.
- Pick **authgent** if you want self-hosted code, a working reference
  implementation of the IETF identity-chaining and transaction-tokens
  drafts, signed delegation receipts, an MCP-OAuth scanner, and zero
  per-MAU billing.
- These two **compose**: many teams use Auth0 for human SSO and bridge
  into authgent for the agent delegation layer via authgent's id_token
  exchange.

## Side-by-side

| Capability | Auth0 for AI Agents | authgent |
|---|:-:|:-:|
| OAuth 2.1 (PKCE, refresh rotation, RFC 7591 DCR) | ✅ | ✅ |
| RFC 9728 Protected Resource Metadata | ✅ | ✅ |
| RFC 9207 `iss` parameter (MCP SEP-2468) | ✅ | ✅ |
| RFC 9449 DPoP | `/token` only, opt-in per tenant | All endpoints, opt-in via `AUTHGENT_REQUIRE_DPOP=true` |
| `draft-ietf-oauth-identity-chaining-14` reference impl | ❌ | ✅ |
| `draft-ietf-oauth-transaction-tokens-08` reference impl | ❌ | ✅ |
| RFC 8693 nested-`act` delegation chain | OBO single-hop | ✅ multi-hop |
| Cascading revocation across delegation chains | ❌ | ✅ |
| Token Vault (3rd-party API tokens for agents) | ✅ | manual |
| Async Authorization (CIBA / human approval) | ✅ | ✅ via HITL step-up |
| FGA / fine-grained authorization for RAG | ✅ | bring-your-own |
| Cross-App Access (XAA) | "Coming Soon" | ✅ via identity-chaining |
| MCP-OAuth scanner / lint | ❌ | ✅ `authgent-server lint` |
| Self-host on your own infra | ❌ | ✅ |
| Run inside an air-gapped / regulated environment | ❌ | ✅ |
| Apache 2.0 source + audit-ready | ❌ | ✅ |
| Pricing model | per-MAU + per-feature | $0 (self-host) |

(Sources: <https://auth0.com/ai>, the public MCP Auth docs, and the
linked draft datatracker pages.)

## Where Auth0 wins today

- **Mature SaaS operations.** Auth0 ships pre-baked dashboards, on-call
  support, status page, ISO/SOC compliance package. authgent is OSS;
  you operate it.
- **Social login + identity providers.** Auth0 has hundreds of
  pre-integrated upstream identity providers. authgent supports OIDC
  via id_token exchange but expects you to bring the upstream IdP.
- **Token Vault.** Auth0's Token Vault is a managed feature for
  storing per-user 3rd-party API tokens (Slack, Google, GitHub).
  authgent does not ship one; you can build a similar vault on top of
  the audit-log + agent-credential primitives, but it's not a 1-line
  feature.

## Where authgent wins today

- **You can read the source.** Every claim above is verifiable by a
  one-line `grep` against the repo. STANDARDS.md maps each spec
  section to a file.
- **IETF reference implementations.** Auth0's marketing of "agent
  identity" predates the IETF drafts that define it; authgent ships
  working code for both WG-track drafts.
- **Multi-hop nested-`act` chains + cascading revocation.** Auth0 OBO
  works for a single hop. authgent's chain depth is configurable and
  revoking a chain's root cascades to every already-issued descendant
  token, closing a gap RFC 8693's own text explicitly leaves as
  implementation-specific (see
  `docs/security-advisories/2026-08-non-cascading-revocation.md`).
- **DPoP across the surface.** authgent supports DPoP on `/token`,
  `/authorize` (DPoP key bound at code issuance), `/introspect`, and
  `/revoke` — opt-in via `AUTHGENT_REQUIRE_DPOP=true` (default false
  for compatibility with bearer-only clients like ChatGPT Custom MCP).
  Auth0 has DPoP at `/token` (GA May 2026), opt-in per tenant; other
  endpoints aren't documented as DPoP-aware.
- **MCP-OAuth scanner.** `authgent-server lint <mcp-url>` audits any
  MCP server's OAuth posture against 10 known-bad patterns
  (Obsidian-disclosed CSRF/state, RFC 8707 audience binding, PKCE
  S256, RFC 9207 iss, etc.). Run it in CI via the `authgent/mcp-lint`
  GitHub Action. Nothing equivalent ships from Auth0.
- **No per-MAU billing on the agent side.** Agent tokens issued
  through authgent don't count against your Auth0 MAU bill.

## Compose them

Many teams keep Auth0 for human login and use authgent for the
agent-delegation layer:

```bash
# Bridge an Auth0 id_token into an authgent delegation chain.
curl -X POST http://localhost:8000/token \
  -d "grant_type=urn:ietf:params:oauth:grant-type:token-exchange" \
  -d "subject_token=$AUTH0_ID_TOKEN" \
  -d "subject_token_type=urn:ietf:params:oauth:token-type:id_token"
```

Configure the trusted Auth0 issuer:

```bash
export AUTHGENT_TRUSTED_OIDC_ISSUERS='["https://your-tenant.auth0.com/"]'
```

The `act` chain that descends from the bridged human-rooted token is
visible in authgent's audit log and inspectable via
`authgent-server inspect-token`.

## Migration checklist

If you are **moving** from Auth0 for AI Agents to authgent:

- Map each Auth0 application to an authgent OAuth client (RFC 7591 DCR).
- Replace Auth0 OBO calls with authgent's token-exchange + nested-`act`
  delegation.
- Configure `AUTHGENT_TRUSTED_OIDC_ISSUERS` for your existing Auth0
  tenant so existing id_tokens still work.
- Run `authgent-server lint` against your MCP server in CI.
- See the `examples/` directory for LangChain / OpenAI Agents / CrewAI
  recipes mirroring the Auth0 quickstarts.

## FAQ

**Is there an open-source alternative to Auth0?** Yes — for the AI-agent
delegation layer specifically, authgent is Apache 2.0, self-hosted, and
implements the same OBO-style delegation Auth0 offers, but multi-hop and
with signed receipts. For general human-facing SSO, Keycloak and Ory
Hydra are the broader open-source Auth0 alternatives; see
[authgent vs Keycloak](keycloak.md) and [authgent vs Ory Hydra](ory-hydra.md).

**Can I use Auth0 and authgent together?** Yes — this is the common
pattern. Keep Auth0 for human login and social identity providers;
bridge each authenticated user into authgent via id_token exchange to
get multi-hop agent delegation, signed receipts, and an MCP-OAuth
scanner Auth0 doesn't ship. See "Compose them" above.
