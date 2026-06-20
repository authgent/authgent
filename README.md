<div align="center">

# authgent

### Grade your MCP server's OAuth posture against the RFCs that actually matter.

An open-source MCP-OAuth conformance scanner — and a public registry of how
the major vendors (Notion, Cloudflare, Linear, Descope, Asana, Square, Box,
HubSpot) grade today against [RFC 7636](https://datatracker.ietf.org/doc/html/rfc7636),
[RFC 8414](https://datatracker.ietf.org/doc/html/rfc8414),
[RFC 8707](https://datatracker.ietf.org/doc/html/rfc8707),
[RFC 9207](https://datatracker.ietf.org/doc/html/rfc9207),
[RFC 9728](https://datatracker.ietf.org/doc/html/rfc9728),
and the [MCP 2025-11-25 authorization spec](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization).

- **`authgent-server lint <mcp-url>`** — 10 RFC-mapped checks, A–F grade,
  embeddable badge. CLI + GitHub Action + hosted at
  [authgent.dev/scan/](https://authgent.dev/scan/).
- **Public registry**: [authgent.dev/registry/](https://authgent.dev/registry/).
- **MCP-PKCE-002 — PKCE advertise-drift**: a public-scanner heuristic for
  the discovery-vs-`/authorize` sub-variant of the known [PKCE-downgrade family](docs/attacks/pkce-drift.md)
  (builds on [OAuch BCP_4_8](https://oauch.io/Threats/Info/BCP_4_8) and
  [Better-Auth GHSA-9h47-pqcx-hjr4](https://github.com/better-auth/better-auth/security/advisories/GHSA-9h47-pqcx-hjr4)).

If you fail the scanner, you can run [`pip install authgent-server`](#run-the-server)
to fix what it found — a reference OAuth 2.1 server implementing
[`draft-ietf-oauth-identity-chaining-14`][icn] and
[`draft-ietf-oauth-transaction-tokens-08`][txntok].

Apache 2.0 · 508 tests · 3 published packages · IETF Internet-Draft on datatracker.

[icn]: https://datatracker.ietf.org/doc/draft-ietf-oauth-identity-chaining/
[txntok]: https://datatracker.ietf.org/doc/draft-ietf-oauth-transaction-tokens/
[rfc8693]: https://datatracker.ietf.org/doc/html/rfc8693
[rfc9449]: https://datatracker.ietf.org/doc/html/rfc9449

[![CI](https://github.com/authgent/authgent/actions/workflows/ci.yml/badge.svg)](https://github.com/authgent/authgent/actions/workflows/ci.yml)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/authgent/authgent/badge)](https://securityscorecards.dev/viewer/?uri=github.com/authgent/authgent)
[![PyPI - Server](https://img.shields.io/pypi/v/authgent-server?label=authgent-server&color=blue)](https://pypi.org/project/authgent-server/)
[![PyPI - SDK](https://img.shields.io/pypi/v/authgent?label=authgent%20SDK&color=blue)](https://pypi.org/project/authgent/)
[![npm](https://img.shields.io/npm/v/authgent?label=authgent%20npm&color=CB3837)](https://www.npmjs.com/package/authgent)
[![PyPI Downloads](https://img.shields.io/pypi/dm/authgent-server?label=monthly%20downloads&color=10b981)](https://pypistats.org/packages/authgent-server)
[![IETF Draft](https://img.shields.io/badge/IETF-draft--agnihotri--oauth--agent--impl--status-orange)](https://datatracker.ietf.org/doc/draft-agnihotri-oauth-agent-impl-status/)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Cite](https://img.shields.io/badge/cite-CITATION.cff-9cf.svg)](CITATION.cff)

[Home](https://authgent.dev/home/) · [Scanner](https://authgent.dev/scan/) · [Registry](https://authgent.dev/registry/) · [PKCE Advertise-Drift](docs/attacks/pkce-drift.md) · [Standards Report](STANDARDS.md) · [MCP Quickstart](docs/mcp-quickstart.md) · [Architecture](ARCHITECTURE.md)

</div>

---

## Audit any MCP server in 10 seconds

```bash
pip install authgent-server
authgent-server lint https://your-mcp-server.example.com
```

```text
[CRITICAL] MCP-PRM-001: Missing Protected Resource Metadata
[ERROR]    MCP-PKCE-002: PKCE method not enforced at /authorize (advertise-vs-enforce drift)
[ERROR]    MCP-AUD-001: RFC 8707 resource indicators not supported
```

Or paste a URL into the [hosted scanner](https://authgent.dev/scan/),
embed an [SVG badge](https://authgent-demo.dhruvagnihotri.com/api/badge?url=https://mcp.example.com)
in your README, or wire the [GitHub Action](.github/actions/mcp-lint/README.md) into CI.

The same code path runs in all three places. The [methodology](docs/methodology.md)
documents every check, the [calibration set](docs/calibration.md) pins the expected
grades for known-good and known-bad shapes (asserted in CI), and the
[disclosure policy](docs/disclosure-policy.md) governs the registry's
14-day responsible-disclosure window.

---

## Who this is for

| Persona | What you get | Where to start |
|---|---|---|
| **MCP-server developer** — *"is my OAuth right?"* | A 10-check audit + an embeddable A–F grade badge. Run in CI on every PR. | [`authgent-server lint`](#audit-any-mcp-server-in-10-seconds) |
| **Security engineer** — *"how does the MCP ecosystem grade against the RFCs?"* | Public registry of how named MCP vendors score. Named-finding catalog with prior-art citations. | [Registry](https://authgent.dev/registry/) · [PKCE Advertise-Drift](docs/attacks/pkce-drift.md) |
| **MCP-server operator who failed the scan** — *"how do I fix this?"* | A drop-in OAuth 2.1 AS designed not to fail its own scanner. | [Run the server](#run-the-server) |
| **IETF / spec implementer** — *"a free reference impl to test against."* | Apache-2.0 implementation of identity-chaining-14 + transaction-tokens-08, section-by-section conformance map. | [Standards Report](STANDARDS.md) |

---

## What the scanner checks

Each check ID is a stable identifier you can suppress in CI, link to in a PR
comment, or cite in a disclosure email. Findings are tiered: `spec_required`
findings drive the letter grade; `advisory` findings are informational.

| Check ID | What it flags | Spec |
|---|---|---|
| `MCP-PRM-001` | RFC 9728 Protected Resource Metadata missing or malformed | [RFC 9728](https://datatracker.ietf.org/doc/html/rfc9728) |
| `MCP-AS-001` | RFC 8414 Authorization Server Metadata missing | [RFC 8414](https://datatracker.ietf.org/doc/html/rfc8414) |
| `MCP-PKCE-001` | `code_challenge_methods_supported` lacks `S256` or includes `plain` | [RFC 7636](https://datatracker.ietf.org/doc/html/rfc7636) |
| `MCP-PKCE-002` | **PKCE advertise-drift** — `S256`-only in metadata, `plain` accepted at `/authorize` (sub-variant of [PKCE downgrade](https://oauch.io/Threats/Info/BCP_4_8)) | [pkce-drift.md](docs/attacks/pkce-drift.md) |
| `MCP-AUD-001` | RFC 8707 resource indicators not supported | [RFC 8707](https://datatracker.ietf.org/doc/html/rfc8707) |
| `MCP-DCR-001` | Dynamic Client Registration not advertised | [RFC 7591](https://datatracker.ietf.org/doc/html/rfc7591) |
| `MCP-DCR-MIRROR-001` | DCR returns identical `client_id` for distinct registrations (Obsidian Jan 2026) | [Obsidian disclosure](https://www.obsidiansecurity.com/blog/when-mcp-meets-oauth-common-pitfalls-leading-to-one-click-account-takeover) |
| `MCP-CSRF-001` | Implicit grant advertised (`response_type=token`) | OAuth 2.1 |
| `MCP-ISS-001` | RFC 9207 `iss` parameter not advertised (advisory) | [RFC 9207](https://datatracker.ietf.org/doc/html/rfc9207) |
| `MCP-REFRESH-001` | Refresh tokens issued without DPoP support (advisory) | [RFC 9449](https://datatracker.ietf.org/doc/html/rfc9449) |
| `MCP-PASSTHROUGH-001` | Tool endpoints answer 200 unauthenticated (heuristic, advisory) | MCP 2025-11-25 |

---

## Run the server

If you failed the scanner — or you're starting fresh and want OAuth 2.1
that ships RFC 8707, RFC 9207, RFC 9449, and identity-chaining out of the
box — install authgent-server:

```bash
pip install authgent-server
authgent-server run     # auto-init, listens on http://localhost:8000
```

That's it. Auto-generates `.env` + ES256 signing keys on first run.
SQLite by default; set `AUTHGENT_DATABASE_URL=postgresql+asyncpg://…` for
production. Docker / Helm / Render / Fly templates in [`server/`](server/).

### Bridge an existing IdP

```bash
# Exchange an Auth0 / Clerk / Okta id_token to start a delegation chain
curl -X POST http://localhost:8000/token \
  -d "grant_type=urn:ietf:params:oauth:grant-type:token-exchange" \
  -d "subject_token=$AUTH0_ID_TOKEN" \
  -d "subject_token_type=urn:ietf:params:oauth:token-type:id_token"
```

Keep Auth0/Okta for human SSO, social login, compliance. Bridge into
authgent for the agent-delegation layer via RFC 8693 token exchange.

---

## Specifications implemented

| Spec | Status |
|---|---|
| [draft-ietf-oauth-identity-chaining-14][icn] | **Reference impl** — §2.3, §2.4, §2.5, §3, §5.1–5.5 ([map](STANDARDS.md)) |
| [draft-ietf-oauth-transaction-tokens-08][txntok] | **Reference impl** — §3, §7, §11 ([map](STANDARDS.md)) |
| OAuth 2.1 (draft) + RFC 6749 | Authorization Code + PKCE (S256), Client Credentials, Refresh, Device Auth |
| [RFC 8693][rfc8693] | Token Exchange with nested `act` claims |
| [RFC 9449][rfc9449] | DPoP — sender-constrained access tokens (opt-in via `AUTHGENT_REQUIRE_DPOP=true`) |
| [RFC 9728](https://datatracker.ietf.org/doc/html/rfc9728) | Protected Resource Metadata |
| [RFC 8414](https://datatracker.ietf.org/doc/html/rfc8414) | OAuth 2.0 Authorization Server Metadata |
| [RFC 7591](https://datatracker.ietf.org/doc/html/rfc7591) | Dynamic Client Registration |
| [RFC 7662](https://datatracker.ietf.org/doc/html/rfc7662) | Token Introspection |
| [RFC 7009](https://datatracker.ietf.org/doc/html/rfc7009) | Token Revocation (with ownership check) |
| [RFC 8628](https://datatracker.ietf.org/doc/html/rfc8628) | Device Authorization Grant |
| [RFC 8707](https://datatracker.ietf.org/doc/html/rfc8707) | Resource Indicators |
| [RFC 9207](https://datatracker.ietf.org/doc/html/rfc9207) | `iss` parameter on `/authorize` redirect |
| [RFC 9457](https://datatracker.ietf.org/doc/html/rfc9457) | Problem Details for HTTP APIs |
| MCP 2026-07-28 | OAuth discovery + RFC 8414 well-known suffix + RFC 9207 `iss` |

Section-by-section spec → file:func mapping in [STANDARDS.md](STANDARDS.md).

---

## SDKs

```bash
pip install authgent     # Python — middleware for FastAPI/Flask, MCP adapter
npm install authgent     # TypeScript — middleware for Express/Hono, MCP adapter
```

Both verify tokens, walk delegation chains, validate DPoP, and ship MCP
adapters. Full docs: [Python SDK](sdks/python/README.md) ·
[TypeScript SDK](sdks/typescript/README.md).

---

## Deeper reading

- [MCP client quickstart](docs/mcp-quickstart.md) — Claude Desktop, Cursor,
  Continue, VS Code MCP, ChatGPT configs.
- [Identity chaining](docs/identity-chaining.md) — cross-domain JWT grants
  + `jwt-bearer` consumer flow with worked examples.
- [Transaction tokens](docs/transaction-tokens.md) — `txntoken+jwt` with
  `tctx`/`rctx` claims.
- [Scanner methodology](docs/methodology.md) — every check, every RFC
  clause, weighted grade math.
- [Calibration set](docs/calibration.md) — published expected grades for
  known-good and known-bad shapes, asserted by CI.
- [Disclosure policy](docs/disclosure-policy.md) — embargo, opt-out,
  correction process for the registry.
- [Architecture](ARCHITECTURE.md) — endpoints / services / providers.
- [Security](SECURITY.md) — defense-in-depth, vulnerability reporting.
- [Compare: vs Auth0](docs/compare/auth0.md) ·
  [vs Keycloak](docs/compare/keycloak.md) ·
  [vs Ory Hydra](docs/compare/ory-hydra.md).

---

## Contributing

```bash
git clone https://github.com/authgent/authgent.git
cd authgent/server
pip install -e ".[dev]"
pytest -v   # 469 tests
```

See [CONTRIBUTING.md](CONTRIBUTING.md). Apache 2.0.
