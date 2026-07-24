---
title: "MCP Server OAuth Checklist: 10 Things to Verify Before You Ship"
description: A practitioner's checklist for OAuth on a Model Context Protocol server. Each item maps to a specific RFC and the most common way it fails in production.
target_query: "MCP server OAuth"
publish_targets: ["dev.to", "lobste.rs", "medium"]
canonical: https://github.com/authgent/authgent/blob/main/docs/blog/2026-06-13-mcp-server-oauth-checklist.md
date: 2026-06-13
draft: false
---

# MCP Server OAuth Checklist: 10 Things to Verify Before You Ship

If you are building a Model Context Protocol (MCP) server, the [MCP authorization spec](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization) inherits OAuth 2.1 wholesale and pulls in a stack of RFCs you may not have implemented end-to-end before. This is the checklist I wish someone had handed me before I shipped the first version of [authgent](https://github.com/authgent/authgent).

Each item names the specific RFC clause it tests, the most common production bug, and a single command to verify it from the outside. If you can satisfy all 10, you have the OAuth posture every major MCP client (Claude Desktop, Cursor, Continue, VS Code MCP, ChatGPT) expects.

## 1. Protected Resource Metadata exists and is well-formed

**RFC**: [RFC 9728](https://datatracker.ietf.org/doc/html/rfc9728).

MCP clients discover your authorization server by hitting `GET /.well-known/oauth-protected-resource` on your MCP server's base URL. The response must be JSON with at least `resource` and `authorization_servers` (an array of issuer URLs).

```bash
curl https://your-mcp.example.com/.well-known/oauth-protected-resource
```

If this returns 404, the MCP client cannot find your authorization server and will refuse to authenticate. This is the single most common reason an MCP server "doesn't show up" in Cursor or Claude Desktop after install.

## 2. Authorization Server Metadata exists

**RFC**: [RFC 8414](https://datatracker.ietf.org/doc/html/rfc8414).

The issuer URL from step 1 must serve `GET /.well-known/oauth-authorization-server` returning a JSON document with `issuer`, `token_endpoint`, `authorization_endpoint`, `jwks_uri`, and `code_challenge_methods_supported`. MCP clients fetch this once per session and cache it.

```bash
curl https://your-as.example.com/.well-known/oauth-authorization-server | jq .
```

The `issuer` field must exactly match the URL you advertised in `authorization_servers` (down to the trailing slash). Mismatch here breaks the issuer-comparison check at the client.

## 3. PKCE S256 is advertised, `plain` is not

**RFC**: [RFC 7636](https://datatracker.ietf.org/doc/html/rfc7636), [OAuth 2.1](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1).

`code_challenge_methods_supported` must include `"S256"`. It must NOT include `"plain"` for any new server in 2026; OAuth 2.1 forbids `plain`.

The subtle bug: many servers advertise `["S256"]` in metadata but their `/authorize` endpoint silently accepts `code_challenge_method=plain` anyway. This is the [PKCE advertise-drift pattern](https://github.com/authgent/authgent/blob/main/docs/attacks/pkce-drift.md), a sub-variant of the known PKCE-downgrade family (OAuch BCP_4_8, Authentik CVE-2024-23647, Better-Auth GHSA-9h47-pqcx-hjr4 from May 2026).

To check: send `code_challenge_method=plain` to your authorize endpoint with an unregistered client_id. The server should reject with `error=invalid_request` and a description that names `code_challenge_method`. If it rejects with a different error, you may have drift.

## 4. Resource Indicators are supported

**RFC**: [RFC 8707](https://datatracker.ietf.org/doc/html/rfc8707).

`resource_indicators_supported: true` must be in the AS metadata. Without it, tokens minted for one MCP server can be replayed against another, which is the [confused-deputy pattern](https://www.obsidiansecurity.com/blog/when-mcp-meets-oauth-common-pitfalls-leading-to-one-click-account-takeover) Obsidian disclosed in January 2026.

## 5. Dynamic Client Registration works

**RFC**: [RFC 7591](https://datatracker.ietf.org/doc/html/rfc7591).

`registration_endpoint` must be advertised, and `POST /register` with a minimal payload must return a fresh `client_id`. Without DCR, every user has to manually obtain a `client_id` from your support team, which makes self-service onboarding impossible.

```bash
curl -X POST https://your-as.example.com/register \
  -H 'Content-Type: application/json' \
  -d '{"client_name":"my-mcp-test","grant_types":["client_credentials"]}'
```

The critical correctness rule: each call MUST return a *different* `client_id`. If two consecutive registrations return the same ID, you have the [DCR-mirror](https://github.com/authgent/authgent/blob/main/docs/attacks/pkce-drift.md) pattern, which Obsidian also disclosed in January 2026 and is a one-click account-takeover vector.

## 6. RFC 9207 `iss` parameter is on every authorize redirect

**RFC**: [RFC 9207](https://datatracker.ietf.org/doc/html/rfc9207).

Both your AS metadata and your `/authorize` redirects must advertise and emit the `iss` parameter. The metadata key is `authorization_response_iss_parameter_supported: true`. The query string of every redirect (success and `error=access_denied`) must include `&iss=<your-issuer-url>`.

This protects MCP clients against the mix-up attack where an authorization response from one IdP gets accepted by another.

## 7. DPoP is supported

**RFC**: [RFC 9449](https://datatracker.ietf.org/doc/html/rfc9449).

Best practice in 2026: `dpop_signing_alg_values_supported: ["ES256"]` in the AS metadata, and accept `DPoP` proof headers on the token endpoint. AI agents tend to leak bearer tokens through verbose log infrastructure (LangChain traces, AutoGen histories, CrewAI logs); DPoP cryptographically binds the token to the holder's ephemeral key so a leaked token is useless.

## 8. The implicit grant is not advertised

**RFC**: [OAuth 2.1](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1).

`response_types_supported` must NOT contain `"token"`. The implicit flow returns tokens in the URL fragment and is forbidden by OAuth 2.1. Its presence breaks state-binding and enables a CSRF / auth-code-leak pattern.

## 9. `security.txt` exists

**RFC**: [RFC 9116](https://datatracker.ietf.org/doc/html/rfc9116).

Serve `GET /.well-known/security.txt` with `Contact:`, `Expires:`, and `Policy:` fields. Without this, security researchers cannot find a way to disclose a finding to you privately. The first thing a serious user does when they suspect a vulnerability is `curl /.well-known/security.txt`.

## 10. Tool endpoints respond 401 + WWW-Authenticate when called without a token

**RFC**: [RFC 6750](https://datatracker.ietf.org/doc/html/rfc6750).

Anonymous `GET /` may legitimately respond 200 with a landing page. But anonymous calls to your tool endpoints must respond 401 with a `WWW-Authenticate: Bearer realm="…"` header. Without the header, MCP clients cannot start the OAuth flow.

For the `insufficient_scope` case (authenticated but scope mismatch), include a `scope="…"` directive listing the missing scopes so MCP clients can do client-side scope accumulation per [MCP SEP-2350](https://github.com/modelcontextprotocol/modelcontextprotocol/issues/2350).

## How to verify all 10 in 10 seconds

These 10 items map 1-to-1 to checks in [`authgent-server lint`](https://github.com/authgent/authgent), an open-source MCP-OAuth conformance scanner. The full list, with severity tiers and remediation hints, is in `docs/methodology.md`.

```bash
pip install authgent-server
authgent-server lint https://your-mcp.example.com
```

Output is human-readable by default, with `--format json` for CI pipelines and `--format github` for inline `::error` annotations on pull requests. There's also a [GitHub Action](https://github.com/authgent/authgent/blob/main/.github/actions/mcp-lint/README.md) that runs the same code path on every PR, with a `--diff <baseline>` mode that gates only on regressions.

The same scanner powers a [public registry](https://authgent.dev/registry/) of how named MCP vendors (Notion, Cloudflare, Linear, Descope, Asana, Square, Box, HubSpot) grade today against the same 10 checks.

If you find your server failing one of these, the [authgent-server](https://pypi.org/project/authgent-server/) package itself is an open-source reference implementation that passes all 10 by default. It is documented as the IETF Internet-Draft [draft-agnihotri-oauth-agent-impl-status-00](https://datatracker.ietf.org/doc/draft-agnihotri-oauth-agent-impl-status/).
