---
title: "RFC 9728 Protected Resource Metadata: A Practical Guide"
description: What RFC 9728 actually requires, what MCP clients expect to find, and the three most common ways production MCP servers get it wrong.
target_query: "RFC 9728 protected resource metadata"
publish_targets: ["dev.to", "medium"]
canonical: https://github.com/authgent/authgent/blob/main/docs/blog/2026-06-13-rfc-9728-protected-resource-metadata.md
date: 2026-06-13
draft: false
---

# RFC 9728 Protected Resource Metadata: A Practical Guide

[RFC 9728](https://datatracker.ietf.org/doc/html/rfc9728) defines how an OAuth 2.0 protected resource publishes the metadata clients need to authenticate against it. In 2026, every MCP server is a protected resource and every MCP client (Claude Desktop, Cursor, Continue, VS Code MCP, ChatGPT) expects to find an RFC 9728-conformant document at a well-known URL.

This post is the field guide: what the spec actually requires, the exact response shape MCP clients consume, and the three production bugs I see in 80% of MCP-server deployments today.

## What the spec says, in one sentence

A protected resource publishes a JSON document at `GET /.well-known/oauth-protected-resource` describing the resource itself and the authorization servers that can issue tokens for it.

## The minimum viable document

```json
{
  "resource": "https://mcp.example.com",
  "authorization_servers": ["https://auth.example.com"],
  "scopes_supported": ["mcp:read", "mcp:write"],
  "bearer_methods_supported": ["header"]
}
```

The `resource` field is the identifier MCP clients pin tokens against (RFC 8707 resource indicators). The `authorization_servers` array is the list of issuer URLs that can mint tokens for this resource. `scopes_supported` is informational. `bearer_methods_supported` tells clients where to put the access token; `header` means the standard `Authorization: Bearer …` HTTP header.

## What MCP clients actually do with this

When a user adds an MCP server to Claude Desktop or Cursor:

1. The client makes an unauthenticated call to a tool endpoint and receives a 401.
2. The 401 includes `WWW-Authenticate: Bearer realm="…", resource_metadata="…"` per [RFC 9728 §5](https://datatracker.ietf.org/doc/html/rfc9728#section-5).
3. The client follows the `resource_metadata` URL (or falls back to the well-known suffix) to fetch the document above.
4. The client picks the first entry from `authorization_servers`, fetches its [RFC 8414](https://datatracker.ietf.org/doc/html/rfc8414) metadata, and runs the authorization-code + PKCE flow.
5. On success, the client stores the access token and replays the original request with the `Authorization: Bearer …` header.

If step 1 returns a 200, or step 2 lacks the `WWW-Authenticate` header, the flow never starts and the user sees "MCP server unreachable" with no path to recovery.

## Bug #1: The endpoint returns 404

**Symptom**: MCP clients show "OAuth required but no metadata found."

**Root cause**: Your reverse proxy or framework swallowed the well-known path. Many minimal Python frameworks (BareWSGI, some FastAPI starter templates) reject `/.well-known/...` as "not a registered route" before the handler runs.

**Fix**: Confirm `curl https://your-mcp.example.com/.well-known/oauth-protected-resource` returns 200 with the JSON body above, not an HTML 404 page. If it returns the 200 in dev but 404 in production, the difference is your ingress (nginx, Traefik, AWS API Gateway) routing.

## Bug #2: `authorization_servers[0]` does not match the issuer claim

**Symptom**: MCP client successfully fetches the doc but errors at "issuer mismatch" during the OAuth handshake.

**Root cause**: You wrote `https://auth.example.com/` in `authorization_servers` but your AS metadata's `issuer` claim is `https://auth.example.com` (no trailing slash). RFC 8414 requires byte-exact comparison.

**Fix**: Pick one canonical form. Use `urllib.parse.urlsplit` (or your framework's URL helper) to normalize before serializing. The convention is no trailing slash, no port if it is the scheme default.

## Bug #3: The endpoint requires authentication

**Symptom**: 401 on the metadata document itself.

**Root cause**: A blanket auth middleware caught the well-known route. Production-grade frameworks let you exempt routes via path patterns; the cheapest fix is an `if request.path.startswith("/.well-known/"):` short-circuit at the top of your auth middleware.

**Fix**: Verify with `curl` (no auth) that the document loads. If it 401s, anything that depends on RFC 9728 discovery is broken.

## The path-suffix variant (multi-tenant MCP)

[MCP SEP-2351](https://github.com/modelcontextprotocol/modelcontextprotocol/issues/2351) and [RFC 8414 §3.1](https://datatracker.ietf.org/doc/html/rfc8414#section-3.1) define the path-suffix pattern: when your MCP server lives at `https://gateway.example.com/tenant-a`, the metadata lives at `https://gateway.example.com/.well-known/oauth-protected-resource/tenant-a` and the `resource` claim is rewritten to the path-prefixed URL.

This is required for any multi-tenant deployment and is one of the most-missed checks in production. If your gateway routes 50 customer MCP servers under different path prefixes, you need the suffix variant on each.

## Quick verify

A complete check covers all three bugs above plus the suffix variant:

```bash
pip install authgent-server
authgent-server lint https://your-mcp.example.com
```

Among the 10 RFC-mapped checks in the scanner, `MCP-PRM-001` is the one that exercises RFC 9728 specifically. The full methodology is at [authgent's docs/methodology.md](https://github.com/authgent/authgent/blob/main/docs/methodology.md).

The same scanner powers a public registry showing how named MCP vendors grade against this and 9 other checks. As of June 2026, several major vendors miss the path-suffix variant; the registry tracks fixes as they ship.

## Read more

- [RFC 9728: OAuth 2.0 Protected Resource Metadata](https://datatracker.ietf.org/doc/html/rfc9728) (the canonical spec; 18 pages, readable in one sitting).
- [RFC 8414: OAuth 2.0 Authorization Server Metadata](https://datatracker.ietf.org/doc/html/rfc8414) (companion spec for the authorization server side).
- [MCP authorization spec, 2025-11-25](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization) (the MCP-side requirements built on top of RFC 9728).
- [authgent on GitHub](https://github.com/authgent/authgent) (the open-source scanner + reference implementation cited in the IETF Internet-Draft [draft-agnihotri-oauth-agent-impl-status-00](https://datatracker.ietf.org/doc/draft-agnihotri-oauth-agent-impl-status/)).
