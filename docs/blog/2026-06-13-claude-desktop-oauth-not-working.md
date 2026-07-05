---
title: "Claude Desktop OAuth Not Working? Here's the Debug Sequence"
description: A step-by-step diagnostic for Claude Desktop OAuth errors against an MCP server. Covers the 5 most common failure modes and a single command to test them all.
target_query: "Claude Desktop OAuth not working"
publish_targets: ["dev.to", "medium"]
canonical: https://github.com/authgent/authgent/blob/main/docs/blog/2026-06-13-claude-desktop-oauth-not-working.md
date: 2026-06-13
draft: false
---

# Claude Desktop OAuth Not Working? Here's the Debug Sequence

You added your MCP server to Claude Desktop's config, restarted the app, and... nothing. The server doesn't show up, or every tool call returns an auth error. This post is the debug sequence I run when this happens, in the order I run it.

If you fix the issue at any step, you can stop. The 10-second tool at the bottom checks all of them at once.

## Step 0: Sanity-check the config file

```bash
cat ~/Library/Application\ Support/Claude/claude_desktop_config.json
```

The config block must look like:

```json
{
  "mcpServers": {
    "your-server": {
      "url": "https://your-mcp.example.com",
      "transport": "http"
    }
  }
}
```

If the URL is wrong, fix it and restart Claude. If the URL is right, move on.

## Step 1: Confirm the server is reachable

```bash
curl -i https://your-mcp.example.com/
```

If this returns "could not resolve host" or "connection refused", you have a DNS or firewall issue, not an OAuth issue. Fix that first.

## Step 2: Confirm the well-known metadata exists

This is the #1 cause of "Claude Desktop OAuth not working" reports.

```bash
curl https://your-mcp.example.com/.well-known/oauth-protected-resource
```

If this returns 404, Claude Desktop has no way to discover your authorization server. The MCP authorization spec inherits OAuth 2.0 Protected Resource Metadata ([RFC 9728](https://datatracker.ietf.org/doc/html/rfc9728)); without this document at the well-known URL, the OAuth flow cannot start.

The fix depends on your stack:

- **FastAPI**: register a route at `/.well-known/oauth-protected-resource` returning the JSON body shown in step 3.
- **Express / Hono**: same pattern, `app.get('/.well-known/oauth-protected-resource', ...)`.
- **Behind nginx / Traefik**: confirm your reverse proxy is not stripping the path.

## Step 3: Confirm the metadata is well-formed

```bash
curl https://your-mcp.example.com/.well-known/oauth-protected-resource | jq .
```

It must return:

```json
{
  "resource": "https://your-mcp.example.com",
  "authorization_servers": ["https://your-as.example.com"],
  "bearer_methods_supported": ["header"]
}
```

If `authorization_servers` is missing, empty, or contains a URL that doesn't match the issuer, Claude Desktop can't proceed.

## Step 4: Confirm the authorization server's metadata exists

Take the URL from `authorization_servers[0]` and try:

```bash
curl https://your-as.example.com/.well-known/oauth-authorization-server | jq .
```

The response must include `issuer`, `token_endpoint`, `authorization_endpoint`, `jwks_uri`, and `code_challenge_methods_supported: ["S256"]`. Missing any of these blocks the OAuth flow.

The most common subtle bug here: `issuer` does not byte-exactly match the URL you advertised in `authorization_servers`. Trailing slashes matter.

## Step 5: Confirm PKCE S256 is advertised, plain is not

`code_challenge_methods_supported` must include `"S256"`. It must NOT include `"plain"`. OAuth 2.1 forbids `plain`, and Claude Desktop's PKCE implementation requires `S256`.

If your AS advertises `["plain"]` only, Claude Desktop will refuse the flow with "no compatible PKCE method." Add `S256` and confirm.

## Step 6: Confirm the 401 + WWW-Authenticate flow

When Claude Desktop hits a tool endpoint without a token, your MCP server must respond:

```
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Bearer realm="example", resource_metadata="https://your-mcp.example.com/.well-known/oauth-protected-resource"
```

The 401 status alone is not enough. The `WWW-Authenticate` header is what tells Claude Desktop where to find the metadata document and what realm it's challenging for. Without it, Claude shows a generic "auth required" message and gives up.

## The 10-second check

Every step above maps to a check in [`authgent-server lint`](https://github.com/authgent/authgent), an open-source MCP-OAuth scanner. The whole sequence runs in about 10 seconds:

```bash
pip install authgent-server
authgent-server lint https://your-mcp.example.com
```

The output names each check by ID (`MCP-PRM-001`, `MCP-AS-001`, `MCP-PKCE-001`, etc.) so you can search for the specific failure in the [methodology doc](https://github.com/authgent/authgent/blob/main/docs/methodology.md). For CI pipelines:

```bash
authgent-server lint https://your-mcp.example.com --format github
```

emits inline `::error` annotations on pull requests, and `--diff <baseline>` gates on new findings only so you don't have to fix everything at once.

If your server fails several checks, the same project ships an OAuth 2.1 reference implementation ([authgent-server](https://pypi.org/project/authgent-server/)) that passes them all by default. It is the IETF Internet-Draft [draft-agnihotri-oauth-agent-impl-status-00](https://datatracker.ietf.org/doc/draft-agnihotri-oauth-agent-impl-status/).

## Read more

- [MCP authorization spec](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization)
- [authgent's MCP client quickstart](https://github.com/authgent/authgent/blob/main/docs/mcp-quickstart.md) with copy-pastable configs for Claude Desktop, Cursor, Continue, VS Code MCP, and ChatGPT.
