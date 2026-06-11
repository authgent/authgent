# MCP Client Quickstart — wire authgent to Claude Desktop, Cursor, Claude Code, Continue, VS Code MCP

You have an MCP server (e.g. the example in
[`examples/mcp_server`](../examples/mcp_server/)) that authgent is
already protecting. This page is the copy-pastable client configuration
for each major MCP client.

For each client we list:

- The config file path.
- A working snippet, identical except for the binary path and the
  transport selection.
- A "what works / known issue" callout reflecting the June 2026
  client-state.

If you add a config for a new MCP client, please open a PR — that's how
this list stays trustworthy.

> **Prerequisites for every client below**
>
> ```bash
> pip install authgent-server
> authgent-server run            # listens on http://localhost:8000
>
> # In another terminal, start one of the MCP server examples:
> uvicorn examples.mcp_server.mcp_server:app --port 9002    # HTTP
> # OR plan to spawn examples/mcp_server/stdio_server.py from the client config.
> ```

---

## Claude Desktop (stdio — primary transport)

**File:** `~/Library/Application Support/Claude/claude_desktop_config.json`
(macOS) or `%APPDATA%\Claude\claude_desktop_config.json` (Windows).

```json
{
  "mcpServers": {
    "authgent-search": {
      "command": "python",
      "args": [
        "/absolute/path/to/authgent/examples/mcp_server/stdio_server.py"
      ],
      "env": {
        "AUTHGENT_SERVER": "http://localhost:8000",
        "AUTHGENT_CLIENT_ID": "agnt_REPLACEME",
        "AUTHGENT_CLIENT_SECRET": "sec_REPLACEME",
        "AUTHGENT_SCOPE": "search:execute summarize:execute"
      }
    }
  }
}
```

Pre-register the client once:

```bash
authgent-server create-agent --name claude-desktop \
  --scopes "search:execute summarize:execute"
```

Restart Claude Desktop. The server appears in the MCP picker.

**Known issue (June 2026):** Claude Desktop does not yet support the
RFC 9449 DPoP HTTP-header for stdio servers (DPoP is HTTP-only by
design). The token authgent mints is a Bearer; rotate `AUTHGENT_CLIENT_SECRET`
quarterly per `docs/operations/secret-rotation.md`.

---

## Cursor (streamable HTTP)

**File:** `.cursor/mcp.json` in the project root, or
`~/.cursor/mcp.json` for global config.

```json
{
  "mcpServers": {
    "authgent-search": {
      "url": "http://localhost:9002/mcp",
      "type": "streamable-http"
    }
  }
}
```

Cursor performs the OAuth handshake itself: it discovers
authgent via the MCP server's `/.well-known/oauth-protected-resource`,
runs DCR + PKCE, and stores the access token. **No client_id/secret
goes in the config.**

**What works:** PKCE, DCR, refresh-token rotation, RFC 9728 PRM
discovery, RFC 9207 `iss` validation. **Known issue:** older Cursor
builds (<0.42) cache stale tokens after authgent revocation; sign out
and reconnect.

---

## Claude Code (HTTP)

**File:** `~/.claude/mcp.json` (per-user) or per-project `.mcp.json`.

```json
{
  "mcpServers": {
    "authgent-search": {
      "type": "http",
      "url": "http://localhost:9002/mcp"
    }
  }
}
```

Add it via CLI:

```bash
claude mcp add authgent-search --type http --url http://localhost:9002/mcp
```

Claude Code does the OAuth dance the same way Cursor does.

**Known issue:** Claude Code's token-refresh window is very short; under
heavy traffic you will see "Authentication expired, reconnecting" toasts.
Mitigation: set `AUTHGENT_ACCESS_TOKEN_TTL=3600` on the server.

---

## Continue (HTTP)

**File:** `~/.continue/config.json`.

```jsonc
{
  "mcpServers": [
    {
      "name": "authgent-search",
      "url": "http://localhost:9002/mcp",
      "transport": "http"
    }
  ]
}
```

Continue follows the same OAuth + PKCE flow.

**Known issue:** Continue does not yet propagate the
RFC 9207 `iss` parameter through to its issuer-validation step
(<https://github.com/continuedev/continue/issues/3812>); authgent will
still emit `iss=` for safety.

---

## VS Code MCP (HTTP, via the official MCP extension)

**File:** `settings.json` (User or Workspace).

```json
{
  "mcp.servers": {
    "authgent-search": {
      "type": "http",
      "url": "http://localhost:9002/mcp",
      "auth": {
        "discovery": "well-known"
      }
    }
  }
}
```

`auth.discovery: "well-known"` tells the extension to read
`/.well-known/oauth-protected-resource` and follow the chain.

**What works:** end-to-end happy path. **Known issue:** the extension
caches the JWKS forever; restart VS Code after authgent key rotation.

---

## ChatGPT (Custom MCP — HTTP only, public URL required)

ChatGPT's Custom MCP feature requires a public HTTPS URL. Use a
tunnel for local development:

```bash
# Terminal 4
ngrok http 9002    # or cloudflared tunnel run
# Use the resulting https://<sub>.ngrok-free.app URL in ChatGPT.
```

Paste the URL plus `/mcp` into ChatGPT → Settings → Connectors. ChatGPT
performs DCR + PKCE against authgent automatically.

**Known issue:** ChatGPT only supports `Bearer`, not DPoP, on Custom
MCP. Set `AUTHGENT_REQUIRE_DPOP=false` for that connector's tenant.

---

## Headless test — `mcp_client_demo.py`

If you just want to confirm the loop works end-to-end without an IDE:

```bash
python examples/mcp_server/mcp_client_demo.py
```

The script registers a fresh client, walks the OAuth code+PKCE handshake
against authgent, redeems a token, and calls the `search` tool. A green
run reproduces what the five clients above do under the hood.

---

## Reporting client-specific bugs

Open an issue at
<https://github.com/authgent/authgent/issues> with:

- The MCP client + version.
- The full `WWW-Authenticate` header from authgent (it should include
  the spec-compliant fields above).
- The client-side error message verbatim.

We update this page as the clients evolve.
