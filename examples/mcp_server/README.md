# MCP Server with authgent as OAuth Provider

This directory contains two example MCP servers built on Anthropic's
official `mcp` Python SDK and protected by authgent. Pick the one that
matches the transport your MCP client uses:

| File | Transport | Used by |
|---|---|---|
| `mcp_server.py` | streamable HTTP (`/mcp`) | Cursor, Continue, VS Code MCP, Claude Code remote, ChatGPT custom MCP |
| `stdio_server.py` | stdio (subprocess) | Claude Desktop (primary), Claude Code local |
| `mcp_client_demo.py` | n/a | Headless test that does the OAuth handshake + a tool call |

The corresponding **client config snippets** for Claude Desktop, Cursor,
Continue, Claude Code, and VS Code MCP are in
[`docs/mcp-quickstart.md`](../../docs/mcp-quickstart.md).

## How it fits together

```
MCP Client (Claude Desktop / Cursor / etc.)
    │
    │ 1. GET <server>/.well-known/oauth-protected-resource
    │    → tells client to use authgent at http://localhost:8000
    │ 2. POST authgent/register (Dynamic Client Registration, RFC 7591)
    │    → returns client_id + client_secret
    │ 3. GET authgent/authorize + PKCE
    │    → returns code (and RFC 9207 iss for verification)
    │ 4. POST authgent/token
    │    → returns access_token (DPoP-bound when the client supports it)
    │
    ▼
authgent-server (localhost:8000)
    │
    │ Issues ES256 JWT carrying scope, sub, and (for delegated agents)
    │ a nested `act` chain. Refresh-token rotation. RFC 9207 iss returned.
    │
    ▼
MCP Server (localhost:9002 for HTTP, stdio for local)
    │ Validates token via authgent SDK (signature + exp + iss + aud + DPoP).
    │ Per-tool scope check; on miss → 403 + WWW-Authenticate scope= (SEP-2350).
    ▼
```

## Run the HTTP example

```bash
# Terminal 1: authgent
authgent-server run

# Terminal 2: MCP server (HTTP)
pip install "authgent>=0.2.0" "mcp>=1.0" fastapi uvicorn
uvicorn examples.mcp_server.mcp_server:app --port 9002

# Terminal 3: simulate a client + tool call
python examples/mcp_server/mcp_client_demo.py
```

## Run the stdio example

The stdio server is normally launched by Claude Desktop via
`claude_desktop_config.json`. To exercise it manually:

```bash
pip install "authgent>=0.2.0" "mcp>=1.0"

# Pre-register a client once
authgent-server create-agent --name my-mcp --scopes "search:execute summarize:execute"
# Note the printed client_id / client_secret.

AUTHGENT_CLIENT_ID=agnt_... \
AUTHGENT_CLIENT_SECRET=sec_... \
python examples/mcp_server/stdio_server.py
```

## Why authgent for MCP?

Without authgent, an MCP server has to:

- Implement OAuth 2.1 (PKCE, DCR, refresh rotation, JWKS, revocation).
- Emit RFC 9728 Protected Resource Metadata.
- Emit RFC 9207 `iss` on `/authorize` redirects.
- Emit `WWW-Authenticate` with `scope=` per MCP SEP-2350.
- Track the agent delegation chain so audit logs make sense.

With authgent:

- Point your MCP server at authgent (`issuer="http://localhost:8000"`).
- authgent handles all of the above end-to-end. authgent's compatibility
  matrix in the README shows which MCP clients have been tested.
