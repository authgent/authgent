# MCP Server with authgent as OAuth Provider

The MCP spec **mandates OAuth 2.1** for authentication. This example shows how to use authgent as your MCP server's OAuth provider.

## Architecture

```
MCP Client (Claude, Cursor, etc.)
    │
    │ 1. Discovers OAuth metadata via /.well-known/oauth-authorization-server
    │ 2. Registers via /register (Dynamic Client Registration)
    │ 3. Gets token via /authorize + PKCE (or client_credentials for M2M)
    │
    ▼
authgent-server (localhost:8000)
    │
    │ Issues ES256 JWT with scopes matching MCP tool permissions
    │
    ▼
Your MCP Server (localhost:9002)
    │ Validates token using authgent SDK
    │ Checks scopes per-tool
    │ Knows WHO is calling and what they can do
    ▼
```

## Files

| File | What it does |
|:-----|:-------------|
| `mcp_server.py` | MCP server with authgent token verification on every tool call |
| `mcp_client_demo.py` | Simulates an MCP client authenticating and calling tools |

## Run

```bash
# Terminal 1: authgent-server
authgent-server run

# Terminal 2: MCP server
pip install authgent fastapi uvicorn
uvicorn mcp_server:app --port 9002

# Terminal 3: simulate MCP client
python mcp_client_demo.py
```

## Why authgent for MCP?

Without authgent, MCP servers need to:
- Implement their own OAuth 2.1 server (hundreds of lines)
- Manage signing keys, token issuance, client registration
- Handle PKCE, token introspection, revocation

With authgent:
- Point your MCP server at authgent: `issuer="http://localhost:8000"`
- authgent handles ALL of OAuth 2.1
- Your MCP server just validates tokens (3 lines of code)
