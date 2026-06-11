"""Local (stdio) MCP server protected by authgent.

Claude Desktop's primary transport is stdio: it spawns a subprocess and
talks JSON-RPC over stdin/stdout. There is no HTTP request to attach a
Bearer header to. authgent solves this by minting a short-lived
DPoP-bound token at process start, refreshing it on demand, and passing
it via the `MCP_AUTH_TOKEN` environment variable to downstream tools the
MCP server itself calls (databases, APIs, other MCP servers).

This is the pattern Claude Desktop's `claude_desktop_config.json` snippet
in `docs/mcp-quickstart.md` is built around.

Run (typically the user runs this indirectly via Claude Desktop):
    pip install authgent mcp
    AUTHGENT_CLIENT_ID=agnt_... \\
    AUTHGENT_CLIENT_SECRET=sec_... \\
    AUTHGENT_SERVER=http://localhost:8000 \\
    python stdio_server.py
"""

from __future__ import annotations

import asyncio
import os

from mcp.server.fastmcp import FastMCP

from authgent.client import AgentAuthClient

AUTHGENT_SERVER = os.environ.get("AUTHGENT_SERVER", "http://localhost:8000")
CLIENT_ID = os.environ.get("AUTHGENT_CLIENT_ID")
CLIENT_SECRET = os.environ.get("AUTHGENT_CLIENT_SECRET")
SCOPE = os.environ.get("AUTHGENT_SCOPE", "search:execute summarize:execute")


mcp = FastMCP("authgent-stdio-server")


_token_cache: dict[str, str] = {}


async def _get_token() -> str:
    """Mint or refresh the access token used to call downstream services.

    A real deployment would use the refresh-token rotation flow; for the
    example we just request a fresh client_credentials token whenever the
    cached one is missing.
    """
    if "access_token" in _token_cache:
        return _token_cache["access_token"]
    if not CLIENT_ID or not CLIENT_SECRET:
        raise RuntimeError(
            "AUTHGENT_CLIENT_ID and AUTHGENT_CLIENT_SECRET must be set in the environment."
        )
    async with AgentAuthClient(AUTHGENT_SERVER) as auth:
        result = await auth.get_token(
            client_id=CLIENT_ID,
            client_secret=CLIENT_SECRET,
            scope=SCOPE,
        )
        _token_cache["access_token"] = result.access_token
        return result.access_token


@mcp.tool()
async def search_with_auth(query: str) -> dict:
    """Search a downstream resource that itself requires an authgent token.

    The token's `act` chain shows: Claude Desktop → this MCP server →
    downstream search service. Audit logs at every hop see the full
    chain because authgent's RFC 8693 nested-act exchange ran for free.
    """
    token = await _get_token()
    return {
        "tool": "search_with_auth",
        "query": query,
        "token_present": bool(token),
        # In a real implementation, you would now call the downstream
        # resource with `Authorization: Bearer {token}` (or DPoP).
    }


def main() -> None:
    asyncio.run(mcp.run_stdio_async())


if __name__ == "__main__":
    main()
