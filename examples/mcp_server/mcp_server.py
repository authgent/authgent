"""Remote (HTTP) MCP server protected by authgent.

Built on Anthropic's official `mcp` Python SDK (`pip install mcp`). Exposes
two tools — `search` and `summarize` — over the streamable-HTTP transport.
Every tool call is gated by an authgent-issued access token whose scopes
must match the tool's required scopes.

This is the example MCP engineers should copy. It demonstrates the four
things that matter to a real MCP client (Claude Desktop, Cursor, Continue):

1. RFC 9728 Protected Resource Metadata exposed at the well-known URL,
   pointing at authgent as the authorization server.
2. WWW-Authenticate challenges that include the required scope per
   MCP SEP-2350 / RFC 6750 §3.1, so the client can step up.
3. authgent token verification (signature + JWKS + DPoP-aware) on every
   request before any tool body runs.
4. The delegation chain (RFC 8693 nested `act` claims) flowing into the
   tool's audit log so downstream services can see the full call chain.

Run:
    # Terminal 1
    authgent-server run

    # Terminal 2
    pip install authgent mcp fastapi uvicorn
    uvicorn mcp_server:app --port 9002

The corresponding client config snippets for Claude Desktop / Cursor /
Continue / VS Code are in `docs/mcp-quickstart.md`.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from mcp.server.fastmcp import FastMCP

from authgent.middleware.fastapi import AgentAuthMiddleware, get_agent_identity
from authgent.models import AgentIdentity

AUTHGENT_SERVER = "http://localhost:8000"
RESOURCE_URL = "http://localhost:9002"


# ── 1. Build an MCP server using the official `mcp` SDK ────────────────────

mcp = FastMCP("authgent-search-server")


@mcp.tool()
def search(query: str, max_results: int = 5) -> dict:
    """Search the corpus.

    Required scope: ``search:execute``.
    Scope check happens in the FastAPI middleware below, before this body
    runs. By the time we are here, the caller is authenticated and scoped.
    """
    return {
        "results": [
            {"title": f"Result {i} for {query}", "url": f"https://example.com/{i}"}
            for i in range(1, min(max_results, 5) + 1)
        ],
    }


@mcp.tool()
def summarize(text: str) -> dict:
    """Summarize text. Required scope: ``summarize:execute``."""
    return {"summary": f"Summary of {len(text)} chars: {text[:100]}..."}


# ── 2. Mount the MCP HTTP transport behind authgent's middleware ──────────

app = FastAPI(title="authgent + MCP example")

# Authgent middleware verifies every incoming Authorization: Bearer / DPoP
# token against the configured authgent JWKS.
app.add_middleware(AgentAuthMiddleware, issuer=AUTHGENT_SERVER)

# The MCP SDK exposes its endpoints; we attach them under the FastAPI app.
# Claude Desktop / Cursor / Continue connect to `/mcp` for the MCP wire
# protocol.
app.mount("/mcp", mcp.sse_app())


# ── 3. RFC 9728 Protected Resource Metadata ───────────────────────────────


@app.get("/.well-known/oauth-protected-resource")
async def protected_resource_metadata() -> dict:
    """Tells the MCP client which authorization server protects this
    resource. Without this, modern MCP clients cannot complete an OAuth
    handshake."""
    return {
        "resource": RESOURCE_URL,
        "authorization_servers": [AUTHGENT_SERVER],
        "scopes_supported": ["search:execute", "summarize:execute"],
        "bearer_methods_supported": ["header"],
    }


# ── 4. Per-tool scope enforcement on top of authentication ────────────────


@app.middleware("http")
async def enforce_per_tool_scope(request: Request, call_next):
    """Map `tools/call` JSON-RPC method names to required scopes.

    On insufficient scope, emit a 403 with WWW-Authenticate carrying the
    exact scope the client needs (MCP SEP-2350 / RFC 6750 §3.1). The MCP
    client uses this to perform a step-up authorization request without
    a round-trip to ask "what scope do you need?".
    """
    if request.url.path.startswith("/mcp"):
        identity: AgentIdentity | None = getattr(request.state, "agent_identity", None)
        if identity is None:
            return await call_next(request)

        body = await request.body()

        async def _replay() -> bytes:
            return body

        request._receive = _replay  # type: ignore[attr-defined]

        # crude inspection — production code would parse the JSON-RPC envelope
        for tool, scope in (("search", "search:execute"), ("summarize", "summarize:execute")):
            if tool.encode() in body and scope not in identity.scopes:
                return JSONResponse(
                    status_code=403,
                    content={"error": "insufficient_scope", "required_scope": scope},
                    headers={
                        "WWW-Authenticate": (
                            f'Bearer realm="authgent", '
                            f'error="insufficient_scope", '
                            f'scope="{scope}"'
                        )
                    },
                )

    return await call_next(request)


# ── 5. Convenience health endpoint ────────────────────────────────────────


@app.get("/health")
async def health() -> dict:
    return {"status": "ok", "auth_server": AUTHGENT_SERVER}


# ── 6. Tool-call audit hook (delegation-chain visibility) ────────────────


@app.middleware("http")
async def audit_delegation_chain(
    request: Request,
    call_next: Annotated[object, "FastAPI middleware next"],  # type: ignore[type-arg]
):
    """Log who called which tool and through what delegation chain.

    Demonstrates how authgent's nested-act chain surfaces inside an MCP
    server: the tool sees not only the calling client but the full path
    from the human root, which is what makes audit useful for agents.
    """
    response = await call_next(request)
    identity: AgentIdentity | None = getattr(request.state, "agent_identity", None)
    if identity is not None and request.url.path.startswith("/mcp"):
        # Log line is intentionally compact — copy it for your structured logger.
        print(
            "mcp.tool_call "
            f"caller={identity.subject} "
            f"scopes={identity.scopes} "
            f"chain_depth={identity.delegation_chain.depth}"
        )
    return response
