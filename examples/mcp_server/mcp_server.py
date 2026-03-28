"""MCP-compatible tool server protected by authgent.

This is a FastAPI server that exposes tools (search, summarize) and uses
authgent to verify that callers have the right scopes.

MCP clients discover the OAuth provider via:
  GET /.well-known/oauth-authorization-server → redirects to authgent

Run: uvicorn mcp_server:app --port 9002
Requires: authgent-server running on localhost:8000
"""

from fastapi import FastAPI, Depends, HTTPException
from fastapi.responses import RedirectResponse, JSONResponse
from authgent.middleware.fastapi import AgentAuthMiddleware, get_agent_identity
from authgent.models import AgentIdentity

AUTHGENT_SERVER = "http://localhost:8000"

app = FastAPI(title="MCP Search Server")

# ── One line: protect all endpoints ──────────────────────────
app.add_middleware(AgentAuthMiddleware, issuer=AUTHGENT_SERVER)


# ── MCP Discovery: point clients to authgent for OAuth ──────
@app.get("/.well-known/oauth-authorization-server")
async def oauth_metadata():
    """MCP clients call this to find the OAuth server.
    We redirect to authgent-server's metadata endpoint."""
    return RedirectResponse(
        f"{AUTHGENT_SERVER}/.well-known/oauth-authorization-server"
    )


@app.get("/.well-known/oauth-protected-resource")
async def protected_resource_metadata():
    """RFC 9728 — tells clients which auth server protects this resource."""
    return JSONResponse({
        "resource": "http://localhost:9002",
        "authorization_servers": [AUTHGENT_SERVER],
        "scopes_supported": ["search:execute", "summarize:execute"],
    })


# ── MCP Tools (protected by authgent) ───────────────────────

@app.post("/tools/search")
async def tool_search(
    query: str,
    max_results: int = 10,
    identity: AgentIdentity = Depends(get_agent_identity),
):
    """Search tool — requires 'search:execute' scope."""
    if "search:execute" not in identity.scopes:
        raise HTTPException(
            status_code=403,
            detail="Requires scope: search:execute",
            headers={"WWW-Authenticate": 'Bearer scope="search:execute"'},
        )

    # Log who called this tool and through what delegation chain
    print(f"[search] caller={identity.subject} "
          f"scopes={identity.scopes} "
          f"delegation_depth={identity.delegation_chain.depth}")

    return {
        "results": [
            {"title": f"Result {i} for: {query}", "url": f"https://example.com/{i}"}
            for i in range(1, min(max_results, 5) + 1)
        ],
        "meta": {
            "authorized_by": identity.subject,
            "delegation_chain_depth": identity.delegation_chain.depth,
        },
    }


@app.post("/tools/summarize")
async def tool_summarize(
    text: str,
    identity: AgentIdentity = Depends(get_agent_identity),
):
    """Summarize tool — requires 'summarize:execute' scope."""
    if "summarize:execute" not in identity.scopes:
        raise HTTPException(
            status_code=403,
            detail="Requires scope: summarize:execute",
            headers={"WWW-Authenticate": 'Bearer scope="summarize:execute"'},
        )

    return {
        "summary": f"Summary of {len(text)} chars: {text[:100]}...",
        "meta": {
            "authorized_by": identity.subject,
        },
    }


@app.get("/health")
async def health():
    return {"status": "ok", "auth_server": AUTHGENT_SERVER}
