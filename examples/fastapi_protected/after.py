"""AFTER authgent — the same endpoint, now protected.

Changes from before.py (marked with # ← NEW):
  - 2 imports added
  - 1 middleware line added
  - Route handlers now receive verified AgentIdentity
  - You know WHO is calling, WHAT they can do, and WHO authorized them

Prerequisites:
    pip install authgent fastapi uvicorn
    authgent-server running on localhost:8000
"""

from fastapi import FastAPI, Depends                                          # same
from authgent.middleware.fastapi import AgentAuthMiddleware, get_agent_identity  # ← NEW
from authgent.models import AgentIdentity                                       # ← NEW

app = FastAPI(title="Search Tool (PROTECTED by authgent)")
app.add_middleware(AgentAuthMiddleware, issuer="http://localhost:8000")          # ← NEW


@app.post("/search")
async def search(query: str, identity: AgentIdentity = Depends(get_agent_identity)):  # ← NEW
    # Now you know exactly:
    print(f"Caller: {identity.subject}")                    # who is the original human/agent
    print(f"Scopes: {identity.scopes}")                     # what they're allowed to do
    print(f"Delegation depth: {identity.delegation_chain.depth}")  # how many hops
    print(f"Actors: {identity.delegation_chain.actors}")    # the full chain

    # Enforce: only agents with 'search' scope can call this
    if "search" not in identity.scopes:
        return {"error": "insufficient_scope"}, 403

    results = [f"Result for: {query}"]
    return {
        "results": results,
        "authorized_by": identity.subject,
        "delegation_depth": identity.delegation_chain.depth,
    }


@app.post("/db/query")
async def db_query(sql: str, identity: AgentIdentity = Depends(get_agent_identity)):  # ← NEW
    # Enforce: must have db:read scope AND chain must start with a human
    if "db:read" not in identity.scopes:
        return {"error": "insufficient_scope"}, 403

    if identity.delegation_chain.depth > 0 and not identity.delegation_chain.human_root:
        return {"error": "delegation chain must originate from a human"}, 403

    return {
        "rows": [{"id": 1, "data": "sensitive"}],
        "authorized_by": identity.subject,
        "acting_as": [a["sub"] for a in identity.delegation_chain.actors],
    }


# Run: uvicorn after:app --port 9001
#
# Test with:
#   curl -X POST http://localhost:9001/search?query=test \
#     -H "Authorization: Bearer <token-from-authgent>"
