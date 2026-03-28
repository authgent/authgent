"""BEFORE authgent — a typical unprotected FastAPI endpoint.

This is what most agent tool servers look like today:
  - No authentication
  - No idea who is calling
  - No delegation tracking
  - API key in env var at best
"""

from fastapi import FastAPI

app = FastAPI(title="Search Tool (UNPROTECTED)")


@app.post("/search")
async def search(query: str):
    # Who is calling this? No idea.
    # Was this authorized by a human? No idea.
    # Can we audit who did what? No.
    results = [f"Result for: {query}"]
    return {"results": results}


@app.post("/db/query")
async def db_query(sql: str):
    # Is this agent allowed to query the DB? No way to check.
    # Is this a delegated request from a human? Unknown.
    return {"rows": [{"id": 1, "data": "sensitive"}]}


# Run: uvicorn before:app --port 9001
