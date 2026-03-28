# Before & After: Protecting a FastAPI Endpoint with authgent

## The Diff

| | `before.py` | `after.py` |
|:--|:--|:--|
| **Lines changed** | — | +3 lines (2 imports, 1 middleware) |
| **Who is calling?** | No idea | `identity.subject` → `"user:alice"` |
| **What can they do?** | No idea | `identity.scopes` → `["search", "db:read"]` |
| **Who authorized them?** | No idea | `identity.delegation_chain` → full chain |
| **Can they escalate?** | Yes | No — scope only narrows per hop |
| **Audit trail?** | None | Every token carries the full delegation history |

## Run it

```bash
# Terminal 1: authgent-server
authgent-server run

# Terminal 2: the protected endpoint
pip install authgent fastapi uvicorn
uvicorn after:app --port 9001

# Terminal 3: test it
# Register an agent
curl -s -X POST http://localhost:8000/agents \
  -H "Content-Type: application/json" \
  -d '{"name": "test-bot", "allowed_scopes": ["search", "db:read"]}' | jq .

# Get a token (use client_id and client_secret from above)
TOKEN=$(curl -s -X POST http://localhost:8000/token \
  -d "grant_type=client_credentials&client_id=agnt_xxx&client_secret=sec_xxx&scope=search" \
  | jq -r .access_token)

# Call the protected endpoint
curl -X POST "http://localhost:9001/search?query=hello" \
  -H "Authorization: Bearer $TOKEN"
```

## What changed in the code

```diff
+ from authgent.middleware.fastapi import AgentAuthMiddleware, get_agent_identity
+ from authgent.models import AgentIdentity

  app = FastAPI()
+ app.add_middleware(AgentAuthMiddleware, issuer="http://localhost:8000")

  @app.post("/search")
- async def search(query: str):
+ async def search(query: str, identity: AgentIdentity = Depends(get_agent_identity)):
      # Now you have identity.subject, identity.scopes, identity.delegation_chain
```

That's it. 3 lines to go from "no idea who's calling" to full agent identity + delegation tracking.
