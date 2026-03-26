# authgent — Python SDK

The open-source identity SDK for AI agents. Token verification, delegation chain validation, DPoP sender-constrained tokens, and middleware for FastAPI and Flask.

[![PyPI](https://img.shields.io/pypi/v/authgent.svg)](https://pypi.org/project/authgent/)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-3776AB.svg)](https://python.org)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](../../LICENSE)

## Install

```bash
pip install authgent

# With FastAPI middleware
pip install authgent[fastapi]

# With Flask middleware
pip install authgent[flask]
```

## Quick Start

### Verify a Token

```python
from authgent import verify_token

identity = await verify_token(
    token="eyJ...",
    issuer="http://localhost:8000",
)

print(identity.subject)           # "client:agnt_xxx"
print(identity.scopes)            # ["search:execute"]
print(identity.delegation_chain)  # DelegationChain(depth=0)
```

### Validate Delegation Chains

```python
from authgent import verify_token, verify_delegation_chain

identity = await verify_token(token=token, issuer="http://localhost:8000")

# Enforce: max 3 hops, must originate from a human
verify_delegation_chain(
    identity.delegation_chain,
    max_depth=3,
    require_human_root=True,
    allowed_actors=["client:agnt_trusted_orchestrator"],
)
```

### Server API Client

```python
from authgent import AgentAuthClient

client = AgentAuthClient("http://localhost:8000")

# Register an agent
agent = await client.register_agent(
    name="search-bot",
    scopes=["search:execute"],
)

# Get a token
token = await client.get_token(
    client_id=agent.client_id,
    client_secret=agent.client_secret,
    scope="search:execute",
)

# Delegate to another agent (token exchange)
delegated = await client.exchange_token(
    subject_token=token.access_token,
    audience="https://downstream-api.example.com",
    scopes=["read"],
    client_id=downstream_agent.client_id,
    client_secret=downstream_agent.client_secret,
)

# Introspect a token
info = await client.introspect_token(delegated.access_token)
print(info["active"])   # True
print(info["act"])      # {"sub": "client:agnt_search", "act": {"sub": "user:123"}}

# Revoke a token
await client.revoke_token(delegated.access_token)
```

### DPoP (Sender-Constrained Tokens)

```python
from authgent import DPoPClient

# Create an ephemeral key pair
dpop = DPoPClient.create()
print(dpop.jkt)  # JWK thumbprint for cnf binding

# Generate proof for a request
proof = dpop.create_proof(
    method="POST",
    url="https://api.example.com/data",
    access_token="eyJ...",
)
# Send as DPoP header alongside the access token

# Verify an incoming DPoP proof
from authgent import verify_dpop_proof

result = verify_dpop_proof(
    proof_jwt=request.headers["DPoP"],
    access_token=token,
    http_method="POST",
    http_uri="https://api.example.com/data",
)
print(result["jkt"])  # JWK thumbprint — must match token's cnf.jkt
```

## Middleware

### FastAPI

```python
from fastapi import FastAPI, Depends, Request
from authgent.middleware.fastapi import AgentAuthMiddleware, get_agent_identity

app = FastAPI()
app.add_middleware(AgentAuthMiddleware, issuer="http://localhost:8000")

@app.post("/tools/search")
async def search(request: Request):
    identity = get_agent_identity(request)
    print(f"Agent: {identity.subject}")
    print(f"Scopes: {identity.scopes}")
    print(f"Delegation depth: {identity.delegation_chain.depth}")
    return {"results": [...]}
```

### Flask

```python
from flask import Flask, g
from authgent.middleware.flask import agent_auth_required

app = Flask(__name__)

@app.route("/tools/search", methods=["POST"])
@agent_auth_required(issuer="http://localhost:8000", scopes=["search:execute"])
def search():
    identity = g.agent_identity
    return {"agent": identity.subject}
```

### MCP Scope Challenge

```python
from authgent.middleware.scope_challenge import ScopeChallengeHandler

handler = ScopeChallengeHandler(
    server_url="http://localhost:8000",
    client_id="agnt_xxx",
    client_secret="sec_xxx",
)

# Automatically detect 403 scope challenges and trigger step-up
result = await handler.handle_scope_challenge(
    response=http_response,
    action="access_pii",
    scope="data:pii:read",
)
```

## Adapters

### MCP Server

```python
from authgent.adapters.mcp import MCPAuthProvider

auth = MCPAuthProvider(server_url="http://localhost:8000")
identity = await auth.verify(token)

# Discovery URLs for MCP clients
auth.metadata_url  # http://localhost:8000/.well-known/oauth-authorization-server
auth.jwks_url      # http://localhost:8000/.well-known/jwks.json
```

### Protected Resource Metadata (RFC 9728)

```python
from authgent.adapters.protected_resource import ProtectedResourceMetadata

metadata = ProtectedResourceMetadata(
    resource="https://mcp-server.example.com",
    authorization_servers=["http://localhost:8000"],
    scopes_supported=["tools:execute", "db:read"],
)

# Serve at /.well-known/oauth-protected-resource
@app.get("/.well-known/oauth-protected-resource")
async def resource_metadata():
    return metadata.to_dict()
```

## Error Handling

All SDK errors extend `AuthgentError`:

```python
from authgent import (
    verify_token,
    AuthgentError,
    InvalidTokenError,
    DelegationError,
    DPoPError,
)

try:
    identity = await verify_token(token=token, issuer=issuer)
except InvalidTokenError as e:
    # Token expired, wrong issuer, bad signature
    print(f"Invalid token: {e}")
except DelegationError as e:
    # Chain too deep, unauthorized actor, scope escalation
    print(f"Delegation violation: {e}")
except DPoPError as e:
    # Proof mismatch, expired, wrong binding
    print(f"DPoP error: {e}")
except AuthgentError as e:
    # Any other SDK error
    print(f"Auth error: {e}")
```

## API Reference

### Core Functions

| Function | Description |
|:---------|:------------|
| `verify_token(token, issuer)` | Verify JWT against issuer's JWKS, return `AgentIdentity` |
| `verify_delegation_chain(chain, ...)` | Enforce depth, actors, human root policies |
| `verify_dpop_proof(proof_jwt, ...)` | Verify DPoP proof-of-possession |
| `DPoPClient.create()` | Create ephemeral DPoP proof generator |
| `AgentAuthClient(url)` | Full server API client |

### Models

| Class | Fields |
|:------|:-------|
| `AgentIdentity` | `subject`, `scopes`, `claims`, `delegation_chain` |
| `DelegationChain` | `depth`, `actors`, `human_root` |
| `TokenClaims` | `sub`, `scope`, `iss`, `exp`, `iat`, `jti`, `act`, `cnf` |

### Middleware

| Import | Framework |
|:-------|:----------|
| `authgent.middleware.fastapi` | FastAPI (ASGI) |
| `authgent.middleware.flask` | Flask (WSGI) |
| `authgent.middleware.scope_challenge` | MCP scope challenge handler |

### Adapters

| Import | Purpose |
|:-------|:--------|
| `authgent.adapters.mcp` | MCP server auth provider |
| `authgent.adapters.protected_resource` | RFC 9728 metadata |
| `authgent.adapters.langchain` | LangChain tool auth |

## License

[Apache 2.0](../../LICENSE)
