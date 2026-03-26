# authgent — TypeScript SDK

The open-source identity SDK for AI agents. Token verification, delegation chains, DPoP, and middleware for Express and Hono.

## Install

```bash
npm install authgent
```

## Quick Start

### Verify a Token

```ts
import { verifyToken } from "authgent";

const identity = await verifyToken({
  token: "eyJ...",
  issuer: "http://localhost:8000",
});

console.log(identity.subject);          // "client:agnt_xxx"
console.log(identity.scopes);           // ["search:execute"]
console.log(identity.delegationChain);  // { depth: 0, actors: [], humanRoot: false }
```

### Validate Delegation Chains

```ts
import { verifyToken, verifyDelegationChain } from "authgent";

const identity = await verifyToken({ token, issuer });

// Enforce: max 3 hops, must originate from a human
verifyDelegationChain(identity.delegationChain, {
  maxDepth: 3,
  requireHumanRoot: true,
  allowedActors: ["client:agnt_trusted_1", "client:agnt_trusted_2"],
});
```

### Get Tokens via Client

```ts
import { AgentAuthClient } from "authgent";

const client = new AgentAuthClient("http://localhost:8000");

// Register an agent
const agent = await client.registerAgent({
  name: "search-bot",
  scopes: ["search:execute"],
});

// Get a token
const token = await client.getToken({
  clientId: agent.clientId,
  clientSecret: agent.clientSecret,
  scope: "search:execute",
});

// Exchange token for delegation
const delegated = await client.exchangeToken({
  subjectToken: token.accessToken,
  audience: "https://downstream-api.example.com",
  scopes: ["read"],
  clientId: agent.clientId,
  clientSecret: agent.clientSecret,
});
```

### DPoP (Sender-Constrained Tokens)

```ts
import { DPoPClient } from "authgent";

const dpop = await DPoPClient.create();
console.log(dpop.jkt); // JWK thumbprint for cnf binding

// Create proof headers for a request
const headers = await dpop.createProofHeaders(
  accessToken,
  "POST",
  "https://api.example.com/data",
);
// { Authorization: "DPoP eyJ...", DPoP: "eyJ..." }
```

## Middleware

### Express

```ts
import express from "express";
import { agentAuth, requireAgentAuth, getAgentIdentity } from "authgent/middleware/express";

const app = express();

// Verify tokens on all requests (non-blocking — stores identity if valid)
app.use(agentAuth({ issuer: "http://localhost:8000" }));

// Enforce auth + scopes on specific routes
app.post("/tools/search",
  requireAgentAuth(["search:execute"]),
  (req, res) => {
    const identity = getAgentIdentity(req);
    res.json({ agent: identity.subject, scopes: identity.scopes });
  },
);
```

### Hono

```ts
import { Hono } from "hono";
import { agentAuth, requireAgentAuth, getAgentIdentity } from "authgent/middleware/hono";

const app = new Hono();

app.use("*", agentAuth({ issuer: "http://localhost:8000" }));

app.post("/tools/search", requireAgentAuth(["search:execute"]), (c) => {
  const identity = getAgentIdentity(c);
  return c.json({ agent: identity.subject });
});
```

## Adapters

### MCP Server

```ts
import { AgentAuthProvider } from "authgent/adapters/mcp";

const auth = new AgentAuthProvider({ serverUrl: "http://localhost:8000" });
const identity = await auth.verify(token);

// Discovery URLs for MCP clients
auth.metadataUrl; // http://localhost:8000/.well-known/oauth-authorization-server
auth.jwksUrl;     // http://localhost:8000/.well-known/jwks.json
```

### Protected Resource Metadata (RFC 9728)

```ts
import { ProtectedResourceMetadata } from "authgent/adapters/protected-resource";

const metadata = new ProtectedResourceMetadata({
  resource: "https://mcp-server.example.com",
  authorizationServers: ["http://localhost:8000"],
  scopesSupported: ["tools:execute", "db:read"],
});

// Serve at /.well-known/oauth-protected-resource
app.get("/.well-known/oauth-protected-resource", (req, res) => {
  res.json(metadata.toJSON());
});
```

## Error Handling

All SDK errors extend `AuthgentError`:

```ts
import { verifyToken, InvalidTokenError, DelegationError, DPoPError } from "authgent";

try {
  const identity = await verifyToken({ token, issuer });
} catch (err) {
  if (err instanceof InvalidTokenError) {
    // Token expired, wrong issuer, bad signature, etc.
  } else if (err instanceof DelegationError) {
    // Delegation chain too deep, unauthorized actor, etc.
  } else if (err instanceof DPoPError) {
    // DPoP proof mismatch, expired, wrong binding, etc.
  }
}
```

## API Reference

### Core

| Export | Description |
|--------|------------|
| `verifyToken(options)` | Verify JWT against issuer JWKS |
| `verifyDelegationChain(chain, options)` | Enforce delegation policies |
| `verifyDPoPProof(options)` | Verify DPoP proof-of-possession |
| `DPoPClient.create()` | Create DPoP proof generator |
| `AgentAuthClient` | Server API client |
| `JWKSFetcher` | JWKS cache with TTL |

### Models

| Type | Description |
|------|------------|
| `AgentIdentity` | Verified agent with subject, scopes, delegation chain |
| `DelegationChain` | Parsed `act` claims with depth, actors, humanRoot |
| `TokenClaims` | Raw + typed JWT claims |

### Middleware

| Import Path | Frameworks |
|-------------|-----------|
| `authgent/middleware/express` | Express 4/5 |
| `authgent/middleware/hono` | Hono (Node, Bun, Deno, Cloudflare Workers) |

### Adapters

| Import Path | Purpose |
|-------------|---------|
| `authgent/adapters/mcp` | MCP server auth provider |
| `authgent/adapters/protected-resource` | RFC 9728 metadata |

## License

Apache-2.0
