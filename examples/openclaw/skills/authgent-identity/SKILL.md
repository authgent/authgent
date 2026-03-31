---
name: authgent-identity
description: Register this OpenClaw agent with authgent-server and obtain a cryptographic identity (OAuth 2.1 client credentials). Run this before any secure delegation or tool access.
metadata: {"openclaw":{"emoji":"🪪","requires":{"bins":["python3","curl"]}}}
---

# authgent-identity — Agent Registration & Authentication

## What it does

Registers this agent with an authgent-server instance and stores its credentials.
After registration, the agent has a cryptographic identity (client_id + client_secret)
and can authenticate to get signed JWTs with scoped permissions.

## When to use

- First time this agent needs to interact securely with other agents
- When the user says "register with authgent", "get identity", or "authenticate"
- Before using authgent-delegate or authgent-verify skills

## Prerequisites

- authgent-server running (default: http://localhost:8000)
- Python 3 + httpx installed (`pip install httpx`)
- Helper script at the skill workspace path

## Workflow

### Register a new agent

1. Ask the user for: agent name, scopes (permissions), and owner (optional).
2. Run:

```bash
python3 ~/.openclaw/workspace/scripts/authgent_helper.py register \
  --name "<AGENT_NAME>" \
  --scopes "<SPACE_SEPARATED_SCOPES>" \
  --owner "<OWNER_EMAIL>"
```

3. Parse the JSON output. Save `client_id` and `client_secret` — you will need these for every subsequent authgent operation.
4. Report the registration result to the user. **Never display the full client_secret** — show only the first 8 characters.

### Authenticate (get a token)

1. Run:

```bash
python3 ~/.openclaw/workspace/scripts/authgent_helper.py authenticate \
  --client-id "<CLIENT_ID>" \
  --client-secret "<CLIENT_SECRET>" \
  --scope "<REQUESTED_SCOPES>"
```

2. Parse the JSON output. The `access_token` field is your signed JWT.
3. Store the `access_token` for use in delegation or tool calls.

## Output format

Report to the user:
- Agent name and client_id
- Granted scopes
- Token expiry (expires_in seconds)

## Guardrails

- Never log or display full client_secret values.
- Never hardcode credentials in messages to other agents — use token exchange instead.
- If registration fails, show the error and ask the user to check that authgent-server is running.

## Example

User: "Register a research agent with search and read permissions"

```bash
python3 scripts/authgent_helper.py register --name "research-agent" --scopes "search read"
# → {"status": 201, "client_id": "agnt_abc123", "client_secret": "sec_...", "name": "research-agent"}

python3 scripts/authgent_helper.py authenticate --client-id "agnt_abc123" --client-secret "sec_..." --scope "search read"
# → {"status": 200, "access_token": "eyJ...", "scope": "search read", "expires_in": 3600}
```
