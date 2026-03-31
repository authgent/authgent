---
name: authgent-revoke
description: Kill switch — revoke an agent's token to block new requests and delegations. Existing child tokens expire per TTL (default 5 min). Use when an agent is compromised or a task must be stopped.
metadata: {"openclaw":{"emoji":"🔴","requires":{"bins":["python3"]}}}
---

# authgent-revoke — Kill Switch

## What it does

Revokes a token so it can no longer be used for new requests or new delegations.
Existing child tokens (issued via prior token exchange) remain valid until their
short TTL expires (default 5 min). For immediate full-chain kill, revoke each
token individually. One revoke call seals the root — no new branches can grow.

## When to use

- When the user says "stop", "kill", "revoke", "shut it down", or "emergency"
- When an agent is behaving unexpectedly or appears compromised
- When a delegated task should be cancelled immediately
- After a security incident to contain the blast radius

## Workflow

### Revoke a specific token

```bash
python3 ~/.openclaw/workspace/scripts/authgent_helper.py revoke \
  --token "<TOKEN_TO_REVOKE>" \
  --client-id "<OWNER_CLIENT_ID>" \
  --client-secret "<OWNER_CLIENT_SECRET>"
```

### Verify it's dead

```bash
python3 ~/.openclaw/workspace/scripts/authgent_helper.py introspect --token "<REVOKED_TOKEN>"
# Should return: {"active": false}
```

## Important

- Only the **token's owner** (the client that originally received it) can revoke it.
- Revoking a parent token blocks it from further use and from new exchanges.
- Existing child tokens (issued via prior exchange) are independent JWTs — they remain
  valid until their short TTL expires (default 5 min). For immediate full kill, revoke
  each child token individually.
- Revocation is **instant for the revoked token** — it is added to a blocklist checked on every request.
- Per RFC 7009, the server returns 200 even if the token was already revoked.

## Guardrails

- Confirm with the user before revoking if the action was not explicitly requested.
- After revoking, notify any affected agents that their authorization has been terminated.
- Log the revocation event for audit purposes.

## Example

User: "Kill the research agent's access immediately"

```bash
python3 scripts/authgent_helper.py revoke \
  --token "eyJ..." \
  --client-id "agnt_orchestrator" \
  --client-secret "sec_..."

# → {"status": 200, "_action": "Token revoked — all downstream delegations are now invalid"}

python3 scripts/authgent_helper.py introspect --token "eyJ..."
# → {"active": false}
```

Result: Token revoked. Research agent and all agents it delegated to can no longer act.
