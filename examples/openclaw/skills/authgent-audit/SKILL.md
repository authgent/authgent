---
name: authgent-audit
description: Query the authgent audit trail to see who authorized what, delegation chains, and security events. Essential for compliance and incident investigation.
metadata: {"openclaw":{"emoji":"📋","requires":{"bins":["python3"]}}}
---

# authgent-audit — Authorization Audit Trail

## What it does

Queries authgent-server's audit log to show a cryptographically verified trail of:
- Agent registrations
- Token issuances and scopes granted
- Delegation chains (who → delegated to → whom, with what scopes)
- Revocations (kill switch events)
- Failed authorization attempts (escalation blocks, invalid tokens)

## When to use

- When the user asks "what happened?", "show me the audit trail", "who did what?"
- After a security incident to trace the chain of events
- For compliance reporting
- To verify that delegation chains are working correctly

## Workflow

### View recent events

```bash
python3 ~/.openclaw/workspace/scripts/authgent_helper.py audit --limit 20
```

### Filter by agent

```bash
python3 ~/.openclaw/workspace/scripts/authgent_helper.py audit --client-id "<CLIENT_ID>" --limit 10
```

### Inspect a specific token's delegation chain

```bash
python3 ~/.openclaw/workspace/scripts/authgent_helper.py inspect --token "<TOKEN>"
```

## Output format

Present the audit trail as a readable timeline:
- Timestamp — Event — Agent — Details
- For delegation chains, show the full path: Agent A → Agent B → Agent C
- Highlight any DENIED or REVOKED events in the summary

## Guardrails

- Audit data may contain client_ids — never expose client_secrets.
- Present data factually — do not speculate about intent.
- If the audit endpoint returns empty results, confirm the time range and agent filter with the user.
