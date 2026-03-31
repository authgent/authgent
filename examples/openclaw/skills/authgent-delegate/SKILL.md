---
name: authgent-delegate
description: Securely delegate work to another OpenClaw agent with scope-narrowed authorization. Creates a scoped token via RFC 8693 token exchange before sending work via sessions_send.
metadata: {"openclaw":{"emoji":"🔗","requires":{"bins":["python3"]}}}
---

# authgent-delegate — Secure Agent-to-Agent Delegation

## What it does

Before delegating work to another agent via `sessions_send`, this skill creates a
**scope-narrowed delegated token** via authgent's token exchange (RFC 8693).
The receiving agent can verify this token to confirm:
- Who authorized the work
- What scopes (permissions) were granted
- The full delegation chain (who → authorized → whom)

## When to use

- Before sending work to another agent via `sessions_send`
- When the user says "delegate", "hand off", "send to agent", or "securely assign"
- Any time work crosses agent boundaries and needs authorization proof

## Prerequisites

- This agent must already have credentials from `authgent-identity` skill
- The target agent must be registered with authgent
- authgent-server must be running

## Workflow

1. Identify the **target agent's client_id** (the agent you're delegating to).
2. Determine what **scopes** the target agent needs. **Always narrow the scope** — only grant what's needed for this specific task.
3. Run token exchange:

```bash
python3 ~/.openclaw/workspace/scripts/authgent_helper.py delegate \
  --subject-token "<YOUR_ACCESS_TOKEN>" \
  --client-id "<TARGET_CLIENT_ID>" \
  --client-secret "<TARGET_CLIENT_SECRET>" \
  --audience "<TARGET_AGENT_NAME>" \
  --scope "<NARROWED_SCOPES>"
```

4. Parse the JSON output. Extract the `access_token` — this is the **delegated token**.
5. Include the delegated token in your `sessions_send` message using this format:

```
[AUTHGENT_TOKEN:<delegated_access_token>]

<your actual task instructions here>
```

6. The receiving agent uses `authgent-verify` to validate the token before executing.

## Scope narrowing rules

- You can only grant scopes **you already have** — never more.
- Always grant the **minimum** scopes needed for the task.
- Example: if you have `search read write delete`, and the task only needs search, delegate with `--scope "search"` only.

## Output format

Report to the user:
- Target agent name
- Delegated scopes (what permissions the target gets)
- Parent scopes (what you had)
- Delegation depth (how many hops deep)

## Guardrails

- **Never delegate your full scope set** — always narrow.
- **Never send your own client_secret** to another agent — use token exchange.
- If token exchange fails with "scope_escalation", you're requesting scopes you don't have.
- If it fails with "invalid_grant", your own token may be expired — re-authenticate first.

## Example

User: "Ask the research agent to search for AI safety papers"

```bash
# 1. Exchange token with narrowed scope
python3 scripts/authgent_helper.py delegate \
  --subject-token "eyJ..." \
  --client-id "agnt_research123" \
  --client-secret "sec_..." \
  --audience "research-agent" \
  --scope "search"

# 2. Send to agent with token
# sessions_send to research-agent:
# [AUTHGENT_TOKEN:eyJ_delegated_token...]
# Please search for recent AI safety papers and summarize the top 5.
```
