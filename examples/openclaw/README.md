# OpenClaw + authgent — Secure Multi-Agent Authorization

**Zero OpenClaw code changes.** Just 5 skills + 1 helper script.

## The Problem

OpenClaw agents communicate via `sessions_send` — but there's no cryptographic proof of
who authorized what. Any agent with `bash` access can impersonate any other agent.
There's no scope enforcement across agent boundaries, no delegation chain tracking,
and no way to instantly revoke a compromised agent's authority.

## The Solution

Drop 5 authgent skills into your OpenClaw workspace. Each agent gets a cryptographic
identity (signed JWT), delegations are scope-narrowed and auditable, and a single API
call kills an entire delegation chain.

```
Without authgent                     With authgent
─────────────────                    ─────────────────
sessions_send("do X")                sessions_send("[AUTHGENT_TOKEN:eyJ...] do X")
  → trust on faith                     → cryptographic proof of authorization
  → no scope limits                    → scope narrowed per delegation
  → no audit trail                     → full who→authorized→whom→for what
  → no kill switch                     → one call revokes entire chain
```

## Quick Start

### 1. Install authgent-server

```bash
pip install authgent-server httpx
authgent-server run
```

### 2. Copy skills to OpenClaw workspace

```bash
cp -r skills/* ~/.openclaw/workspace/skills/
cp -r scripts ~/.openclaw/workspace/scripts
```

Or create symlinks:

```bash
ln -s $(pwd)/skills/* ~/.openclaw/workspace/skills/
ln -s $(pwd)/scripts ~/.openclaw/workspace/scripts
```

### 3. Run the demo (no OpenClaw required)

The demo simulates what happens inside OpenClaw agents:

```bash
# Terminal 1: start authgent-server
authgent-server run

# Terminal 2: run the demo
python demo_openclaw_authgent.py
```

## Skills

| Skill | Purpose | When to use |
|:------|:--------|:------------|
| `authgent-identity` | Register agent + get JWT | On first use / startup |
| `authgent-delegate` | Scope-narrowed token exchange before `sessions_send` | Before delegating work |
| `authgent-verify` | Verify incoming token before executing | When receiving delegated work |
| `authgent-audit` | Query the authorization audit trail | Compliance / debugging |
| `authgent-revoke` | Kill switch — revoke token chain | Emergency / task cancellation |

## Demo Flow

```
Step 1: Register 3 agents (Orchestrator, Research, DB)
Step 2: Orchestrator authenticates → signed JWT (search read write db:read)
Step 3: Orchestrator → Research Agent (scope narrowed to: search db:read)
Step 4: Research Agent verifies token before executing
Step 5: Research Agent tries to escalate to "write" → BLOCKED ✗
Step 6: Research → DB Agent (2-hop delegation, db:read only)
Step 7: Human inspects the delegation chain audit trail
Step 8: KILL SWITCH — revoke root token → entire chain dies
Step 9: Verify: revoked token cannot create new delegations
```

## How It Works Inside OpenClaw

### Orchestrator agent's SOUL.md

```markdown
When delegating work to another agent:
1. Use the authgent-delegate skill to create a scoped token
2. Include the token in your sessions_send message
3. Only grant the minimum scopes needed for the task
```

### Receiving agent's SOUL.md

```markdown
When receiving work from another agent:
1. Look for [AUTHGENT_TOKEN:...] in the message
2. Use the authgent-verify skill to validate before executing
3. Never execute delegated work without a valid token
4. Never exceed the granted scopes
```

## File Structure

```
examples/openclaw/
├── README.md
├── demo_openclaw_authgent.py    # Interactive demo (runs against live server)
├── scripts/
│   └── authgent_helper.py       # CLI wrapper for authgent API (used by skills)
└── skills/
    ├── authgent-identity/       # Register + authenticate
    │   └── SKILL.md
    ├── authgent-delegate/       # Scope-narrowed delegation
    │   └── SKILL.md
    ├── authgent-verify/         # Verify incoming tokens
    │   └── SKILL.md
    ├── authgent-audit/          # Query audit trail
    │   └── SKILL.md
    └── authgent-revoke/         # Kill switch
        └── SKILL.md
```

## What authgent Adds to OpenClaw

| Capability | OpenClaw Alone | OpenClaw + authgent |
|:-----------|:---------------|:--------------------|
| Agent identity | Session name | Signed JWT (ES256) |
| Delegation proof | Text message | RFC 8693 token exchange |
| Scope enforcement | Tool allowlist (binary) | Per-delegation scope narrowing |
| Audit trail | Chat history | Cryptographic authorization log |
| Revocation | Kill session | Kill entire delegation chain |
| HITL step-up | None | Human approval gate for dangerous ops |
| Standards | — | OAuth 2.1, RFC 8693, RFC 7009, RFC 9449 |
