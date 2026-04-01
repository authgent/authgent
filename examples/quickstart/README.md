# Quickstart — 60-Second Demo

Register agents, get tokens, delegate, and revoke — all against a live authgent-server.

## Prerequisites

```bash
pip install authgent-server httpx
```

## Run

**Terminal 1 — start the server:**
```bash
authgent-server run
```

**Terminal 2 — run the demo:**
```bash
python demo.py
```

## What it does

1. **Registers** two agents (orchestrator + search-bot) with scoped credentials
2. **Authenticates** the orchestrator via `client_credentials`
3. **Delegates** from orchestrator → search-bot with scope narrowing (RFC 8693 token exchange)
4. **Inspects** the delegated token to show the delegation chain
5. **Revokes** the token and confirms it's no longer valid

The entire flow runs in ~2 seconds against the local server.
