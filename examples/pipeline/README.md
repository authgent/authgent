# Multi-Agent Pipeline with authgent

This example shows a **real 3-agent pipeline** where:

```
Human (Alice) → Orchestrator → Search Agent → DB Agent
```

Each hop narrows scope, and every token carries a verifiable delegation chain.

## What's in this directory

| File | What it does |
|:-----|:-------------|
| `setup_agents.py` | Registers 3 agents with authgent-server, saves credentials to `.agents.json` |
| `run_pipeline.py` | Runs the full pipeline end-to-end — orchestrator → search → DB with scope narrowing, escalation blocking, and revocation |

## How to run

```bash
# Terminal 1: start authgent-server
cd ../../server
pip install -e ".[dev]"
authgent-server init && authgent-server run

# Terminal 2: register agents + run pipeline
cd examples/pipeline
pip install httpx fastapi uvicorn
python setup_agents.py       # one-time setup
python run_pipeline.py       # runs the full demo
```

## What you'll see

```
Step 1: Orchestrator authenticates
  → Token: sub=client:orchestrator, scope=read write search db:read

Step 2: Orchestrator delegates to Search Agent (scope: search db:read)
  → Token: sub=client:orchestrator, scope=search db:read
  → act: { sub: "client:orchestrator" }

Step 3: Search Agent delegates to DB Agent (scope: db:read only)
  → Token: sub=client:orchestrator, scope=db:read
  → act: { sub: "client:search-agent", act: { sub: "client:orchestrator" } }

Step 4: DB Agent verifies the full chain
  → Original subject: client:orchestrator
  → Delegation depth: 2
  → Chain: orchestrator → search-agent → db-agent
  → Scope at this hop: db:read (narrowed from original read write search db:read)
```
