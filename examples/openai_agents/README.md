# OpenAI Agents SDK + authgent

Shows how to use authgent with the [OpenAI Agents SDK](https://github.com/openai/openai-agents-python) to build multi-agent pipelines where every tool call carries verifiable authorization.

## The Problem

```python
# Typical OpenAI agent tool — no auth, no delegation
@function_tool
def search_web(query: str) -> str:
    resp = httpx.get(f"https://search-api.com?q={query}")
    return resp.text
```

Who called this? Was it authorized? If Agent A delegated to Agent B — can the tool tell?

## The Fix

```python
from dataclasses import dataclass
from agents import Agent, Runner, function_tool, RunContextWrapper
from authgent.client import AgentAuthClient

@dataclass
class AuthCtx:
    auth: AgentAuthClient
    token: str  # scoped, delegated token for this agent

@function_tool
async def search_web(ctx: RunContextWrapper[AuthCtx], query: str) -> str:
    # Token carries delegation chain + enforced scopes
    headers = {"Authorization": f"Bearer {ctx.context.token}"}
    resp = httpx.get(f"https://search-api.com?q={query}", headers=headers)
    return resp.text

research = Agent(name="research", tools=[search_web])
orchestrator = Agent(name="orchestrator", handoffs=[research])
```

## What this example demonstrates

1. **Three agents** (orchestrator, research, writer) each with different scopes
2. **Orchestrator** delegates to research agent via token exchange — scope narrows
3. **Orchestrator** delegates to writer agent separately — different scope
4. **Scope enforcement** — writer can't escalate to search (blocked)
5. **Introspection** — see who holds what tokens with what delegation chains
6. **Token revocation** on shutdown

## Run

```bash
# Terminal 1: authgent-server
authgent-server run

# Terminal 2: run the example
pip install authgent httpx
python openai_agents_demo.py
```

> **Note:** This demo simulates the auth flow without requiring `openai-agents` or an API key.
> It shows the token lifecycle that your OpenAI Agents SDK code would use.

## Architecture

```
                ┌─────────────────────────────┐
                │  Orchestrator Agent         │
                │  scope: search write summ.  │
                │  token: root (no act claim) │
                └──────┬──────────┬───────────┘
                       │          │
    exchange (search)  │          │  exchange (write)
                       ▼          ▼
┌─────────────────────────┐  ┌─────────────────────────┐
│  Research Agent         │  │  Writer Agent           │
│  scope: search          │  │  scope: write           │
│  act: { sub: orch }     │  │  act: { sub: orch }     │
│  tools: search_web      │  │  tools: write_doc       │
└─────────────────────────┘  └─────────────────────────┘
         ✓ can search                 ✓ can write
         ✗ can't write                ✗ can't search
```
