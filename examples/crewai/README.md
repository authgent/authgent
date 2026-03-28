# CrewAI + authgent

Shows how to use authgent with [CrewAI](https://github.com/crewAIInc/crewAI) to build authenticated multi-agent crews where every agent has its own identity, scoped permissions, and verifiable delegation chains.

## The Problem

```python
# Typical CrewAI tool — no auth, no identity tracking
@tool
def search_web(query: str) -> str:
    return httpx.get(f"https://search-api.com?q={query}").text
```

CrewAI agents share one process. If one agent calls a tool, the tool has no idea which agent called it, what scopes it has, or who authorized it.

## The Fix

```python
from authgent.adapters.langchain import AuthgentToolWrapper

# One wrapper per agent — manages token lifecycle
researcher_auth = AuthgentToolWrapper(
    server_url="http://localhost:8000",
    client_id=os.environ["RESEARCHER_CLIENT_ID"],
    client_secret=os.environ["RESEARCHER_CLIENT_SECRET"],
    scope="search read",
)

@tool
async def search_web(query: str) -> str:
    headers = await researcher_auth.get_auth_headers()
    return httpx.get(f"https://search-api.com?q={query}", headers=headers).text
```

## What this example demonstrates

1. **Three CrewAI agents** (researcher, analyst, writer) with different scopes
2. **Each agent authenticates** with its own credentials at task start
3. **Token exchange** when work flows between agents (scope narrows)
4. **Scope enforcement** — writer can't use search tools
5. **Audit trail** — introspect tokens to see who did what
6. **Token revocation** on crew completion

## Run

```bash
# Terminal 1: authgent-server
authgent-server run

# Terminal 2: run the example
pip install authgent httpx
python crewai_demo.py
```

> **Note:** This demo simulates the auth flow without requiring `crewai` installed.
> It shows the per-agent token lifecycle that your CrewAI tools would use.

## Architecture

```
┌─────────── CrewAI Crew ────────────────────────────┐
│                                                      │
│  ┌────────────┐  ┌────────────┐  ┌────────────┐    │
│  │ Researcher  │  │  Analyst   │  │   Writer   │    │
│  │ search,read │  │  read,db   │  │   write    │    │
│  └──────┬─────┘  └──────┬─────┘  └──────┬─────┘    │
│         │               │               │           │
│         └───────────────┼───────────────┘           │
│                         │                            │
│              ┌──────────▼──────────┐                │
│              │  authgent-server     │                │
│              │  token per agent     │                │
│              │  scope enforcement   │                │
│              └─────────────────────┘                │
└──────────────────────────────────────────────────────┘
```
