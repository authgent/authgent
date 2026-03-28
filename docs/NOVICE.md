# AI Agents, MCP, and authgent — A Complete Beginner's Guide

**Audience:** You know a little about authentication (passwords, logins) but nothing about AI agents, MCP, or how this project works.

---

## Table of Contents

1. [What is an AI Model?](#1-what-is-an-ai-model)
2. [What is an API? (Claude, Gemini, GPT, etc.)](#2-what-is-an-api-claude-gemini-gpt-etc)
3. [What is an AI Agent?](#3-what-is-an-ai-agent)
4. [How Are Agents Built?](#4-how-are-agents-built)
5. [Why Do People Build Agents?](#5-why-do-people-build-agents)
6. [What is MCP?](#6-what-is-mcp)
7. [What is an MCP Server?](#7-what-is-an-mcp-server)
8. [The Security Problem — Why authgent Exists](#8-the-security-problem--why-authgent-exists)
9. [What is authgent?](#9-what-is-authgent)
10. [How authgent Works — Step by Step](#10-how-authgent-works--step-by-step)
11. [Real-World Example: Protecting Your SQL Database](#11-real-world-example-protecting-your-sql-database)
12. [How to Build Your Own Agent](#12-how-to-build-your-own-agent)
13. [Glossary](#13-glossary)

---

## 1. What is an AI Model?

An **AI model** is a giant mathematical function that has been trained on enormous amounts of text (and sometimes images, code, audio, etc.). You give it input (called a **prompt**), and it produces output (called a **completion** or **response**).

Think of it like this:

```
You type:  "What is the capital of France?"
Model says: "The capital of France is Paris."
```

The model doesn't "know" things the way you do. It has learned statistical patterns from billions of documents. It's very good at predicting what text should come next.

### Examples of AI models

| Model | Made by | What it is |
|:------|:--------|:-----------|
| **Claude** (Opus 4, Sonnet 4, Haiku) | Anthropic | A family of language models. Opus 4 is the most capable. |
| **GPT-4o, GPT-4.1** | OpenAI | Another family of language models. |
| **Gemini** (2.5 Pro, 2.5 Flash) | Google | Google's family of language models. |
| **Llama 4** | Meta | Open-source models you can run on your own computer. |

**Key point: These are NOT agents.** They are the "brains" that agents use. By themselves, a model just takes text in and puts text out. It can't browse the web, read your files, query your database, or send emails. It's just a very smart text predictor.

---

## 2. What is an API? (Claude, Gemini, GPT, etc.)

An **API** (Application Programming Interface) is a way for one program to talk to another program over the internet.

When people say "I'm using the Claude API" or "I'm calling GPT", they mean:

```
Your code  ──HTTP request──►  Anthropic's servers  ──response──►  Your code
              "What is 2+2?"                          "4"
```

You send a message (in a specific format) to a URL like `https://api.anthropic.com/v1/messages`, and you get a response back. It's like ordering food at a restaurant — you don't go into the kitchen, you just send your order through a waiter (the API).

### How you actually call an API

```python
import anthropic

client = anthropic.Anthropic(api_key="sk-ant-...")

response = client.messages.create(
    model="claude-sonnet-4-20250514",
    max_tokens=1024,
    messages=[{"role": "user", "content": "What is 2+2?"}]
)

print(response.content[0].text)  # "4"
```

That's it. You send a message, you get text back. The model runs on Anthropic's computers, not yours.

**The API key** (`sk-ant-...`) is like a password. It proves you have permission to use the API and they charge your account for usage.

---

## 3. What is an AI Agent?

An **agent** is a program that uses an AI model **plus tools** to accomplish tasks autonomously.

Here's the key difference:

| | AI Model alone | AI Agent |
|:--|:--------------|:---------|
| Can answer questions | ✅ | ✅ |
| Can read files on your computer | ❌ | ✅ |
| Can search the web | ❌ | ✅ |
| Can query a database | ❌ | ✅ |
| Can send emails | ❌ | ✅ |
| Can call other APIs | ❌ | ✅ |
| Can make decisions and take actions | ❌ | ✅ |
| Can delegate work to other agents | ❌ | ✅ |

### The anatomy of an agent

```
┌─────────────────────────────────────────┐
│              AI AGENT                    │
│                                          │
│  ┌──────────┐   ┌──────────────────┐    │
│  │  Brain    │   │  Tools           │    │
│  │ (Claude,  │   │  - Read files    │    │
│  │  GPT,     │   │  - Search web    │    │
│  │  Gemini)  │   │  - Run SQL       │    │
│  └─────┬─────┘   │  - Send email    │    │
│        │         │  - Call APIs     │    │
│        │         └────────┬─────────┘    │
│        │                  │              │
│        └───── loop ───────┘              │
│     "Think → Act → Observe → Repeat"    │
└─────────────────────────────────────────┘
```

An agent works in a loop:

1. **Think:** The AI model reads the task and decides what to do next
2. **Act:** It calls a tool (e.g., "run this SQL query")
3. **Observe:** It reads the result of the tool
4. **Repeat:** It decides if the task is done, or if it needs to do more

### A concrete example

You tell an agent: *"Find all customers who haven't ordered in 90 days and email them a 10% discount code."*

The agent:
1. **Thinks:** "I need to query the database for inactive customers"
2. **Acts:** Runs `SELECT * FROM customers WHERE last_order < NOW() - INTERVAL 90 DAY`
3. **Observes:** Gets back 47 customers
4. **Thinks:** "Now I need to generate discount codes and send emails"
5. **Acts:** Calls the email API for each customer
6. **Observes:** All emails sent
7. **Done.**

No human had to write the SQL query or the email template. The agent figured it out from the natural language instruction.

### What you're already using

**Windsurf (this IDE), Cursor, Claude Code** — these are all AI agents! They:
- Use an AI model (Claude, GPT, etc.) as their brain
- Have tools: read files, edit files, run terminal commands, search code
- Work in a loop: read your request → figure out what to do → make changes → verify

When you ask Windsurf to "fix the bug on line 42", it's an agent: it reads the file, understands the bug, edits the code, and maybe runs tests to verify.

---

## 4. How Are Agents Built?

There are several ways to build an agent, from simple to complex:

### Level 1: Raw API + tools (simplest)

You write Python (or any language) code that:
1. Calls the Claude/GPT API with a system prompt describing available tools
2. The model responds with which tool to call and what arguments to use
3. Your code executes the tool and feeds the result back to the model
4. Repeat until done

```python
import anthropic

client = anthropic.Anthropic()

# Define tools the agent can use
tools = [
    {
        "name": "run_sql",
        "description": "Execute a SQL query against the database",
        "input_schema": {
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "The SQL query to run"}
            },
            "required": ["query"]
        }
    }
]

# The agent loop
messages = [{"role": "user", "content": "How many users signed up this month?"}]

while True:
    response = client.messages.create(
        model="claude-sonnet-4-20250514",
        tools=tools,
        messages=messages,
    )

    # If the model wants to use a tool
    if response.stop_reason == "tool_use":
        tool_call = response.content[-1]      # e.g. run_sql("SELECT COUNT(*) ...")
        result = execute_tool(tool_call)       # You run the actual SQL
        messages.append({"role": "assistant", "content": response.content})
        messages.append({"role": "user", "content": [{"type": "tool_result", ...}]})
    else:
        # Model is done — print the final answer
        print(response.content[0].text)
        break
```

### Level 2: Agent frameworks (easier)

Frameworks like **LangChain**, **LangGraph**, **CrewAI**, **AutoGen**, and **Pydantic AI** provide pre-built patterns so you don't have to write the loop yourself:

```python
from langchain.agents import create_tool_calling_agent
from langchain_anthropic import ChatAnthropic
from langchain.tools import tool

@tool
def run_sql(query: str) -> str:
    """Execute a SQL query."""
    return db.execute(query)

llm = ChatAnthropic(model="claude-sonnet-4-20250514")
agent = create_tool_calling_agent(llm, tools=[run_sql])
agent.invoke({"input": "How many users signed up this month?"})
```

### Level 3: Multi-agent systems (complex)

Multiple agents work together, each specialized:

```
┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│ Orchestrator │────►│ Search Agent │     │  DB Agent    │
│  (plans the  │     │ (searches    │     │ (queries     │
│   work)      │────►│  the web)    │     │  databases)  │
└──────────────┘     └──────────────┘     └──────────────┘
```

The Orchestrator agent decides which sub-agents to call and coordinates the work. This is where things get interesting — and where security gets tricky.

---

## 5. Why Do People Build Agents?

### The short answer: automation that actually understands context

Before agents, automation meant rigid scripts:
```
IF email contains "invoice" THEN move to "Invoices" folder
```

With agents, automation understands nuance:
```
"Read my emails, figure out which ones need a response,
 draft replies in my writing style, and flag anything urgent."
```

### Real use cases

| Use case | What the agent does |
|:---------|:-------------------|
| **Code assistant** | Reads your codebase, writes code, runs tests, fixes bugs (Windsurf, Cursor, Claude Code) |
| **Customer support** | Reads customer history, checks order status, issues refunds, escalates complex cases |
| **Data analysis** | Queries databases, builds charts, writes reports, spots anomalies |
| **Research** | Searches papers, summarizes findings, identifies trends |
| **DevOps** | Monitors systems, diagnoses alerts, applies fixes, writes incident reports |
| **Sales** | Researches prospects, drafts personalized emails, updates CRM |

### Why now?

Models got good enough in 2024–2026 that they can reliably:
- Follow complex multi-step instructions
- Use tools correctly (call APIs with the right arguments)
- Reason about what to do next
- Know when to stop or ask for help

---

## 6. What is MCP?

**MCP** stands for **Model Context Protocol**. It was created by Anthropic and is now an open standard.

### The problem MCP solves

Every AI tool/agent needs to connect to external data sources — databases, file systems, APIs, etc. Before MCP, every integration was custom:

```
                        ┌── Custom code for Slack
                        ├── Custom code for GitHub
Claude/Windsurf ────────├── Custom code for PostgreSQL
                        ├── Custom code for Jira
                        └── Custom code for Google Drive
```

If you wanted Claude to read your Slack messages AND query your database AND check GitHub, you had to write custom integration code for each one. And if you switched from Claude to GPT, you'd have to rewrite all of it.

### MCP is like USB for AI

MCP standardizes how AI models connect to tools and data sources. Think of it like USB:

- **Before USB:** Every device had a different connector. Your printer had one cable, your keyboard another, your camera another.
- **After USB:** One standard connector for everything.

```
                        ┌── MCP Server: Slack
                        ├── MCP Server: GitHub
Claude/Windsurf ─MCP───├── MCP Server: PostgreSQL
                        ├── MCP Server: Jira
                        └── MCP Server: Google Drive
```

Now any AI client that speaks MCP can connect to any MCP server. You write the integration once, and it works with Claude, Windsurf, Cursor, or any other MCP-compatible client.

### The MCP architecture

```
┌───────────────────┐          ┌───────────────────┐
│    MCP Client     │          │    MCP Server      │
│  (Claude Desktop, │   MCP    │  (your data/tool   │
│   Windsurf,       │◄────────►│   adapter)         │
│   Cursor, etc.)   │ protocol │                    │
└───────────────────┘          └───────┬────────────┘
                                       │
                                       ▼
                               ┌───────────────┐
                               │  Your Data    │
                               │  (Database,   │
                               │   API, Files) │
                               └───────────────┘
```

- **MCP Client:** The AI app you use (Claude Desktop, Windsurf, etc.)
- **MCP Server:** A small program that exposes your data/tools in the MCP format
- **MCP Protocol:** The standardized way they communicate (JSON-RPC over stdio or HTTP)

---

## 7. What is an MCP Server?

An **MCP server** is a small program that wraps some data source or tool and makes it available to AI clients through the MCP protocol.

### Example: A SQL database MCP server

Let's say you have a PostgreSQL database. You want Claude Desktop to be able to query it. You'd run an MCP server that:

1. Connects to your PostgreSQL database
2. Exposes "tools" like `run_query`, `list_tables`, `describe_table`
3. Speaks the MCP protocol so Claude Desktop can discover and use these tools

```python
# Simplified MCP server example (using the mcp Python package)
from mcp.server import Server
import psycopg2

server = Server("my-database")
db = psycopg2.connect("postgresql://user:pass@localhost/mydb")

@server.tool()
def run_query(sql: str) -> str:
    """Execute a read-only SQL query."""
    cursor = db.cursor()
    cursor.execute(sql)
    return str(cursor.fetchall())

@server.tool()
def list_tables() -> str:
    """List all tables in the database."""
    cursor = db.cursor()
    cursor.execute("SELECT table_name FROM information_schema.tables WHERE table_schema='public'")
    return str(cursor.fetchall())

server.run()
```

Now in Claude Desktop, you'd configure this MCP server, and Claude can:
- Ask "What tables do you have?" → calls `list_tables()`
- Ask "How many orders were placed today?" → calls `run_query("SELECT COUNT(*) FROM orders WHERE ...")`

### MCP servers you might already be using

If you've configured tools in Windsurf or Claude Desktop, you're using MCP servers:

| MCP Server | What it does |
|:-----------|:-------------|
| **Filesystem** | Read/write files on your computer |
| **GitHub** | Read repos, create issues, review PRs |
| **PostgreSQL** | Query databases |
| **Slack** | Read/send messages |
| **Brave Search** | Search the web |

### The security problem with MCP servers

Here's where it gets scary. That MCP server above has `user:pass@localhost/mydb` hardcoded. That means:

- **Anyone who can talk to the MCP server has full database access**
- The AI can run ANY query — including `DROP TABLE customers`
- There's no audit trail of what was accessed
- There's no way to limit scope (read-only vs. read-write)
- If Agent A delegates to Agent B, Agent B gets the same full access

**This is the exact problem authgent solves.** Keep reading.

---

## 8. The Security Problem — Why authgent Exists

### The scenario

You're a developer. You have:
- A **production database** with customer data, orders, revenue numbers
- **Windsurf** (or Claude Code) as your AI coding assistant
- You want the AI to help you analyze data, but you **don't want to give it your database password**

Today, the options are bad:

#### Option A: Give the AI your credentials (dangerous)

```
You → Windsurf: "Here's my database URI: postgresql://admin:s3cret@prod.db.com/myapp"
```

Now the AI has your admin password. It's in the chat history. It might be in logs. Anyone with access to the logs can see it. The AI could accidentally run a `DELETE` or `UPDATE` query.

#### Option B: Don't give the AI access (useless)

The AI can't help you with database tasks at all.

#### Option C: Copy-paste data manually (tedious)

You run queries yourself, paste results into the chat. Works for simple things, but defeats the purpose of having an AI assistant.

### The deeper problem: agent-to-agent delegation

It gets worse when multiple agents work together:

```
You (Human)
  └─► Orchestrator Agent (you trust this one)
        └─► Data Analysis Agent (the orchestrator delegates to this)
              └─► SQL Query Agent (the analysis agent delegates to this)
                    └─► YOUR DATABASE  ← Who authorized THIS access?
```

Questions nobody can answer today:
- **Who authorized the SQL Query Agent to access your database?** You authorized the Orchestrator, but you never explicitly approved the SQL Query Agent.
- **What scope does it have?** Can it only SELECT, or can it INSERT/UPDATE/DELETE too?
- **Can you prove the delegation chain?** If something goes wrong, can you trace back through every hop?
- **Can you revoke access?** If the Orchestrator is compromised, can you kill all downstream tokens instantly?

With traditional auth (Auth0, Keycloak, etc.), the answer to all of these is **no**. They issue the first token and don't know about the chain.

---

## 9. What is authgent?

**authgent** is an OAuth 2.1 authorization server built specifically for AI agents.

Let's break that down:

### What is OAuth?

**OAuth** is the standard protocol that powers "Login with Google" buttons and API authentication everywhere. When you click "Login with Google" on a website, OAuth is what happens behind the scenes:

1. The website redirects you to Google
2. Google asks: "Do you want to let this website access your name and email?"
3. You click "Allow"
4. Google gives the website a **token** (a temporary key)
5. The website uses that token to access your info — nothing more

The key ideas in OAuth:
- **Tokens** instead of passwords — temporary, limited, revocable
- **Scopes** — the token only grants specific permissions (e.g., "read email" but not "delete email")
- **Consent** — the user explicitly approves what the app can do

### What does authgent add?

authgent takes OAuth and adds everything needed for **multi-agent systems**:

| Feature | What it means in plain English |
|:--------|:-------------------------------|
| **Agent identity** | Every agent gets its own ID and credentials, like a person gets a driver's license |
| **Token issuance** | Agents get temporary tokens (keys) instead of permanent passwords |
| **Scoped permissions** | Each token says exactly what the agent is allowed to do (e.g., "db:read" but NOT "db:write") |
| **Delegation chains** | When Agent A gives work to Agent B, the token tracks this: "Agent B is acting on behalf of Agent A, who was authorized by the human" |
| **Scope reduction** | At each delegation hop, permissions can only shrink, never grow. Agent A has read+write → gives Agent B only read. Agent B can NEVER escalate to write. |
| **Token revocation** | Kill any token instantly. If an agent is compromised, its token becomes useless. |
| **DPoP (proof of possession)** | Even if someone steals a token from logs, they can't use it — the token is cryptographically bound to the agent's private key |
| **Human-in-the-loop** | For sensitive operations, the agent pauses and asks a human for approval before proceeding |
| **Audit trail** | Every token issued, every delegation, every revocation is logged |

### Where authgent fits in the ecosystem

```
┌─────────────────────────────────────────────────────────┐
│                     YOUR SYSTEM                          │
│                                                          │
│  ┌──────────┐    ┌──────────────┐    ┌───────────────┐  │
│  │  Human   │    │  authgent    │    │  Your Data    │  │
│  │  (You)   │───►│  Server      │    │  (Database,   │  │
│  └──────────┘    │              │    │   APIs, etc.) │  │
│                  │  Issues      │    └───────┬───────┘  │
│  ┌──────────┐   │  tokens,     │            │          │
│  │ Agent A  │◄──│  tracks      │    ┌───────┴───────┐  │
│  │(Windsurf)│   │  delegation, │    │  MCP Server   │  │
│  └────┬─────┘   │  enforces    │    │  (protected   │  │
│       │         │  scopes      │    │   by authgent │  │
│  ┌────▼─────┐   │              │    │   SDK)        │  │
│  │ Agent B  │◄──│              │    └───────────────┘  │
│  │(DB query)│   └──────────────┘                       │
│  └──────────┘                                          │
└─────────────────────────────────────────────────────────┘
```

**authgent is the identity layer.** It sits between your agents and your data, making sure every access is authorized, scoped, tracked, and revocable.

---

## 10. How authgent Works — Step by Step

Let's walk through a real scenario step by step.

### Step 1: Start the server

```bash
pip install authgent-server
authgent-server init    # Creates config, database, signing keys
authgent-server run     # Starts the server on http://localhost:8000
```

You now have an OAuth 2.1 server running locally.

### Step 2: Register your agents

Each agent needs its own identity, like creating user accounts:

```bash
# Register an orchestrator agent with broad permissions
curl -X POST http://localhost:8000/agents \
  -H "Content-Type: application/json" \
  -d '{"name": "orchestrator", "allowed_scopes": ["db:read", "db:write", "search:execute"]}'

# Response:
# {
#   "id": "agnt_abc123",
#   "client_id": "agnt_abc123",
#   "client_secret": "sec_xyz789",    ← This is the agent's "password"
#   "name": "orchestrator"
# }
```

```bash
# Register a DB reader agent with ONLY read permission
curl -X POST http://localhost:8000/agents \
  -H "Content-Type: application/json" \
  -d '{"name": "db-reader", "allowed_scopes": ["db:read"]}'
```

### Step 3: Agent gets a token

When the orchestrator wants to do work, it authenticates and gets a token:

```bash
curl -X POST http://localhost:8000/token \
  -d "grant_type=client_credentials" \
  -d "client_id=agnt_abc123" \
  -d "client_secret=sec_xyz789" \
  -d "scope=db:read db:write"
```

The server returns a **JWT token** — a signed, tamper-proof JSON object:

```json
{
  "sub": "client:orchestrator",
  "scope": "db:read db:write",
  "iss": "http://localhost:8000",
  "exp": 1711400000,
  "aud": "http://localhost:8000"
}
```

### Step 4: Agent delegates to another agent (scope narrows)

The orchestrator needs the DB reader to fetch some data. It **exchanges** its token for a narrower one:

```bash
curl -X POST http://localhost:8000/token \
  -d "grant_type=urn:ietf:params:oauth:grant-type:token-exchange" \
  -d "subject_token=eyJ...orchestrator_token..." \
  -d "audience=agent:db-reader" \
  -d "scope=db:read" \
  -d "client_id=agnt_abc123" \
  -d "client_secret=sec_xyz789"
```

The new token:

```json
{
  "sub": "client:orchestrator",
  "scope": "db:read",
  "act": { "sub": "client:orchestrator" },
  "aud": "agent:db-reader"
}
```

Notice:
- **scope** shrank from `db:read db:write` to just `db:read`
- **act** (actor) claim appeared — it proves the orchestrator created this token
- If the orchestrator tried to give `db:write` to the DB reader, **the server would reject it** because the DB reader's `allowed_scopes` only includes `db:read`

### Step 5: MCP server validates the token

Your MCP server (the one that actually talks to the database) uses the authgent SDK to verify every request:

```python
from fastapi import FastAPI, Depends
from authgent.middleware.fastapi import AgentAuthMiddleware, get_agent_identity

app = FastAPI()
app.add_middleware(AgentAuthMiddleware, issuer="http://localhost:8000")

@app.post("/query")
async def run_query(sql: str, identity = Depends(get_agent_identity)):
    # identity.subject   → "client:orchestrator"
    # identity.scopes    → ["db:read"]
    # identity.delegation_chain → shows who delegated to whom

    if "db:read" not in identity.scopes:
        raise HTTPException(403, "You don't have db:read permission")

    if sql.strip().upper().startswith(("INSERT", "UPDATE", "DELETE", "DROP")):
        if "db:write" not in identity.scopes:
            raise HTTPException(403, "You don't have db:write permission")

    return db.execute(sql)
```

**No username or password is ever shared with the agent.** The agent presents a token, the MCP server validates it, and the MCP server (which you control) talks to the database.

---

## 11. Real-World Example: Protecting Your SQL Database

> *"I have a SQL database URI and I want Windsurf or Claude Code to read data but I don't want to give my username and password. Can this help?"*

**Yes, absolutely.** Here's exactly how.

### The architecture

```
┌────────────┐     ┌──────────────┐     ┌─────────────┐     ┌──────────┐
│  Windsurf  │     │   authgent   │     │  MCP Server │     │ Your SQL │
│  (Claude)  │────►│   Server     │     │  (you write │────►│ Database │
│            │     │              │     │   this)     │     │          │
│  "How many │     │  Validates   │     │  Validates  │     │ postgres │
│   users?"  │     │  agent ID,   │     │  token,     │     │ ://...   │
│            │     │  issues      │     │  runs query │     │          │
└──────┬─────┘     │  scoped      │     │  if allowed │     └──────────┘
       │           │  tokens      │     └──────┬──────┘
       │           └──────────────┘            │
       │                                       │
       └── Gets token, sends to MCP server ────┘
```

### Step-by-step setup

#### 1. Start authgent server

```bash
pip install authgent-server
authgent-server init
authgent-server run
# Running on http://localhost:8000
```

#### 2. Register an agent for Windsurf with read-only access

```bash
curl -X POST http://localhost:8000/agents \
  -H "Content-Type: application/json" \
  -d '{
    "name": "windsurf-agent",
    "allowed_scopes": ["db:read"]
  }'

# Save the client_id and client_secret
```

#### 3. Write a tiny MCP server that protects your database

```python
# my_db_server.py
from fastapi import FastAPI, Depends, HTTPException
from authgent.middleware.fastapi import AgentAuthMiddleware, get_agent_identity
import asyncpg

DATABASE_URL = "postgresql://admin:s3cret@localhost/myapp"  # YOUR real credentials
# ↑ This stays on YOUR server. The agent never sees it.

app = FastAPI()
app.add_middleware(AgentAuthMiddleware, issuer="http://localhost:8000")

pool = None

@app.on_event("startup")
async def startup():
    global pool
    pool = await asyncpg.create_pool(DATABASE_URL)

@app.post("/query")
async def query(sql: str, identity = Depends(get_agent_identity)):
    # The agent doesn't know the database password.
    # It just has a TOKEN that says "db:read".
    # We verify the token and decide whether to allow the query.

    if "db:read" not in identity.scopes:
        raise HTTPException(403, "Insufficient scope")

    # Safety: only allow SELECT queries
    if not sql.strip().upper().startswith("SELECT"):
        raise HTTPException(403, "Only SELECT queries are allowed with db:read scope")

    async with pool.acquire() as conn:
        rows = await conn.fetch(sql)
        return {"rows": [dict(r) for r in rows]}
```

#### 4. Configure Windsurf to use this MCP server

In your Windsurf MCP config, you'd point to this server. Windsurf would:

1. Authenticate with authgent using its `client_id` and `client_secret`
2. Get a token scoped to `db:read`
3. Send queries to your MCP server with the token
4. Your MCP server validates the token and runs ONLY SELECT queries

**What you achieved:**
- ✅ Windsurf can query your database
- ✅ Your database password is never exposed to the AI
- ✅ The agent can ONLY read — it literally cannot write or delete
- ✅ Every query is authenticated and auditable
- ✅ You can revoke access instantly by killing the token
- ✅ If the token is leaked in logs, DPoP makes it unusable by anyone else

### What if you don't want to write the MCP server yourself?

You can use an existing database MCP server and put authgent's middleware in front of it. The authgent SDK provides middleware for FastAPI, Flask (Python), Express, and Hono (JavaScript) — it's literally 3 lines of code added to any existing server:

```python
from authgent.middleware.fastapi import AgentAuthMiddleware
app.add_middleware(AgentAuthMiddleware, issuer="http://localhost:8000")
# That's it. Every request now requires a valid agent token.
```

---

## 12. How to Build Your Own Agent

If you want to build your own agent from scratch, here's the simplest path:

### Minimal agent in 30 lines

```python
import anthropic

client = anthropic.Anthropic()  # Uses ANTHROPIC_API_KEY env var

tools = [
    {
        "name": "read_file",
        "description": "Read a file from disk",
        "input_schema": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "File path to read"}
            },
            "required": ["path"]
        }
    }
]

def execute_tool(name, input):
    if name == "read_file":
        return open(input["path"]).read()

messages = [{"role": "user", "content": "Read my config.json and explain what it does"}]

while True:
    response = client.messages.create(
        model="claude-sonnet-4-20250514", max_tokens=4096,
        tools=tools, messages=messages,
    )
    # Append assistant response
    messages.append({"role": "assistant", "content": response.content})

    if response.stop_reason == "tool_use":
        results = []
        for block in response.content:
            if block.type == "tool_use":
                result = execute_tool(block.name, block.input)
                results.append({
                    "type": "tool_result",
                    "tool_use_id": block.id,
                    "content": result,
                })
        messages.append({"role": "user", "content": results})
    else:
        print(response.content[0].text)
        break
```

That's a working agent. It can read files and explain them.

### Adding authgent to your agent

When your agent needs to call protected services (like a database MCP server), you use the authgent SDK:

```python
from authgent import AgentAuthClient

auth = AgentAuthClient("http://localhost:8000")

# Get a scoped token
token = await auth.get_token(
    client_id="agnt_abc123",
    client_secret="sec_xyz789",
    scope="db:read",
)

# Use the token when calling the MCP server
import httpx
resp = await httpx.post(
    "http://localhost:9000/query",
    json={"sql": "SELECT * FROM users LIMIT 10"},
    headers={"Authorization": f"Bearer {token.access_token}"},
)
```

### Frameworks to make it easier

| Framework | Language | Good for |
|:----------|:---------|:---------|
| **LangChain / LangGraph** | Python | Most popular, huge ecosystem |
| **CrewAI** | Python | Multi-agent teams with roles |
| **AutoGen** | Python | Microsoft's multi-agent framework |
| **Pydantic AI** | Python | Type-safe, minimal |
| **Vercel AI SDK** | TypeScript | Web-based agents |
| **Mastra** | TypeScript | Full-stack agent framework |

---

## 13. Glossary

| Term | Plain English |
|:-----|:-------------|
| **AI Model** | The "brain" — a program trained on text that can understand and generate language (Claude, GPT, Gemini) |
| **API** | A way for programs to talk to each other over the internet |
| **API Key** | A secret string that proves you're allowed to use an API |
| **Agent** | A program that uses an AI model + tools to accomplish tasks autonomously |
| **MCP** | Model Context Protocol — a standard way for AI to connect to tools and data |
| **MCP Server** | A program that exposes tools/data to AI clients using the MCP protocol |
| **MCP Client** | The AI app (Claude Desktop, Windsurf, etc.) that connects to MCP servers |
| **OAuth** | The standard protocol for authorization — "let this app access my data with these permissions" |
| **Token** | A temporary key that grants specific permissions — like a movie ticket vs. a master key |
| **JWT** | JSON Web Token — a signed, tamper-proof token format |
| **Scope** | What a token is allowed to do (e.g., `db:read` means "can read from database") |
| **Delegation** | When Agent A gives Agent B a narrower version of its own permissions |
| **DPoP** | A security feature that binds a token to a specific key — stolen tokens are useless |
| **Token Exchange** | The process of trading one token for a narrower one (RFC 8693) |
| **Revocation** | Killing a token so it can never be used again |
| **Human-in-the-loop (HITL)** | Requiring a human to approve before an agent takes a sensitive action |
| **Introspection** | Asking the server "is this token valid and what does it allow?" |
| **authgent** | This project — an OAuth 2.1 server purpose-built for AI agent identity, delegation, and security |

---

## Summary

```
  Claude, GPT, Gemini         =  AI models (the "brains")
  Windsurf, Cursor, Claude Code  =  AI agents (brains + tools)
  MCP                          =  Standard protocol for connecting AI to data/tools
  MCP Server                   =  Program that exposes your data to AI via MCP
  OAuth                        =  Standard protocol for "who is allowed to do what"
  authgent                     =  OAuth server built for AI agents
                                  (identity, delegation chains, scope enforcement,
                                   token theft protection, audit trails)
```

**The key insight:** AI agents need the same kind of identity and access control that humans have had for decades — but with extra features for multi-agent delegation. authgent provides that.

**Your specific use case** (SQL database + Windsurf without sharing passwords): authgent sits between Windsurf and your database. Windsurf gets a read-only token. Your database credentials stay on your server. The agent can query but never delete. You can revoke access anytime. Every query is logged.

---

*This document is part of the [authgent](https://github.com/authgent/authgent) project — the open-source auth server built for AI agents.*
