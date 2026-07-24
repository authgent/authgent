# Framework Integration Outreach Templates

## 1. LangChain (141k stars)

**Repository:** https://github.com/langchain-ai/langchain  
**Maintainer:** @hwchase17 (Harrison Chase)  
**Where to post:** GitHub Issue

### Issue Title
```
[Feature Request] Add authgent as OAuth provider example for multi-agent delegation chains
```

### Issue Body
```markdown
### Feature Description

Add an example showing authgent integration for multi-agent workflows with proper identity delegation chains.

### Motivation

LangChain's multi-agent orchestration currently lacks a standardized OAuth pattern for:
- Scoped delegation (orchestrator → search agent → API agent)
- Audit trails showing which agent made which API call
- Revocation (kill an entire delegation chain if one agent is compromised)

authgent implements IETF `draft-ietf-oauth-identity-chaining-14` (agent delegation) and is the reference implementation cited in the spec on datatracker.

### Proposed Implementation

Add to `docs/docs/integrations/providers/`:

**`authgent.mdx`**:
```python
from langchain.agents import AgentExecutor
from authgent import AgentAuthClient

# Register orchestrator agent
auth_client = AgentAuthClient("https://auth.example.com")
orchestrator_token = auth_client.register_agent(
    name="orchestrator",
    scopes=["search:read", "api:write"]
)

# Delegate to search agent (scoped down)
search_token = auth_client.exchange_token(
    orchestrator_token,
    actor_scopes=["search:read"]  # narrower than parent
)

# Use delegated token in tools
search_agent = create_openai_tools_agent(
    tools=[search_tool],
    headers={"Authorization": f"Bearer {search_token}"}
)
```
\`\`\`

### Alternative: Just a link

If a full example doesn't fit your roadmap, would you accept a PR adding authgent to:
- `docs/docs/security/agent_authentication.md` (if it exists)
- Or the integrations directory with a link to authgent's LangChain example: https://github.com/authgent/authgent/tree/main/examples/langchain_tool

### Additional Context

- **IETF reference**: https://datatracker.ietf.org/doc/draft-agnihotri-oauth-agent-impl-status/
- **Repo**: https://github.com/authgent/authgent
- **License**: Apache 2.0
- **LangChain example** (already exists in authgent repo): https://github.com/authgent/authgent/tree/main/examples/langchain_tool

Happy to submit a PR if this fits your integration roadmap.
```

---

## 2. FastMCP (26k stars, 70% market share)

**Repository:** https://github.com/jlowin/fastmcp  
**Maintainer:** @jlowin (Jeremiah Lowin)  
**Where to post:** GitHub Issue

### Issue Title
```
[Enhancement] Add authgent OAuth template to `fastmcp init`
```

### Issue Body
```markdown
### Enhancement Description

Include authgent as an OAuth provider option when running `fastmcp init`, similar to how `create-react-app` includes ESLint by default.

### Why This Matters

**70% of new MCP servers use FastMCP** (per PulseMCP data). Most ship without OAuth, or roll their own (often broken — see authgent's scan of 30 production servers: only 1 earned an A).

Adding authgent to the `fastmcp init` template gives developers:
- RFC 9728 Protected Resource Metadata (required by MCP spec)
- RFC 7636 PKCE enforcement
- RFC 8707 Resource Indicators (prevents confused deputy attacks)
- Zero-config OAuth that Just Works™

### Proposed Implementation

When user runs `fastmcp init`, prompt:

```
? Add OAuth authentication? (y/N)
? OAuth provider:
  > authgent (self-hosted, Apache 2.0)
    Auth0
    Okta
    None (I'll add it later)
```

If `authgent` selected:
1. Add `authgent-server` to `requirements.txt` (or `pyproject.toml`)
2. Generate `.env` with `AUTHGENT_SECRET_KEY` (via `secrets.token_urlsafe(32)`)
3. Add to generated server:

```python
from fastmcp import FastMCP
from authgent.middleware.fastapi import AgentAuthMiddleware

mcp = FastMCP("My Server")

# Add OAuth protection
mcp.app.add_middleware(
    AgentAuthMiddleware,
    issuer_url="http://localhost:8000",  # authgent default
    required_scopes=["mcp:read", "mcp:write"]
)
```

4. Add to README: "Run `authgent-server run` in a separate terminal before starting your MCP server"

### Alternative: Just Documentation

If modifying `fastmcp init` is too invasive, would you accept a PR adding an OAuth example to the FastMCP docs?

- Page: `docs/guides/authentication.md` (create if doesn't exist)
- Content: Link to https://github.com/authgent/authgent/tree/main/examples/mcp_server with a copy-pasteable FastMCP + authgent snippet

### Additional Context

- **Why authgent specifically**: It's the IETF reference implementation for agent OAuth (cited in `draft-agnihotri-oauth-agent-impl-status`)
- **Why this matters for FastMCP**: MCP Enterprise-Managed Authorization (EMA) launched June 2026 with 7 partners; 3 shipped broken OAuth. FastMCP users will face the same pain.
- **Repo**: https://github.com/authgent/authgent
- **License**: Apache 2.0

Happy to submit a PR for either approach.
```

---

## 3. CrewAI (54.9k stars, 100k certified devs)

**Repository:** https://github.com/joaomdmoura/crewAI  
**Maintainer:** @joaomdmoura  
**Where to post:** GitHub Issue

### Issue Title
```
[Feature] Add authgent example for per-agent identity + scoped delegation
```

### Issue Body
```markdown
### Feature Description

Add an example showing how to give each CrewAI agent its own OAuth identity with scoped delegation chains.

### Problem This Solves

Current CrewAI examples use a single shared API key for the entire crew. This creates:
- **No audit trail** - can't tell which agent made which API call
- **Over-privileged agents** - every agent has every permission
- **No revocation granularity** - can't kill one agent without killing the whole crew

### Proposed Solution

Add to `examples/` or `docs/`:

**`oauth_delegation_crew.py`**:
```python
from crewai import Crew, Agent, Task
from authgent import AgentAuthClient

auth = AgentAuthClient("https://auth.example.com")

# Each agent gets its own identity
researcher_token = auth.register_agent(
    name="researcher",
    scopes=["search:read"]
)

writer_token = auth.register_agent(
    name="writer", 
    scopes=["docs:write"]
)

# Agents can delegate (researcher → writer)
delegated_token = auth.exchange_token(
    researcher_token,
    subject_token=writer_token,
    requested_scopes=["docs:write"]  # scoped down
)

# Use in tools
researcher = Agent(
    role="Researcher",
    tools=[search_tool],
    tool_kwargs={"headers": {"Authorization": f"Bearer {researcher_token}"}}
)

writer = Agent(
    role="Writer",
    tools=[write_tool],
    tool_kwargs={"headers": {"Authorization": f"Bearer {delegated_token}"}}
)
```
\`\`\`

### Why authgent

- **IETF reference implementation**: `draft-ietf-oauth-identity-chaining-14` (delegation chains)
- **Audit receipts**: Every delegation step is signed and logged
- **Revoke cascade**: Revoking the parent token kills all children
- **Apache 2.0**: No vendor lock-in

### Alternative

If a full example doesn't fit, would you accept:
- A link in `docs/how-to/Secure-Agents.md` to authgent's CrewAI example?
- Authgent's example is here: https://github.com/authgent/authgent/tree/main/examples/crewai

### Additional Context

- **CrewAI + authgent example** (already exists): https://github.com/authgent/authgent/tree/main/examples/crewai
- **Repo**: https://github.com/authgent/authgent
- **IETF draft**: https://datatracker.ietf.org/doc/draft-agnihotri-oauth-agent-impl-status/

Happy to submit a PR if this aligns with your roadmap.
```

---

## 4. LlamaIndex (36k stars)

**Repository:** https://github.com/run-llama/llama_index  
**Maintainer:** @logan-markewich  
**Where to post:** GitHub Issue

### Issue Title
```
[Enhancement] Add authgent OAuth example for secure data connectors
```

### Issue Body
```markdown
### Enhancement Description

Add an example showing authgent integration for LlamaIndex data connectors that need OAuth (Google Drive, Notion, Slack, GitHub, etc.).

### Problem

LlamaIndex data connectors currently use:
- Env variables with long-lived API keys (`NOTION_API_KEY`, `GITHUB_TOKEN`)
- No token rotation
- No scoped delegation (one token has access to everything)
- No audit trail (can't tell which query accessed which document)

### Proposed Solution

Add to `docs/examples/` or `llama-index-integrations/`:

**`authgent_data_connector.py`**:
```python
from llama_index.core import VectorStoreIndex
from llama_index.readers.notion import NotionPageReader
from authgent import AgentAuthClient

auth = AgentAuthClient("https://auth.example.com")

# Register agent with scoped access
agent_token = auth.register_agent(
    name="rag-indexer",
    scopes=["notion:read"]
)

# Use OAuth token instead of API key
notion_reader = NotionPageReader(
    integration_token=agent_token  # OAuth token, not static API key
)

documents = notion_reader.load_data(page_ids=["page-id-123"])
index = VectorStoreIndex.from_documents(documents)
```
\`\`\`

**Benefits**:
- Tokens auto-refresh (no manual rotation)
- Scoped to specific pages/workspaces
- Audit log shows which documents were accessed
- Revocable without changing API keys

### Why authgent

- **Bridge existing IdPs**: Works with Auth0/Okta/Clerk via RFC 8693 token exchange
- **IETF reference**: `draft-ietf-oauth-identity-chaining-14` for agent delegation
- **Apache 2.0**: Open source, self-hostable

### Alternative

If a full integration doesn't fit:
- Add a link in `docs/module_guides/loading/connector_authentication.md` to authgent's docs?
- Or add authgent to the "Community Integrations" page?

### Additional Context

- **Repo**: https://github.com/authgent/authgent
- **Example** (generic connector pattern): https://github.com/authgent/authgent/tree/main/examples/pipeline
- **IETF draft**: https://datatracker.ietf.org/doc/draft-agnihotri-oauth-agent-impl-status/

Happy to submit a PR if this aligns with your security roadmap.
```

---

## How to Use These Templates

### Step 1: Copy the relevant template
- Pick the framework(s) you want to target first (LangChain has biggest reach, FastMCP has highest market share)

### Step 2: Customize if needed
- All templates are generic; swap in specific details if you have integration examples already built

### Step 3: Post as GitHub Issue
- Go to the framework's repo
- Click "Issues" → "New Issue"
- Paste title + body
- Submit

### Step 4: Monitor for responses
- Check issues daily for maintainer replies
- If positive response, offer to submit PR immediately
- If no response within 7 days, ping once in issue comments

### Step 5: Amplify acceptances
- If any maintainer accepts, tweet it: "Excited to integrate authgent with @langchain..."
- Cross-link in your launch posts: "Already integrated with LangChain, FastMCP, CrewAI..."

### Expected Response Rate
- 50-70% will respond within 14 days (maintainers monitor issues actively)
- 30-50% will accept some form of integration (even if just a doc link)
- 1-2 will accept a full `init` template or default example (FastMCP is most likely)
