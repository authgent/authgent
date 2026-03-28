# LangChain Agent with authgent

Shows how to use the `AuthgentToolWrapper` to automatically manage tokens when LangChain agents call external tools.

## The Problem

```python
# Typical LangChain tool — no auth, no delegation tracking
@tool
def search(query: str) -> str:
    resp = httpx.get(f"https://search-api.com?q={query}")
    return resp.text
```

## The Fix (using authgent adapter)

```python
from authgent.adapters.langchain import AuthgentToolWrapper

# Create wrapper — handles token lifecycle automatically
wrapper = AuthgentToolWrapper(
    server_url="http://localhost:8000",
    client_id=os.environ["AGENT_CLIENT_ID"],
    client_secret=os.environ["AGENT_CLIENT_SECRET"],
    scope="search:execute",
)

@tool
async def search(query: str) -> str:
    # Get auth headers (auto-refreshes expired tokens)
    headers = await wrapper.get_auth_headers()
    resp = httpx.get(f"https://search-api.com?q={query}", headers=headers)
    return resp.text

# Or delegate to a different resource (auto token exchange)
@tool
async def query_db(sql: str) -> str:
    headers = await wrapper.get_auth_headers(
        resource="https://db-agent.internal.com",  # triggers token exchange
        http_method="POST",
        http_uri="https://db-agent.internal.com/query",
    )
    resp = httpx.post("https://db-agent.internal.com/query",
                      json={"sql": sql}, headers=headers)
    return resp.text
```

## Run

```bash
# Terminal 1: authgent-server
authgent-server run

# Terminal 2: run the example
pip install authgent langchain-core langchain-openai httpx
export OPENAI_API_KEY=sk-...
python langchain_agent.py
```
