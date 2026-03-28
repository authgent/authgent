#!/usr/bin/env python3
"""One-time setup: register 3 agents with authgent-server, save credentials.

Run: python setup_agents.py
Requires: authgent-server running on localhost:8000
"""

import json
import httpx

SERVER = "http://localhost:8000"


def main():
    print("Registering agents with authgent-server...\n")

    agents = {}

    # Orchestrator — broad scopes, can delegate to others
    resp = httpx.post(f"{SERVER}/agents", json={
        "name": "orchestrator",
        "allowed_scopes": ["read", "write", "search", "db:read"],
        "owner": "platform-team",
        "capabilities": ["delegation", "orchestration"],
    })
    assert resp.status_code == 201, f"Failed: {resp.text}"
    data = resp.json()
    agents["orchestrator"] = {
        "id": data["id"],
        "client_id": data["client_id"],
        "client_secret": data["client_secret"],
    }
    print(f"  ✓ orchestrator  → {data['client_id']}")

    # Search Agent — can only search, needs exchange grant
    resp = httpx.post(f"{SERVER}/register", json={
        "client_name": "search-agent",
        "grant_types": [
            "client_credentials",
            "urn:ietf:params:oauth:grant-type:token-exchange",
        ],
        "scope": "search db:read",
    })
    assert resp.status_code == 201, f"Failed: {resp.text}"
    data = resp.json()
    agents["search_agent"] = {
        "client_id": data["client_id"],
        "client_secret": data["client_secret"],
    }
    print(f"  ✓ search-agent  → {data['client_id']}")

    # DB Agent — read-only access, needs exchange grant
    resp = httpx.post(f"{SERVER}/register", json={
        "client_name": "db-agent",
        "grant_types": [
            "client_credentials",
            "urn:ietf:params:oauth:grant-type:token-exchange",
        ],
        "scope": "db:read",
    })
    assert resp.status_code == 201, f"Failed: {resp.text}"
    data = resp.json()
    agents["db_agent"] = {
        "client_id": data["client_id"],
        "client_secret": data["client_secret"],
    }
    print(f"  ✓ db-agent      → {data['client_id']}")

    # Save credentials
    with open(".agents.json", "w") as f:
        json.dump(agents, f, indent=2)

    print(f"\nCredentials saved to .agents.json")
    print("Run: python run_pipeline.py")


if __name__ == "__main__":
    main()
