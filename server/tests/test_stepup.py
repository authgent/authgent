"""Tests for HITL Step-Up Authorization endpoints."""

import pytest


@pytest.mark.asyncio
async def test_stepup_create_and_poll(test_client):
    """Create a step-up request and poll its status."""
    resp = test_client.post("/stepup", json={
        "agent_id": "agnt_test",
        "action": "delete_database",
        "scope": "db:delete",
        "resource": "https://api.example.com/db",
    })
    assert resp.status_code == 202
    body = resp.json()
    assert body["status"] == "pending"
    assert body["agent_id"] == "agnt_test"
    assert body["action"] == "delete_database"
    assert body["scope"] == "db:delete"
    request_id = body["id"]

    # Poll
    poll = test_client.get(f"/stepup/{request_id}")
    assert poll.status_code == 200
    assert poll.json()["status"] == "pending"


@pytest.mark.asyncio
async def test_stepup_approve(test_client):
    """Approve a pending step-up request."""
    create = test_client.post("/stepup", json={
        "agent_id": "agnt_test",
        "action": "send_email",
        "scope": "email:send",
    })
    request_id = create.json()["id"]

    resp = test_client.post(f"/stepup/{request_id}/approve", json={
        "approved_by": "alice@example.com",
    })
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "approved"
    assert body["approved_by"] == "alice@example.com"
    assert body["approved_at"] is not None


@pytest.mark.asyncio
async def test_stepup_deny(test_client):
    """Deny a pending step-up request."""
    create = test_client.post("/stepup", json={
        "agent_id": "agnt_test",
        "action": "transfer_funds",
        "scope": "bank:write",
    })
    request_id = create.json()["id"]

    resp = test_client.post(f"/stepup/{request_id}/deny", json={})
    assert resp.status_code == 200
    assert resp.json()["status"] == "denied"


@pytest.mark.asyncio
async def test_stepup_double_approve_fails(test_client):
    """Cannot approve an already-approved request."""
    create = test_client.post("/stepup", json={
        "agent_id": "agnt_test",
        "action": "action",
        "scope": "scope",
    })
    request_id = create.json()["id"]

    test_client.post(f"/stepup/{request_id}/approve", json={"approved_by": "alice"})

    resp = test_client.post(f"/stepup/{request_id}/approve", json={"approved_by": "bob"})
    assert resp.status_code == 400


@pytest.mark.asyncio
async def test_stepup_not_found(test_client):
    """Getting a nonexistent step-up request returns 400."""
    resp = test_client.get("/stepup/nonexistent_id")
    assert resp.status_code == 400
