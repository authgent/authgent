"""Tests for GET /audit — Audit Log query endpoint."""

from datetime import UTC, datetime

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import AsyncSession

from authgent_server.models.audit_log import AuditLog


@pytest.fixture
def _seed_audit_logs(test_client: TestClient, db_session: AsyncSession) -> None:
    """Seed the audit_log table with test events via direct DB insert."""
    import asyncio

    async def _seed():
        logs = [
            AuditLog(
                action="token.issued",
                actor="client:orchestrator",
                subject="client:orchestrator",
                client_id="agnt_abc123",
                ip_address="127.0.0.1",
                metadata_={"grant_type": "client_credentials", "jti": "tok_111111111111"},
                timestamp=datetime(2026, 3, 28, 10, 0, 0, tzinfo=UTC),
            ),
            AuditLog(
                action="token.exchanged",
                actor="client:orchestrator",
                subject="client:db-reader",
                client_id="agnt_abc123",
                ip_address="127.0.0.1",
                metadata_={
                    "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
                    "audience": "agent:db-reader",
                    "jti": "tok_222222222222",
                },
                timestamp=datetime(2026, 3, 28, 10, 1, 0, tzinfo=UTC),
            ),
            AuditLog(
                action="token.revoked",
                actor="client:orchestrator",
                client_id="agnt_abc123",
                ip_address="127.0.0.1",
                metadata_={"jti": "tok_111111111111"},
                timestamp=datetime(2026, 3, 28, 10, 2, 0, tzinfo=UTC),
            ),
            AuditLog(
                action="token.issued",
                actor="client:search-bot",
                subject="client:search-bot",
                client_id="agnt_def456",
                ip_address="192.168.1.1",
                metadata_={"grant_type": "client_credentials", "jti": "tok_333333333333"},
                timestamp=datetime(2026, 3, 28, 10, 3, 0, tzinfo=UTC),
            ),
        ]
        for log in logs:
            db_session.add(log)
        await db_session.commit()

    asyncio.get_event_loop().run_until_complete(_seed())


def test_audit_list_empty(test_client: TestClient) -> None:
    """GET /audit returns empty list when no events exist."""
    resp = test_client.get("/audit")
    assert resp.status_code == 200
    data = resp.json()
    assert data["items"] == []
    assert data["total"] == 0
    assert data["offset"] == 0
    assert data["limit"] == 50


def test_audit_list_with_events(test_client: TestClient, _seed_audit_logs: None) -> None:
    """GET /audit returns seeded audit events."""
    resp = test_client.get("/audit")
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] == 4
    assert len(data["items"]) == 4
    # Most recent first
    assert data["items"][0]["action"] == "token.issued"
    assert data["items"][0]["client_id"] == "agnt_def456"


def test_audit_filter_by_action(test_client: TestClient, _seed_audit_logs: None) -> None:
    """GET /audit?action=token.revoked filters correctly."""
    resp = test_client.get("/audit", params={"action": "token.revoked"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] == 1
    assert data["items"][0]["action"] == "token.revoked"


def test_audit_filter_by_client_id(test_client: TestClient, _seed_audit_logs: None) -> None:
    """GET /audit?client_id=agnt_def456 filters correctly."""
    resp = test_client.get("/audit", params={"client_id": "agnt_def456"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] == 1
    assert all(item["client_id"] == "agnt_def456" for item in data["items"])


def test_audit_filter_by_actor(test_client: TestClient, _seed_audit_logs: None) -> None:
    """GET /audit?actor=client:orchestrator filters correctly."""
    resp = test_client.get("/audit", params={"actor": "client:orchestrator"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] == 3


def test_audit_pagination(test_client: TestClient, _seed_audit_logs: None) -> None:
    """GET /audit with offset/limit paginates correctly."""
    resp = test_client.get("/audit", params={"limit": 2, "offset": 0})
    assert resp.status_code == 200
    data = resp.json()
    assert len(data["items"]) == 2
    assert data["total"] == 4

    resp2 = test_client.get("/audit", params={"limit": 2, "offset": 2})
    data2 = resp2.json()
    assert len(data2["items"]) == 2
    # Different items
    assert data["items"][0]["id"] != data2["items"][0]["id"]


def test_audit_since_filter(test_client: TestClient, _seed_audit_logs: None) -> None:
    """GET /audit?since=ISO8601 filters by time."""
    resp = test_client.get("/audit", params={"since": "2026-03-28T10:02:00+00:00"})
    assert resp.status_code == 200
    data = resp.json()
    # Should get events at 10:02 and 10:03
    assert data["total"] == 2


def test_audit_metadata_preserved(test_client: TestClient, _seed_audit_logs: None) -> None:
    """Audit metadata is returned in the response."""
    resp = test_client.get("/audit", params={"action": "token.exchanged"})
    assert resp.status_code == 200
    item = resp.json()["items"][0]
    assert item["metadata"] is not None
    assert "audience" in item["metadata"]
    assert item["metadata"]["audience"] == "agent:db-reader"


def test_audit_after_token_issuance(test_client: TestClient) -> None:
    """Issuing a token creates an audit log entry queryable via GET /audit."""
    # Create an agent
    agent_resp = test_client.post(
        "/agents",
        json={"name": "audit-test-agent", "allowed_scopes": ["read"]},
    )
    creds = agent_resp.json()

    # Issue a token
    test_client.post(
        "/token",
        data={
            "grant_type": "client_credentials",
            "client_id": creds["client_id"],
            "client_secret": creds["client_secret"],
            "scope": "read",
        },
    )

    # Check audit log
    resp = test_client.get("/audit", params={"client_id": creds["client_id"]})
    assert resp.status_code == 200
    data = resp.json()
    actions = [item["action"] for item in data["items"]]
    assert "token.issued" in actions


def test_audit_limit_validation(test_client: TestClient) -> None:
    """GET /audit rejects limit > 200."""
    resp = test_client.get("/audit", params={"limit": 300})
    assert resp.status_code == 422


def test_audit_offset_validation(test_client: TestClient) -> None:
    """GET /audit rejects negative offset."""
    resp = test_client.get("/audit", params={"offset": -1})
    assert resp.status_code == 422
