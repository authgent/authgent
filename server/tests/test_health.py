"""Tests for health check endpoints."""

from fastapi.testclient import TestClient


def test_health_returns_ok(test_client: TestClient) -> None:
    resp = test_client.get("/health")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


def test_ready_returns_status(test_client: TestClient) -> None:
    resp = test_client.get("/ready")
    # May be 200 or 503 depending on whether signing key was generated
    assert resp.status_code in (200, 503)
    data = resp.json()
    assert "status" in data
    assert "db" in data
