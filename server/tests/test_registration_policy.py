"""Tests for registration_policy enforcement on POST /agents and POST /register."""

import os

import pytest
from fastapi.testclient import TestClient


@pytest.fixture(autouse=True)
def _reset_settings():
    """Reset cached settings before each test so env var changes take effect."""
    from authgent_server.config import reset_settings
    from authgent_server.dependencies import reset_providers

    reset_settings()
    reset_providers()
    yield
    reset_settings()
    reset_providers()


# ── policy=open (default) ──


def test_open_policy_allows_register(test_client: TestClient) -> None:
    """Default open policy should allow unauthenticated registration."""
    resp = test_client.post(
        "/register",
        json={"client_name": "open-test", "grant_types": ["client_credentials"], "scope": "read"},
    )
    assert resp.status_code == 201


def test_open_policy_allows_create_agent(test_client: TestClient) -> None:
    resp = test_client.post(
        "/agents",
        json={"name": "open-agent", "allowed_scopes": ["read"]},
    )
    assert resp.status_code == 201


# ── policy=token ──


def test_token_policy_rejects_unauthenticated_register(test_client: TestClient, monkeypatch) -> None:
    monkeypatch.setenv("AUTHGENT_REGISTRATION_POLICY", "token")
    monkeypatch.setenv("AUTHGENT_REGISTRATION_TOKEN", "secret-reg-token-123")
    from authgent_server.config import reset_settings
    reset_settings()

    resp = test_client.post(
        "/register",
        json={"client_name": "no-auth", "grant_types": ["client_credentials"], "scope": "read"},
    )
    assert resp.status_code == 401
    body = resp.json()
    msg = body.get("error_description", body.get("detail", "")).lower()
    assert "registration" in msg or "authentication" in msg


def test_token_policy_rejects_wrong_token(test_client: TestClient, monkeypatch) -> None:
    monkeypatch.setenv("AUTHGENT_REGISTRATION_POLICY", "token")
    monkeypatch.setenv("AUTHGENT_REGISTRATION_TOKEN", "secret-reg-token-123")
    from authgent_server.config import reset_settings
    reset_settings()

    resp = test_client.post(
        "/register",
        json={"client_name": "bad-token", "grant_types": ["client_credentials"], "scope": "read"},
        headers={"Authorization": "Bearer wrong-token"},
    )
    assert resp.status_code == 401
    body = resp.json()
    msg = body.get("error_description", body.get("detail", "")).lower()
    assert "invalid" in msg


def test_token_policy_accepts_correct_token(test_client: TestClient, monkeypatch) -> None:
    monkeypatch.setenv("AUTHGENT_REGISTRATION_POLICY", "token")
    monkeypatch.setenv("AUTHGENT_REGISTRATION_TOKEN", "secret-reg-token-123")
    from authgent_server.config import reset_settings
    reset_settings()

    resp = test_client.post(
        "/register",
        json={"client_name": "good-token", "grant_types": ["client_credentials"], "scope": "read"},
        headers={"Authorization": "Bearer secret-reg-token-123"},
    )
    assert resp.status_code == 201


def test_token_policy_rejects_unauthenticated_agent(test_client: TestClient, monkeypatch) -> None:
    monkeypatch.setenv("AUTHGENT_REGISTRATION_POLICY", "token")
    monkeypatch.setenv("AUTHGENT_REGISTRATION_TOKEN", "secret-reg-token-123")
    from authgent_server.config import reset_settings
    reset_settings()

    resp = test_client.post(
        "/agents",
        json={"name": "no-auth-agent", "allowed_scopes": ["read"]},
    )
    assert resp.status_code == 401


def test_token_policy_accepts_correct_token_for_agent(test_client: TestClient, monkeypatch) -> None:
    monkeypatch.setenv("AUTHGENT_REGISTRATION_POLICY", "token")
    monkeypatch.setenv("AUTHGENT_REGISTRATION_TOKEN", "secret-reg-token-123")
    from authgent_server.config import reset_settings
    reset_settings()

    resp = test_client.post(
        "/agents",
        json={"name": "authed-agent", "allowed_scopes": ["read"]},
        headers={"Authorization": "Bearer secret-reg-token-123"},
    )
    assert resp.status_code == 201


def test_token_policy_misconfigured_no_token_set(test_client: TestClient, monkeypatch) -> None:
    """If policy=token but no REGISTRATION_TOKEN is set, return a clear error."""
    monkeypatch.setenv("AUTHGENT_REGISTRATION_POLICY", "token")
    monkeypatch.delenv("AUTHGENT_REGISTRATION_TOKEN", raising=False)
    from authgent_server.config import reset_settings
    reset_settings()

    resp = test_client.post(
        "/register",
        json={"client_name": "misconfig", "grant_types": ["client_credentials"], "scope": "read"},
        headers={"Authorization": "Bearer anything"},
    )
    assert resp.status_code == 401
    body = resp.json()
    msg = body.get("error_description", body.get("detail", "")).lower()
    assert "misconfigured" in msg
