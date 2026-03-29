"""Tests for AgentAuthClient — stepup, check_exchange, introspect, refresh methods."""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass

import pytest

from authgent.client import AgentAuthClient, TokenResult


# ── Helpers ──────────────────────────────────────────────────────────────


def _fake_jwt(claims: dict) -> str:
    """Build a fake JWT (header.payload.signature) for testing decode logic."""
    header = base64.urlsafe_b64encode(json.dumps({"alg": "ES256"}).encode()).rstrip(b"=").decode()
    payload = base64.urlsafe_b64encode(json.dumps(claims).encode()).rstrip(b"=").decode()
    return f"{header}.{payload}.fake_signature"


@dataclass
class FakeResponse:
    status_code: int
    text: str
    _json: dict

    def json(self):
        return self._json


class FakeHttpxClient:
    """Captures all post/get calls for assertion, returns preset responses."""

    def __init__(self, response: FakeResponse):
        self._response = response
        self.calls: list[tuple[str, str, dict]] = []  # (method, url, kwargs)

    async def post(self, url, **kwargs):
        self.calls.append(("POST", url, kwargs))
        return self._response

    async def get(self, url, **kwargs):
        self.calls.append(("GET", url, kwargs))
        return self._response

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        pass


def _patch_client(monkeypatch, status: int, body: dict) -> FakeHttpxClient:
    """Monkeypatch httpx.AsyncClient to return a FakeHttpxClient."""
    resp = FakeResponse(status_code=status, text=json.dumps(body), _json=body)
    fake = FakeHttpxClient(resp)

    import httpx

    monkeypatch.setattr(httpx, "AsyncClient", lambda **kw: fake)
    return fake


# ══════════════════════════════════════════════════════════════════════════
# _decode_jwt_claims
# ══════════════════════════════════════════════════════════════════════════


def test_decode_jwt_claims_valid():
    token = _fake_jwt({"sub": "client:agnt_123", "client_id": "agnt_123", "scope": "read"})
    claims = AgentAuthClient._decode_jwt_claims(token)
    assert claims["sub"] == "client:agnt_123"
    assert claims["client_id"] == "agnt_123"
    assert claims["scope"] == "read"


def test_decode_jwt_claims_invalid():
    assert AgentAuthClient._decode_jwt_claims("not-a-jwt") == {}
    assert AgentAuthClient._decode_jwt_claims("") == {}
    assert AgentAuthClient._decode_jwt_claims("a.b") == {}


# ══════════════════════════════════════════════════════════════════════════
# request_stepup — payload correctness
# ══════════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_request_stepup_sends_correct_payload(monkeypatch):
    """request_stepup() must send agent_id, action, scope to POST /stepup."""
    client = AgentAuthClient("http://localhost:8000")
    fake = _patch_client(monkeypatch, 202, {
        "id": "req_abc",
        "agent_id": "agent-1",
        "action": "delete",
        "scope": "admin",
        "status": "pending",
        "expires_at": "2026-01-01T00:00:00",
        "created_at": "2026-01-01T00:00:00",
    })

    result = await client.request_stepup(
        agent_id="agent-1",
        action="delete",
        scope="admin",
        resource="https://api.example.com/records",
    )

    assert result["status"] == "pending"
    assert result["id"] == "req_abc"

    # Verify the payload sent to the server
    assert len(fake.calls) == 1
    method, url, kwargs = fake.calls[0]
    assert method == "POST"
    assert "/stepup" in url
    sent_json = kwargs["json"]
    assert sent_json["agent_id"] == "agent-1"
    assert sent_json["action"] == "delete"
    assert sent_json["scope"] == "admin"
    assert sent_json["resource"] == "https://api.example.com/records"
    # Must NOT contain old broken fields
    assert "token" not in sent_json
    assert "reason" not in sent_json


@pytest.mark.asyncio
async def test_request_stepup_minimal_payload(monkeypatch):
    """request_stepup() with only required fields should not include optionals."""
    client = AgentAuthClient("http://localhost:8000")
    fake = _patch_client(monkeypatch, 202, {"id": "r1", "status": "pending"})

    await client.request_stepup(agent_id="a1", action="act", scope="s1")

    sent_json = fake.calls[0][2]["json"]
    assert "resource" not in sent_json
    assert "delegation_chain" not in sent_json
    assert "metadata" not in sent_json


# ══════════════════════════════════════════════════════════════════════════
# request_stepup_for_token — convenience method
# ══════════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_request_stepup_for_token_extracts_client_id(monkeypatch):
    """request_stepup_for_token() should extract client_id from JWT and use as agent_id."""
    client = AgentAuthClient("http://localhost:8000")
    token = _fake_jwt({"sub": "client:agnt_xyz", "client_id": "agnt_xyz"})
    fake = _patch_client(monkeypatch, 202, {"id": "r2", "status": "pending"})

    await client.request_stepup_for_token(token=token, action="escalate", scope="admin")

    sent_json = fake.calls[0][2]["json"]
    assert sent_json["agent_id"] == "agnt_xyz"
    assert sent_json["action"] == "escalate"
    assert sent_json["scope"] == "admin"


@pytest.mark.asyncio
async def test_request_stepup_for_token_fallback_to_sub(monkeypatch):
    """When client_id is missing, should fall back to sub claim."""
    client = AgentAuthClient("http://localhost:8000")
    token = _fake_jwt({"sub": "client:fallback_id"})
    fake = _patch_client(monkeypatch, 202, {"id": "r3", "status": "pending"})

    await client.request_stepup_for_token(token=token, action="act", scope="read")

    sent_json = fake.calls[0][2]["json"]
    assert sent_json["agent_id"] == "client:fallback_id"


# ══════════════════════════════════════════════════════════════════════════
# check_stepup
# ══════════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_check_stepup(monkeypatch):
    client = AgentAuthClient("http://localhost:8000")
    fake = _patch_client(monkeypatch, 200, {"id": "r1", "status": "approved"})

    result = await client.check_stepup("r1")
    assert result["status"] == "approved"

    method, url, _ = fake.calls[0]
    assert method == "GET"
    assert "/stepup/r1" in url


# ══════════════════════════════════════════════════════════════════════════
# check_exchange
# ══════════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_check_exchange(monkeypatch):
    client = AgentAuthClient("http://localhost:8000")
    fake = _patch_client(monkeypatch, 200, {
        "allowed": True,
        "effective_scopes": ["read"],
        "delegation_depth": 0,
        "max_delegation_depth": 5,
        "reasons": [],
    })

    result = await client.check_exchange(
        subject_token="eyJ...",
        audience="https://target.example.com",
        client_id="agnt_123",
        scope="read",
    )

    assert result["allowed"] is True
    assert result["effective_scopes"] == ["read"]

    sent_json = fake.calls[0][2]["json"]
    assert sent_json["subject_token"] == "eyJ..."
    assert sent_json["audience"] == "https://target.example.com"
    assert sent_json["client_id"] == "agnt_123"


@pytest.mark.asyncio
async def test_check_exchange_denied(monkeypatch):
    client = AgentAuthClient("http://localhost:8000")
    _patch_client(monkeypatch, 200, {
        "allowed": False,
        "effective_scopes": [],
        "delegation_depth": 0,
        "max_delegation_depth": 5,
        "reasons": ["Scope escalation: admin not in parent scopes"],
    })

    result = await client.check_exchange(
        subject_token="eyJ...",
        audience="https://target.example.com",
        client_id="agnt_123",
        scope="admin",
    )

    assert result["allowed"] is False
    assert len(result["reasons"]) == 1
    assert "escalation" in result["reasons"][0].lower()


# ══════════════════════════════════════════════════════════════════════════
# introspect_token
# ══════════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_introspect_token(monkeypatch):
    client = AgentAuthClient("http://localhost:8000")
    _patch_client(monkeypatch, 200, {"active": True, "sub": "client:agnt_1", "scope": "read"})

    result = await client.introspect_token("access_token_here", client_id="c1")
    assert result["active"] is True
    assert result["scope"] == "read"


# ══════════════════════════════════════════════════════════════════════════
# refresh_token
# ══════════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_refresh_token(monkeypatch):
    client = AgentAuthClient("http://localhost:8000")
    _patch_client(monkeypatch, 200, {
        "access_token": "new_token",
        "token_type": "Bearer",
        "expires_in": 3600,
        "scope": "read",
        "refresh_token": "new_rt",
    })

    result = await client.refresh_token("old_rt", client_id="c1", client_secret="s1")
    assert isinstance(result, TokenResult)
    assert result.access_token == "new_token"
    assert result.refresh_token == "new_rt"
