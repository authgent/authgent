"""Tests for RFC-compliant error response headers."""

import pytest


@pytest.mark.asyncio
async def test_401_has_www_authenticate_header(test_client):
    """401 responses must include WWW-Authenticate header (RFC 6750 §3)."""
    resp = test_client.post(
        "/token",
        data={
            "grant_type": "client_credentials",
            "client_id": "nonexistent_client",
            "client_secret": "wrong_secret",
        },
    )
    assert resp.status_code == 401
    assert "WWW-Authenticate" in resp.headers
    assert "Bearer" in resp.headers["WWW-Authenticate"]
    assert "invalid_client" in resp.headers["WWW-Authenticate"]


@pytest.mark.asyncio
async def test_problem_detail_format_on_non_token_endpoint(test_client):
    """Non-token endpoints should return RFC 9457 Problem Details."""
    resp = test_client.get("/agents/nonexistent_id_123")
    assert resp.status_code == 404
    body = resp.json()
    assert "type" in body
    assert "title" in body
    assert "status" in body
    assert "detail" in body


@pytest.mark.asyncio
async def test_oauth_error_format_on_token_endpoint(test_client):
    """Token endpoint should return RFC 6749 §5.2 error format."""
    resp = test_client.post(
        "/token",
        data={
            "grant_type": "unsupported_type",
            "client_id": "nonexistent",
            "client_secret": "wrong",
        },
    )
    # Should be an OAuth error format (either invalid_client or unsupported_grant_type)
    body = resp.json()
    assert "error" in body
    assert "error_description" in body


@pytest.mark.asyncio
async def test_missing_token_param_returns_400(test_client):
    """Missing required parameters should return 400."""
    resp = test_client.post("/token", data={})
    assert resp.status_code == 400
    body = resp.json()
    assert body["error"] == "invalid_request"
