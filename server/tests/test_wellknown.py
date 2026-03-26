"""Tests for /.well-known discovery endpoints."""

from fastapi.testclient import TestClient


def test_oauth_server_metadata(test_client: TestClient) -> None:
    resp = test_client.get("/.well-known/oauth-authorization-server")
    assert resp.status_code == 200
    data = resp.json()
    assert data["issuer"] == "http://localhost:8000"
    assert "authorization_endpoint" in data
    assert "token_endpoint" in data
    assert "jwks_uri" in data
    assert "registration_endpoint" in data
    assert "revocation_endpoint" in data
    assert data["resource_indicators_supported"] is True
    assert "S256" in data["code_challenge_methods_supported"]
    assert "client_credentials" in data["grant_types_supported"]
    assert "authorization_code" in data["grant_types_supported"]


def test_openid_configuration(test_client: TestClient) -> None:
    resp = test_client.get("/.well-known/openid-configuration")
    assert resp.status_code == 200
    data = resp.json()
    assert data["issuer"] == "http://localhost:8000"
    assert "userinfo_endpoint" in data
    assert "id_token_signing_alg_values_supported" in data


def test_jwks_endpoint(test_client: TestClient) -> None:
    resp = test_client.get("/.well-known/jwks.json")
    assert resp.status_code == 200
    data = resp.json()
    assert "keys" in data


def test_protected_resource_metadata(test_client: TestClient) -> None:
    resp = test_client.get("/.well-known/oauth-protected-resource")
    assert resp.status_code == 200
    data = resp.json()
    assert "resource" in data
    assert "authorization_servers" in data
