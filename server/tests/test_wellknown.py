"""Tests for /.well-known discovery endpoints."""

import secrets

from fastapi.testclient import TestClient


def _register_client(tc: TestClient, scope: str = "read write") -> dict:
    resp = tc.post(
        "/register",
        json={
            "client_name": f"wk-{secrets.token_hex(4)}",
            "grant_types": ["client_credentials"],
            "scope": scope,
        },
    )
    assert resp.status_code == 201
    return resp.json()


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


# ── scopes_supported dynamic aggregation ──


def test_discovery_scopes_populated_from_clients(test_client: TestClient) -> None:
    """Discovery metadata should return scopes aggregated from registered clients."""
    _register_client(test_client, scope="read write admin")

    resp = test_client.get("/.well-known/oauth-authorization-server")
    assert resp.status_code == 200
    data = resp.json()
    scopes = data["scopes_supported"]
    assert "read" in scopes
    assert "write" in scopes
    assert "admin" in scopes


def test_discovery_scopes_in_protected_resource(test_client: TestClient) -> None:
    """RFC 9728 protected resource metadata should also show scopes."""
    _register_client(test_client, scope="search:execute")

    resp = test_client.get("/.well-known/oauth-protected-resource")
    assert resp.status_code == 200
    data = resp.json()
    assert "search:execute" in data["scopes_supported"]


def test_openid_discovery_includes_scopes(test_client: TestClient) -> None:
    """OIDC discovery should include scopes from registered clients."""
    _register_client(test_client, scope="profile email")

    resp = test_client.get("/.well-known/openid-configuration")
    assert resp.status_code == 200
    data = resp.json()
    assert "profile" in data["scopes_supported"]
    assert "email" in data["scopes_supported"]


def test_oauth_server_metadata_path_suffix_sep2351(test_client: TestClient) -> None:
    """MCP SEP-2351 / RFC 8414 §3.1: path-suffixed metadata MUST be served
    and MUST rewrite the `issuer` claim to the path-prefixed URL so issuer
    comparison succeeds at the MCP client."""
    resp = test_client.get("/.well-known/oauth-authorization-server/tenant-a")
    assert resp.status_code == 200
    data = resp.json()
    assert data["issuer"] == "http://localhost:8000/tenant-a"
    # Endpoint URLs remain rooted at the real server.
    assert data["token_endpoint"].startswith("http://localhost:8000/")


def test_protected_resource_metadata_path_suffix_sep2351(test_client: TestClient) -> None:
    """MCP SEP-2351 / RFC 9728: path-suffixed PRM rewrites `resource`."""
    resp = test_client.get("/.well-known/oauth-protected-resource/mcp/finance")
    assert resp.status_code == 200
    data = resp.json()
    assert data["resource"] == "http://localhost:8000/mcp/finance"
    assert data["authorization_servers"] == ["http://localhost:8000"]


def test_oauth_server_metadata_deep_path_suffix(test_client: TestClient) -> None:
    """Multi-segment path suffix (e.g. /tenant-a/v2) is supported."""
    resp = test_client.get("/.well-known/oauth-authorization-server/tenant-a/v2")
    assert resp.status_code == 200
    assert resp.json()["issuer"] == "http://localhost:8000/tenant-a/v2"


def test_security_txt_rfc9116(test_client: TestClient) -> None:
    """RFC 9116: /.well-known/security.txt is text/plain with required
    Contact and Expires fields."""
    resp = test_client.get("/.well-known/security.txt")
    assert resp.status_code == 200
    assert "text/plain" in resp.headers["content-type"]
    body = resp.text
    assert "Contact:" in body
    assert "Expires:" in body
    assert "Policy:" in body
