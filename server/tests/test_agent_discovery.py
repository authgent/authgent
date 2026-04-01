"""Integration tests — Foreign Agent Auto-Discovery.

Simulates a foreign agent with ZERO prior configuration performing
the complete bootstrap flow against a running authgent server:

  1. Hit a protected-style endpoint → get 401 with WWW-Authenticate discovery URIs
  2. Fetch /.well-known/oauth-protected-resource → learn authorization_servers
  3. Fetch /.well-known/oauth-authorization-server → learn all endpoints & capabilities
  4. POST /register (RFC 7591) → get client_id + client_secret
  5. POST /token (client_credentials) → get a scoped access_token
  6. Introspect the token → verify claims
  7. Use the token in a delegation exchange → verify chain works
  8. Verify /openapi.json has securitySchemes for automated parsing

Also tests RFC 7591 schema validation:
  - jwks_uri / jwks mutual exclusion
  - jwks_uri HTTPS enforcement
  - jwks structure validation
  - client_uri validation
  - New fields returned in registration response
"""

from __future__ import annotations

import secrets
from urllib.parse import urlparse

from fastapi.testclient import TestClient

# ─── Helpers ──────────────────────────────────────────────────────────


def _register(tc: TestClient, **overrides) -> dict:
    body = {
        "client_name": f"disc-{secrets.token_hex(4)}",
        "grant_types": ["client_credentials"],
        "scope": "read write",
        **overrides,
    }
    resp = tc.post("/register", json=body)
    assert resp.status_code == 201, f"Registration failed: {resp.json()}"
    return resp.json()


def _cc_token(tc: TestClient, creds: dict, scope: str = "read") -> dict:
    resp = tc.post(
        "/token",
        data={
            "grant_type": "client_credentials",
            "client_id": creds["client_id"],
            "client_secret": creds["client_secret"],
            "scope": scope,
        },
    )
    assert resp.status_code == 200, f"Token failed: {resp.json()}"
    return resp.json()


# ═════════════════════════════════════════════════════════════════════
# 1. FULL DISCOVERY FLOW — Zero-config foreign agent bootstrap
# ═════════════════════════════════════════════════════════════════════


class TestForeignAgentDiscoveryFlow:
    """Simulates a foreign agent discovering, registering, and
    authenticating against authgent with zero prior configuration."""

    def test_complete_discovery_register_token_flow(self, test_client: TestClient) -> None:
        """End-to-end: 401 → discover → register → token → introspect."""

        # ── Step 1: Hit token endpoint without auth → get 401 with discovery URIs ──
        resp_401 = test_client.post(
            "/token",
            data={
                "grant_type": "client_credentials",
                "client_id": "nonexistent_foreign_agent",
                "client_secret": "wrong",
            },
        )
        assert resp_401.status_code == 401
        www_auth = resp_401.headers["WWW-Authenticate"]

        # Verify RFC 6750 §3 fields present
        assert 'realm="authgent"' in www_auth
        assert "authorization_uri=" in www_auth
        assert "resource_metadata=" in www_auth
        assert "error=" in www_auth

        # ── Step 2: Parse resource_metadata URI from WWW-Authenticate ──
        resource_meta_uri = None
        for part in www_auth.split(","):
            part = part.strip()
            if part.startswith("resource_metadata="):
                resource_meta_uri = part.split("=", 1)[1].strip('"')
                break
        assert resource_meta_uri is not None, "resource_metadata not found in WWW-Authenticate"

        # Fetch the protected resource metadata (RFC 9728)
        resource_path = urlparse(resource_meta_uri).path
        resp_prm = test_client.get(resource_path)
        assert resp_prm.status_code == 200
        prm = resp_prm.json()
        assert "authorization_servers" in prm
        assert len(prm["authorization_servers"]) > 0

        # ── Step 3: Fetch authorization server metadata (RFC 8414) ──
        auth_server_url = prm["authorization_servers"][0]
        auth_server_path = urlparse(auth_server_url).path or ""
        meta_resp = test_client.get(
            f"{auth_server_path}/.well-known/oauth-authorization-server"
        )
        assert meta_resp.status_code == 200
        meta = meta_resp.json()

        # Verify required metadata fields
        assert "issuer" in meta
        assert "token_endpoint" in meta
        assert "registration_endpoint" in meta
        assert "grant_types_supported" in meta
        assert "client_credentials" in meta["grant_types_supported"]
        assert "code_challenge_methods_supported" in meta
        assert "S256" in meta["code_challenge_methods_supported"]

        # ── Step 4: Dynamically register via RFC 7591 ──
        reg_path = urlparse(meta["registration_endpoint"]).path
        reg_resp = test_client.post(
            reg_path,
            json={
                "client_name": "foreign-discovery-bot",
                "grant_types": ["client_credentials"],
                "scope": "read write",
                "client_uri": "https://foreign-agent.example.com",
                "contacts": ["admin@foreign-agent.example.com"],
            },
        )
        assert reg_resp.status_code == 201
        creds = reg_resp.json()
        assert "client_id" in creds
        assert "client_secret" in creds
        assert creds["client_name"] == "foreign-discovery-bot"
        assert creds["client_uri"] == "https://foreign-agent.example.com"
        assert creds["contacts"] == ["admin@foreign-agent.example.com"]

        # ── Step 5: Request a token ──
        token_path = urlparse(meta["token_endpoint"]).path
        tok_resp = test_client.post(
            token_path,
            data={
                "grant_type": "client_credentials",
                "client_id": creds["client_id"],
                "client_secret": creds["client_secret"],
                "scope": "read",
            },
        )
        assert tok_resp.status_code == 200
        token_data = tok_resp.json()
        assert "access_token" in token_data
        assert token_data["token_type"] in ("Bearer", "bearer")

        # ── Step 6: Introspect the token to verify claims ──
        intro_resp = test_client.post(
            "/introspect",
            data={"token": token_data["access_token"]},
        )
        assert intro_resp.status_code == 200
        intro = intro_resp.json()
        assert intro["active"] is True
        assert intro["client_id"] == creds["client_id"]
        assert "read" in intro["scope"]

    def test_discovery_flow_with_token_exchange(self, test_client: TestClient) -> None:
        """Foreign agent discovers, registers, gets token, then delegates."""

        # Discover
        meta_resp = test_client.get("/.well-known/oauth-authorization-server")
        meta = meta_resp.json()
        assert "urn:ietf:params:oauth:grant-type:token-exchange" in meta["grant_types_supported"]

        # Register parent + child with exchange capability
        parent = _register(test_client, scope="read write search")
        child = _register(
            test_client,
            grant_types=[
                "client_credentials",
                "urn:ietf:params:oauth:grant-type:token-exchange",
            ],
            scope="read search",
        )

        # Parent gets token
        parent_tok = _cc_token(test_client, parent, scope="read write search")

        # Child exchanges parent's token for narrower scope
        exchange_resp = test_client.post(
            "/token",
            data={
                "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
                "client_id": child["client_id"],
                "client_secret": child["client_secret"],
                "subject_token": parent_tok["access_token"],
                "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
                "audience": "https://downstream-service.example.com",
                "scope": "read",
            },
        )
        assert exchange_resp.status_code == 200
        exchanged = exchange_resp.json()
        assert "access_token" in exchanged

        # Verify delegation chain
        intro = test_client.post(
            "/introspect", data={"token": exchanged["access_token"]}
        ).json()
        assert intro["active"] is True
        assert intro["scope"] == "read"
        assert intro["act"] is not None
        assert "sub" in intro["act"]


# ═════════════════════════════════════════════════════════════════════
# 2. WWW-AUTHENTICATE HEADER COMPLIANCE
# ═════════════════════════════════════════════════════════════════════


class TestWWWAuthenticateHeaders:
    """Verify RFC 6750 §3 WWW-Authenticate headers contain discovery URIs."""

    def test_401_includes_realm(self, test_client: TestClient) -> None:
        resp = test_client.post(
            "/token",
            data={
                "grant_type": "client_credentials",
                "client_id": "fake",
                "client_secret": "fake",
            },
        )
        assert resp.status_code == 401
        www_auth = resp.headers["WWW-Authenticate"]
        assert 'realm="authgent"' in www_auth

    def test_401_includes_authorization_uri(self, test_client: TestClient) -> None:
        resp = test_client.post(
            "/token",
            data={
                "grant_type": "client_credentials",
                "client_id": "fake",
                "client_secret": "fake",
            },
        )
        www_auth = resp.headers["WWW-Authenticate"]
        assert "authorization_uri=" in www_auth
        # Extract and verify it's a valid URL
        for part in www_auth.split(","):
            part = part.strip()
            if part.startswith("authorization_uri="):
                uri = part.split("=", 1)[1].strip('"')
                parsed = urlparse(uri)
                assert parsed.scheme in ("http", "https")
                assert "/token" in parsed.path

    def test_401_includes_resource_metadata(self, test_client: TestClient) -> None:
        resp = test_client.post(
            "/token",
            data={
                "grant_type": "client_credentials",
                "client_id": "fake",
                "client_secret": "fake",
            },
        )
        www_auth = resp.headers["WWW-Authenticate"]
        assert "resource_metadata=" in www_auth
        for part in www_auth.split(","):
            part = part.strip()
            if part.startswith("resource_metadata="):
                uri = part.split("=", 1)[1].strip('"')
                assert "/.well-known/oauth-protected-resource" in uri

    def test_401_includes_error_code(self, test_client: TestClient) -> None:
        resp = test_client.post(
            "/token",
            data={
                "grant_type": "client_credentials",
                "client_id": "fake",
                "client_secret": "fake",
            },
        )
        www_auth = resp.headers["WWW-Authenticate"]
        assert 'error="invalid_client"' in www_auth


# ═════════════════════════════════════════════════════════════════════
# 3. OPENAPI SECURITY SCHEMES
# ═════════════════════════════════════════════════════════════════════


class TestOpenAPISecuritySchemes:
    """Verify /openapi.json exposes securitySchemes for automated parsing."""

    def test_openapi_has_security_schemes(self, test_client: TestClient) -> None:
        resp = test_client.get("/openapi.json")
        assert resp.status_code == 200
        spec = resp.json()

        assert "components" in spec
        assert "securitySchemes" in spec["components"]
        schemes = spec["components"]["securitySchemes"]

        assert "OAuth2ClientCredentials" in schemes
        assert "OAuth2AuthorizationCode" in schemes
        assert "BearerToken" in schemes
        assert "DPoP" in schemes

    def test_openapi_client_credentials_flow(self, test_client: TestClient) -> None:
        spec = test_client.get("/openapi.json").json()
        cc = spec["components"]["securitySchemes"]["OAuth2ClientCredentials"]

        assert cc["type"] == "oauth2"
        assert "flows" in cc
        assert "clientCredentials" in cc["flows"]
        assert "tokenUrl" in cc["flows"]["clientCredentials"]
        assert "/token" in cc["flows"]["clientCredentials"]["tokenUrl"]

    def test_openapi_auth_code_flow(self, test_client: TestClient) -> None:
        spec = test_client.get("/openapi.json").json()
        ac = spec["components"]["securitySchemes"]["OAuth2AuthorizationCode"]

        assert ac["type"] == "oauth2"
        assert "authorizationCode" in ac["flows"]
        flow = ac["flows"]["authorizationCode"]
        assert "/authorize" in flow["authorizationUrl"]
        assert "/token" in flow["tokenUrl"]

    def test_openapi_bearer_token_scheme(self, test_client: TestClient) -> None:
        spec = test_client.get("/openapi.json").json()
        bt = spec["components"]["securitySchemes"]["BearerToken"]

        assert bt["type"] == "http"
        assert bt["scheme"] == "bearer"
        assert bt["bearerFormat"] == "JWT"

    def test_openapi_has_server_url(self, test_client: TestClient) -> None:
        spec = test_client.get("/openapi.json").json()
        assert "servers" in spec
        assert len(spec["servers"]) > 0
        assert "url" in spec["servers"][0]

    def test_openapi_has_global_security(self, test_client: TestClient) -> None:
        spec = test_client.get("/openapi.json").json()
        assert "security" in spec
        security_names = [list(s.keys())[0] for s in spec["security"]]
        assert "BearerToken" in security_names

    def test_openapi_description_mentions_discovery(self, test_client: TestClient) -> None:
        spec = test_client.get("/openapi.json").json()
        assert "/.well-known/oauth-authorization-server" in spec["info"]["description"]


# ═════════════════════════════════════════════════════════════════════
# 4. RFC 7591 REGISTRATION — NEW FIELDS & VALIDATION
# ═════════════════════════════════════════════════════════════════════


class TestRFC7591RegistrationFields:
    """Test new RFC 7591 fields: jwks_uri, jwks, client_uri, contacts."""

    def test_register_with_jwks_uri(self, test_client: TestClient) -> None:
        resp = test_client.post(
            "/register",
            json={
                "client_name": "jwks-uri-agent",
                "jwks_uri": "https://agent.example.com/.well-known/jwks.json",
            },
        )
        assert resp.status_code == 201
        data = resp.json()
        assert data["jwks_uri"] == "https://agent.example.com/.well-known/jwks.json"

    def test_register_with_inline_jwks(self, test_client: TestClient) -> None:
        resp = test_client.post(
            "/register",
            json={
                "client_name": "jwks-inline-agent",
                "jwks": {
                    "keys": [
                        {
                            "kty": "EC",
                            "crv": "P-256",
                            "x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
                            "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
                        }
                    ]
                },
            },
        )
        assert resp.status_code == 201
        data = resp.json()
        assert data["jwks"] is not None
        assert "keys" in data["jwks"]

    def test_register_with_client_uri_and_contacts(self, test_client: TestClient) -> None:
        resp = test_client.post(
            "/register",
            json={
                "client_name": "full-metadata-agent",
                "client_uri": "https://my-agent.example.com",
                "contacts": ["admin@example.com", "security@example.com"],
            },
        )
        assert resp.status_code == 201
        data = resp.json()
        assert data["client_uri"] == "https://my-agent.example.com"
        assert data["contacts"] == ["admin@example.com", "security@example.com"]

    def test_register_jwks_uri_and_jwks_mutual_exclusion(self, test_client: TestClient) -> None:
        """RFC 7591 §2: jwks_uri and jwks MUST NOT both be present."""
        resp = test_client.post(
            "/register",
            json={
                "client_name": "bad-both-jwks",
                "jwks_uri": "https://agent.example.com/jwks.json",
                "jwks": {"keys": [{"kty": "EC", "crv": "P-256", "x": "abc", "y": "def"}]},
            },
        )
        assert resp.status_code == 422
        body = resp.json()
        # Pydantic validation error should mention the mutual exclusion
        error_text = str(body)
        assert "jwks_uri" in error_text or "jwks" in error_text

    def test_register_jwks_uri_requires_https(self, test_client: TestClient) -> None:
        resp = test_client.post(
            "/register",
            json={
                "client_name": "bad-http-jwks",
                "jwks_uri": "http://external-server.example.com/jwks.json",
            },
        )
        assert resp.status_code == 422

    def test_register_jwks_uri_allows_localhost_http(self, test_client: TestClient) -> None:
        resp = test_client.post(
            "/register",
            json={
                "client_name": "dev-jwks",
                "jwks_uri": "http://localhost:9000/.well-known/jwks.json",
            },
        )
        assert resp.status_code == 201

    def test_register_jwks_invalid_structure(self, test_client: TestClient) -> None:
        """jwks must have a 'keys' array per RFC 7517 §5."""
        resp = test_client.post(
            "/register",
            json={
                "client_name": "bad-jwks-structure",
                "jwks": {"not_keys": "invalid"},
            },
        )
        assert resp.status_code == 422

    def test_register_client_uri_requires_http_scheme(self, test_client: TestClient) -> None:
        resp = test_client.post(
            "/register",
            json={
                "client_name": "bad-client-uri",
                "client_uri": "ftp://example.com/agent",
            },
        )
        assert resp.status_code == 422

    def test_register_without_new_fields_still_works(self, test_client: TestClient) -> None:
        """Backward compatibility: registration without new fields works."""
        resp = test_client.post(
            "/register",
            json={
                "client_name": "minimal-agent",
                "grant_types": ["client_credentials"],
                "scope": "read",
            },
        )
        assert resp.status_code == 201
        data = resp.json()
        assert data["jwks_uri"] is None
        assert data["jwks"] is None
        assert data["client_uri"] is None
        assert data["contacts"] == []


# ═════════════════════════════════════════════════════════════════════
# 5. SERVER METADATA COMPLETENESS
# ═════════════════════════════════════════════════════════════════════


class TestServerMetadataCompleteness:
    """Verify RFC 8414 metadata is complete and consistent."""

    def test_metadata_lists_all_endpoints(self, test_client: TestClient) -> None:
        meta = test_client.get("/.well-known/oauth-authorization-server").json()

        required_endpoints = [
            "authorization_endpoint",
            "token_endpoint",
            "registration_endpoint",
            "revocation_endpoint",
            "introspection_endpoint",
            "jwks_uri",
            "device_authorization_endpoint",
        ]
        for ep in required_endpoints:
            assert ep in meta, f"Missing: {ep}"
            assert meta[ep].startswith("http"), f"{ep} not a valid URL: {meta[ep]}"

    def test_metadata_grant_types_match_reality(self, test_client: TestClient) -> None:
        """Every advertised grant type should actually work."""
        meta = test_client.get("/.well-known/oauth-authorization-server").json()
        expected_grants = {
            "authorization_code",
            "client_credentials",
            "refresh_token",
            "urn:ietf:params:oauth:grant-type:token-exchange",
            "urn:ietf:params:oauth:grant-type:device_code",
        }
        assert set(meta["grant_types_supported"]) == expected_grants

    def test_metadata_does_not_advertise_private_key_jwt(self, test_client: TestClient) -> None:
        """private_key_jwt should NOT be advertised until implemented."""
        meta = test_client.get("/.well-known/oauth-authorization-server").json()
        assert "private_key_jwt" not in meta["token_endpoint_auth_methods_supported"]

    def test_metadata_response_types_code_only(self, test_client: TestClient) -> None:
        """OAuth 2.1: only 'code' response type (no implicit)."""
        meta = test_client.get("/.well-known/oauth-authorization-server").json()
        assert meta["response_types_supported"] == ["code"]

    def test_protected_resource_metadata_points_to_auth_server(
        self, test_client: TestClient
    ) -> None:
        """RFC 9728 PRM links back to the authorization server."""
        prm = test_client.get("/.well-known/oauth-protected-resource").json()
        meta = test_client.get("/.well-known/oauth-authorization-server").json()

        assert meta["issuer"] in prm["authorization_servers"]

    def test_jwks_endpoint_returns_valid_keys(self, test_client: TestClient) -> None:
        """JWKS endpoint returns at least one usable key."""
        # Signing keys are lazily created on first token issuance in tests,
        # so issue a token first to ensure a key exists.
        creds = _register(test_client, scope="read")
        _cc_token(test_client, creds, scope="read")

        jwks = test_client.get("/.well-known/jwks.json").json()
        assert "keys" in jwks
        assert len(jwks["keys"]) > 0
        key = jwks["keys"][0]
        assert "kty" in key
        assert "kid" in key


# ═════════════════════════════════════════════════════════════════════
# 6. CROSS-CUTTING: DISCOVERY → REGISTRATION → USE FULL PIPELINE
# ═════════════════════════════════════════════════════════════════════


class TestDiscoveryToDelegationPipeline:
    """Full pipeline: discover → register 2 agents → token → exchange → introspect."""

    def test_two_foreign_agents_discover_register_delegate(
        self, test_client: TestClient
    ) -> None:
        """Two foreign agents independently discover the server,
        register, get tokens, and perform a delegation exchange."""

        # Both agents discover the server
        meta = test_client.get("/.well-known/oauth-authorization-server").json()
        reg_endpoint = urlparse(meta["registration_endpoint"]).path
        token_endpoint = urlparse(meta["token_endpoint"]).path

        # Agent A registers
        a_resp = test_client.post(
            reg_endpoint,
            json={
                "client_name": "agent-alpha",
                "grant_types": ["client_credentials"],
                "scope": "read write search",
                "client_uri": "https://alpha.agents.io",
            },
        )
        assert a_resp.status_code == 201
        agent_a = a_resp.json()

        # Agent B registers with exchange capability
        b_resp = test_client.post(
            reg_endpoint,
            json={
                "client_name": "agent-beta",
                "grant_types": [
                    "client_credentials",
                    "urn:ietf:params:oauth:grant-type:token-exchange",
                ],
                "scope": "read search",
                "client_uri": "https://beta.agents.io",
                "contacts": ["ops@beta.agents.io"],
            },
        )
        assert b_resp.status_code == 201
        agent_b = b_resp.json()

        # Agent A gets a broad token
        a_tok = test_client.post(
            token_endpoint,
            data={
                "grant_type": "client_credentials",
                "client_id": agent_a["client_id"],
                "client_secret": agent_a["client_secret"],
                "scope": "read write search",
            },
        )
        assert a_tok.status_code == 200
        a_access = a_tok.json()["access_token"]

        # Agent B exchanges Agent A's token for narrower scope
        b_exchange = test_client.post(
            token_endpoint,
            data={
                "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
                "client_id": agent_b["client_id"],
                "client_secret": agent_b["client_secret"],
                "subject_token": a_access,
                "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
                "audience": "https://beta.agents.io",
                "scope": "read",
            },
        )
        assert b_exchange.status_code == 200
        b_access = b_exchange.json()["access_token"]

        # Introspect — verify delegation chain
        intro = test_client.post("/introspect", data={"token": b_access}).json()
        assert intro["active"] is True
        assert intro["scope"] == "read"
        assert intro["act"] is not None
        assert "sub" in intro["act"]

        # Scope escalation blocked
        b_escalate = test_client.post(
            token_endpoint,
            data={
                "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
                "client_id": agent_b["client_id"],
                "client_secret": agent_b["client_secret"],
                "subject_token": b_access,
                "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
                "audience": "https://gamma.agents.io",
                "scope": "read write",
            },
        )
        assert b_escalate.status_code == 403
