"""Tests for external OIDC id_token exchange (§4.7).

Covers:
- ExternalIDTokenVerifier: trusted/untrusted issuer, expired, wrong aud, happy path
- TokenService._handle_token_exchange with subject_token_type=id_token
- Integration via /token endpoint with subject_token_type form param
- Human root delegation chain propagation
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from authgent_server.config import Settings
from authgent_server.errors import InvalidGrant, InvalidRequest
from authgent_server.services.external_oidc import (
    ACCESS_TOKEN_TYPE,
    ID_TOKEN_TYPE,
    ExternalIDTokenVerifier,
    _IssuerJWKSCache,
)

# ---------------------------------------------------------------------------
# Fixtures: key pairs + helper to mint fake id_tokens
# ---------------------------------------------------------------------------


@pytest.fixture
def rsa_keypair():
    """Generate RSA key pair for simulating Auth0/Clerk JWKS."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return {"private": private_key, "public": private_key.public_key()}


@pytest.fixture
def ec_keypair():
    """Generate EC P-256 key pair for simulating ES256 id_tokens."""
    private_key = ec.generate_private_key(ec.SECP256R1())
    return {"private": private_key, "public": private_key.public_key()}


def _build_jwks_response(public_key: Any, kid: str, alg: str = "RS256") -> dict:
    """Build a JWKS JSON response from a public key."""
    if alg == "RS256":
        jwk = jwt.algorithms.RSAAlgorithm.to_jwk(public_key, as_dict=True)
    else:
        jwk = jwt.algorithms.ECAlgorithm.to_jwk(public_key, as_dict=True)
    jwk["kid"] = kid
    jwk["alg"] = alg
    jwk["use"] = "sig"
    return {"keys": [jwk]}


def _mint_id_token(
    private_key: Any,
    kid: str = "test-kid-1",
    alg: str = "RS256",
    issuer: str = "https://dev-test.us.auth0.com/",
    audience: str = "my-app-client-id",
    subject: str = "auth0|user123",
    email: str = "alice@example.com",
    name: str = "Alice",
    expires_delta: timedelta = timedelta(hours=1),
    extra_claims: dict | None = None,
) -> str:
    """Mint a fake id_token for testing."""
    now = datetime.now(UTC)
    claims: dict[str, Any] = {
        "iss": issuer,
        "sub": subject,
        "aud": audience,
        "exp": int((now + expires_delta).timestamp()),
        "iat": int(now.timestamp()),
        "email": email,
        "name": name,
    }
    if extra_claims:
        claims.update(extra_claims)
    return jwt.encode(claims, private_key, algorithm=alg, headers={"kid": kid})


def _settings_with_issuers(
    issuers: list[str] | None = None,
    audience: str | None = None,
) -> Settings:
    """Create a Settings instance with trusted OIDC config."""
    return Settings(
        secret_key="test-secret-key-for-unit-tests-only-64chars-long-padding-here!!",
        database_url="sqlite+aiosqlite:///:memory:",
        server_url="http://localhost:8000",
        trusted_oidc_issuers=issuers or [],
        trusted_oidc_audience=audience,
    )


# ===========================================================================
# Unit tests: ExternalIDTokenVerifier
# ===========================================================================


class TestExternalIDTokenVerifier:
    """Unit tests for ExternalIDTokenVerifier."""

    def test_is_configured_false_when_empty(self):
        settings = _settings_with_issuers(issuers=[])
        verifier = ExternalIDTokenVerifier(settings)
        assert verifier.is_configured is False

    def test_is_configured_true_when_set(self):
        settings = _settings_with_issuers(issuers=["https://auth0.example.com/"])
        verifier = ExternalIDTokenVerifier(settings)
        assert verifier.is_configured is True

    @pytest.mark.asyncio
    async def test_verify_rejects_when_not_configured(self):
        settings = _settings_with_issuers(issuers=[])
        verifier = ExternalIDTokenVerifier(settings)
        with pytest.raises(InvalidRequest, match="not configured"):
            await verifier.verify_id_token("some.jwt.token")

    @pytest.mark.asyncio
    async def test_verify_rejects_malformed_jwt(self):
        settings = _settings_with_issuers(issuers=["https://auth0.example.com/"])
        verifier = ExternalIDTokenVerifier(settings)
        with pytest.raises(InvalidGrant, match="Malformed id_token"):
            await verifier.verify_id_token("not-a-jwt")

    @pytest.mark.asyncio
    async def test_verify_rejects_untrusted_issuer(self, rsa_keypair):
        settings = _settings_with_issuers(
            issuers=["https://trusted.auth0.com/"],
        )
        verifier = ExternalIDTokenVerifier(settings)

        token = _mint_id_token(
            rsa_keypair["private"],
            issuer="https://evil.attacker.com/",
        )
        with pytest.raises(InvalidGrant, match="Untrusted issuer"):
            await verifier.verify_id_token(token)

    @pytest.mark.asyncio
    async def test_verify_rejects_missing_kid(self, rsa_keypair):
        settings = _settings_with_issuers(
            issuers=["https://dev-test.us.auth0.com/"],
        )
        verifier = ExternalIDTokenVerifier(settings)

        # Mint a token with no kid in header
        now = datetime.now(UTC)
        token = jwt.encode(
            {
                "iss": "https://dev-test.us.auth0.com/",
                "sub": "user123",
                "aud": "app",
                "exp": int((now + timedelta(hours=1)).timestamp()),
                "iat": int(now.timestamp()),
            },
            rsa_keypair["private"],
            algorithm="RS256",
            # no kid in headers
        )
        with pytest.raises(InvalidGrant, match="missing 'kid'"):
            await verifier.verify_id_token(token)

    @pytest.mark.asyncio
    async def test_verify_happy_path_rs256(self, rsa_keypair):
        """Full happy path: RS256 id_token from trusted issuer → normalized claims."""
        issuer = "https://dev-test.us.auth0.com/"
        audience = "my-app-client-id"
        kid = "auth0-key-1"

        settings = _settings_with_issuers(
            issuers=[issuer],
            audience=audience,
        )
        verifier = ExternalIDTokenVerifier(settings)

        token = _mint_id_token(
            rsa_keypair["private"],
            kid=kid,
            issuer=issuer,
            audience=audience,
            subject="auth0|alice",
            email="alice@example.com",
            name="Alice",
        )

        jwks_response = _build_jwks_response(rsa_keypair["public"], kid, "RS256")

        with patch("authgent_server.services.external_oidc.httpx.AsyncClient") as mock_client_cls:
            mock_response = MagicMock()
            mock_response.json.return_value = jwks_response
            mock_response.raise_for_status = MagicMock()

            mock_client = AsyncMock()
            mock_client.get = AsyncMock(return_value=mock_response)
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=None)
            mock_client_cls.return_value = mock_client

            result = await verifier.verify_id_token(token)

        assert result["sub"] == "user:auth0|alice"
        assert result["idp_iss"] == issuer
        assert result["idp_sub"] == "auth0|alice"
        assert result["email"] == "alice@example.com"
        assert result["name"] == "Alice"
        assert result["human_root"] is True

    @pytest.mark.asyncio
    async def test_verify_happy_path_es256(self, ec_keypair):
        """ES256 id_token from trusted issuer (e.g. Clerk)."""
        issuer = "https://clerk.example.com"
        kid = "clerk-key-1"

        settings = _settings_with_issuers(issuers=[issuer])
        verifier = ExternalIDTokenVerifier(settings)

        token = _mint_id_token(
            ec_keypair["private"],
            kid=kid,
            alg="ES256",
            issuer=issuer,
            subject="clerk_user_abc",
        )

        jwks_response = _build_jwks_response(ec_keypair["public"], kid, "ES256")

        with patch("authgent_server.services.external_oidc.httpx.AsyncClient") as mock_client_cls:
            mock_response = MagicMock()
            mock_response.json.return_value = jwks_response
            mock_response.raise_for_status = MagicMock()

            mock_client = AsyncMock()
            mock_client.get = AsyncMock(return_value=mock_response)
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=None)
            mock_client_cls.return_value = mock_client

            result = await verifier.verify_id_token(token)

        assert result["sub"] == "user:clerk_user_abc"
        assert result["human_root"] is True

    @pytest.mark.asyncio
    async def test_verify_rejects_expired_token(self, rsa_keypair):
        """Expired id_tokens must be rejected."""
        issuer = "https://dev-test.us.auth0.com/"
        kid = "auth0-key-1"

        settings = _settings_with_issuers(issuers=[issuer])
        verifier = ExternalIDTokenVerifier(settings)

        token = _mint_id_token(
            rsa_keypair["private"],
            kid=kid,
            issuer=issuer,
            expires_delta=timedelta(hours=-1),  # already expired
        )

        jwks_response = _build_jwks_response(rsa_keypair["public"], kid, "RS256")

        with patch("authgent_server.services.external_oidc.httpx.AsyncClient") as mock_client_cls:
            mock_response = MagicMock()
            mock_response.json.return_value = jwks_response
            mock_response.raise_for_status = MagicMock()

            mock_client = AsyncMock()
            mock_client.get = AsyncMock(return_value=mock_response)
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=None)
            mock_client_cls.return_value = mock_client

            with pytest.raises(InvalidGrant, match="expired"):
                await verifier.verify_id_token(token)

    @pytest.mark.asyncio
    async def test_verify_rejects_wrong_audience(self, rsa_keypair):
        """id_token with wrong audience must be rejected."""
        issuer = "https://dev-test.us.auth0.com/"
        kid = "auth0-key-1"

        settings = _settings_with_issuers(
            issuers=[issuer],
            audience="expected-client-id",
        )
        verifier = ExternalIDTokenVerifier(settings)

        token = _mint_id_token(
            rsa_keypair["private"],
            kid=kid,
            issuer=issuer,
            audience="wrong-client-id",
        )

        jwks_response = _build_jwks_response(rsa_keypair["public"], kid, "RS256")

        with patch("authgent_server.services.external_oidc.httpx.AsyncClient") as mock_client_cls:
            mock_response = MagicMock()
            mock_response.json.return_value = jwks_response
            mock_response.raise_for_status = MagicMock()

            mock_client = AsyncMock()
            mock_client.get = AsyncMock(return_value=mock_response)
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=None)
            mock_client_cls.return_value = mock_client

            with pytest.raises(InvalidGrant, match="audience mismatch"):
                await verifier.verify_id_token(token)

    @pytest.mark.asyncio
    async def test_verify_skips_audience_when_not_configured(self, rsa_keypair):
        """If trusted_oidc_audience is None, aud check is skipped."""
        issuer = "https://dev-test.us.auth0.com/"
        kid = "auth0-key-1"

        settings = _settings_with_issuers(
            issuers=[issuer],
            audience=None,  # no audience configured
        )
        verifier = ExternalIDTokenVerifier(settings)

        token = _mint_id_token(
            rsa_keypair["private"],
            kid=kid,
            issuer=issuer,
            audience="any-audience-is-fine",
        )

        jwks_response = _build_jwks_response(rsa_keypair["public"], kid, "RS256")

        with patch("authgent_server.services.external_oidc.httpx.AsyncClient") as mock_client_cls:
            mock_response = MagicMock()
            mock_response.json.return_value = jwks_response
            mock_response.raise_for_status = MagicMock()

            mock_client = AsyncMock()
            mock_client.get = AsyncMock(return_value=mock_response)
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=None)
            mock_client_cls.return_value = mock_client

            result = await verifier.verify_id_token(token)
            assert result["sub"] == "user:auth0|user123"

    @pytest.mark.asyncio
    async def test_verify_trailing_slash_normalization(self, rsa_keypair):
        """Issuer URLs with/without trailing slash should match."""
        settings = _settings_with_issuers(
            issuers=["https://dev-test.us.auth0.com"],  # no trailing slash
        )
        verifier = ExternalIDTokenVerifier(settings)

        # The issuer in the JWT has trailing slash, allowlist doesn't.
        # _is_trusted_issuer normalizes both, so this should work.
        assert verifier._is_trusted_issuer("https://dev-test.us.auth0.com/") is True
        assert verifier._is_trusted_issuer("https://dev-test.us.auth0.com") is True

    @pytest.mark.asyncio
    async def test_verify_rejects_wrong_signature(self, rsa_keypair):
        """Token signed with a different key must be rejected."""
        issuer = "https://dev-test.us.auth0.com/"
        kid = "auth0-key-1"

        settings = _settings_with_issuers(issuers=[issuer])
        verifier = ExternalIDTokenVerifier(settings)

        # Sign with one key
        token = _mint_id_token(
            rsa_keypair["private"],
            kid=kid,
            issuer=issuer,
        )

        # But JWKS returns a different key
        different_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        jwks_response = _build_jwks_response(different_key.public_key(), kid, "RS256")

        with patch("authgent_server.services.external_oidc.httpx.AsyncClient") as mock_client_cls:
            mock_response = MagicMock()
            mock_response.json.return_value = jwks_response
            mock_response.raise_for_status = MagicMock()

            mock_client = AsyncMock()
            mock_client.get = AsyncMock(return_value=mock_response)
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=None)
            mock_client_cls.return_value = mock_client

            with pytest.raises(InvalidGrant, match="verification failed"):
                await verifier.verify_id_token(token)


# ===========================================================================
# Unit tests: _IssuerJWKSCache
# ===========================================================================


class TestIssuerJWKSCache:
    """Tests for JWKS caching behavior."""

    @pytest.mark.asyncio
    async def test_cache_reuses_keys(self, rsa_keypair):
        """Keys are fetched once and cached on subsequent calls."""
        kid = "cached-key-1"
        jwks_response = _build_jwks_response(rsa_keypair["public"], kid, "RS256")

        cache = _IssuerJWKSCache("https://auth0.example.com", cache_ttl=300)

        with patch("authgent_server.services.external_oidc.httpx.AsyncClient") as mock_client_cls:
            mock_response = MagicMock()
            mock_response.json.return_value = jwks_response
            mock_response.raise_for_status = MagicMock()

            mock_client = AsyncMock()
            mock_client.get = AsyncMock(return_value=mock_response)
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=None)
            mock_client_cls.return_value = mock_client

            # First call fetches
            key1 = await cache.get_key(kid)
            assert key1 is not None

            # Second call uses cache (no new HTTP call)
            key2 = await cache.get_key(kid)
            assert key2 == key1

            # httpx.AsyncClient() should have been instantiated once
            assert mock_client_cls.call_count == 1

    @pytest.mark.asyncio
    async def test_cache_unknown_kid_triggers_refetch(self, rsa_keypair):
        """Unknown kid triggers a forced re-fetch (key rotation scenario)."""
        kid1 = "old-key"
        kid2 = "new-key-after-rotation"

        _build_jwks_response(rsa_keypair["public"], kid1, "RS256")  # old key (not used)
        jwks_rotated = _build_jwks_response(rsa_keypair["public"], kid2, "RS256")

        cache = _IssuerJWKSCache("https://auth0.example.com", cache_ttl=300)

        call_count = 0

        async def mock_get(*args: Any, **kwargs: Any) -> MagicMock:
            nonlocal call_count
            call_count += 1
            resp = MagicMock()
            resp.raise_for_status = MagicMock()
            # Return rotated JWKS on all calls (simulating rotation happened)
            resp.json.return_value = jwks_rotated
            return resp

        with patch("authgent_server.services.external_oidc.httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.get = mock_get
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=None)
            mock_client_cls.return_value = mock_client

            # Request kid2 which isn't in cache → fetches, finds kid2
            key = await cache.get_key(kid2)
            assert key is not None

    @pytest.mark.asyncio
    async def test_cache_raises_on_unknown_kid_after_refetch(self, rsa_keypair):
        """If kid is still unknown after forced re-fetch, raise InvalidGrant."""
        kid = "known-key"
        unknown_kid = "totally-unknown"

        jwks_response = _build_jwks_response(rsa_keypair["public"], kid, "RS256")
        cache = _IssuerJWKSCache("https://auth0.example.com", cache_ttl=300)

        with patch("authgent_server.services.external_oidc.httpx.AsyncClient") as mock_client_cls:
            mock_response = MagicMock()
            mock_response.json.return_value = jwks_response
            mock_response.raise_for_status = MagicMock()

            mock_client = AsyncMock()
            mock_client.get = AsyncMock(return_value=mock_response)
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=None)
            mock_client_cls.return_value = mock_client

            with pytest.raises(InvalidGrant, match="Unknown signing key"):
                await cache.get_key(unknown_kid)


# ===========================================================================
# Unit tests: TokenService._verify_external_id_token
# ===========================================================================


class TestTokenServiceExternalIdToken:
    """Tests for token exchange with subject_token_type=id_token."""

    @pytest.mark.asyncio
    async def test_verify_external_raises_when_no_verifier(self):
        """If external_oidc is None, raise InvalidRequest."""
        from authgent_server.services.audit_service import AuditService
        from authgent_server.services.delegation_service import DelegationService
        from authgent_server.services.jwks_service import JWKSService
        from authgent_server.services.token_service import TokenService

        settings = _settings_with_issuers()
        ts = TokenService(
            settings=settings,
            jwks=MagicMock(spec=JWKSService),
            delegation=DelegationService(settings),
            audit=MagicMock(spec=AuditService),
            external_oidc=None,
        )
        with pytest.raises(InvalidRequest, match="not configured"):
            await ts._verify_external_id_token("some.jwt")

    @pytest.mark.asyncio
    async def test_verify_external_returns_normalized_claims(self):
        """Successful verification returns parent_claims for delegation."""
        from authgent_server.services.audit_service import AuditService
        from authgent_server.services.delegation_service import DelegationService
        from authgent_server.services.jwks_service import JWKSService
        from authgent_server.services.token_service import TokenService

        settings = _settings_with_issuers(
            issuers=["https://auth0.example.com/"],
        )
        mock_verifier = AsyncMock(spec=ExternalIDTokenVerifier)
        mock_verifier.verify_id_token.return_value = {
            "sub": "user:auth0|bob",
            "idp_iss": "https://auth0.example.com/",
            "idp_sub": "auth0|bob",
            "email": "bob@example.com",
            "name": "Bob",
            "human_root": True,
        }

        ts = TokenService(
            settings=settings,
            jwks=MagicMock(spec=JWKSService),
            delegation=DelegationService(settings),
            audit=MagicMock(spec=AuditService),
            external_oidc=mock_verifier,
        )

        result = await ts._verify_external_id_token("fake.jwt.token")
        assert result["sub"] == "user:auth0|bob"
        assert result["human_root"] is True
        assert result["scope"] == ""
        assert result["idp_iss"] == "https://auth0.example.com/"

    @pytest.mark.asyncio
    async def test_unsupported_subject_token_type_rejected(self, db_session):
        """Unknown subject_token_type should raise InvalidRequest."""
        from authgent_server.services.audit_service import AuditService
        from authgent_server.services.delegation_service import DelegationService
        from authgent_server.services.jwks_service import JWKSService
        from authgent_server.services.token_service import TokenService

        settings = _settings_with_issuers()
        ts = TokenService(
            settings=settings,
            jwks=JWKSService(settings),
            delegation=DelegationService(settings),
            audit=MagicMock(spec=AuditService),
        )

        with pytest.raises(InvalidRequest, match="Unsupported subject_token_type"):
            await ts.issue_token(
                db=db_session,
                grant_type="urn:ietf:params:oauth:grant-type:token-exchange",
                client_id="test-client",
                subject_token="some.jwt",
                subject_token_type="urn:ietf:params:oauth:token-type:saml2",
                audience="agent:target",
            )


# ===========================================================================
# Integration tests: /token endpoint with subject_token_type
# ===========================================================================


class TestTokenEndpointSubjectTokenType:
    """Integration tests via FastAPI TestClient."""

    def test_token_exchange_passes_subject_token_type(self, test_client):
        """Verify subject_token_type is extracted from form and reaches service."""
        # Register a client first
        reg_resp = test_client.post(
            "/register",
            json={
                "client_name": "test-exchange-client",
                "grant_types": [
                    "client_credentials",
                    "urn:ietf:params:oauth:grant-type:token-exchange",
                ],
                "scope": "tools:execute",
            },
        )
        assert reg_resp.status_code == 201
        client_data = reg_resp.json()
        client_id = client_data["client_id"]
        client_secret = client_data["client_secret"]

        # Try token exchange with unsupported subject_token_type
        # This tests that the form param is properly extracted and passed through
        resp = test_client.post(
            "/token",
            data={
                "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
                "client_id": client_id,
                "client_secret": client_secret,
                "subject_token": "fake.jwt.here",
                "subject_token_type": "urn:ietf:params:oauth:token-type:saml2",
                "audience": "agent:some-target",
            },
        )
        # Should get InvalidRequest for unsupported type, not a generic error
        assert resp.status_code == 400
        body = resp.json()
        assert (
            "unsupported" in body.get("detail", "").lower()
            or "unsupported" in body.get("error_description", "").lower()
        )

    def test_token_exchange_id_token_not_configured(self, test_client):
        """id_token exchange without trusted issuers configured → clear error."""
        reg_resp = test_client.post(
            "/register",
            json={
                "client_name": "test-idtoken-client",
                "grant_types": [
                    "client_credentials",
                    "urn:ietf:params:oauth:grant-type:token-exchange",
                ],
                "scope": "tools:execute",
            },
        )
        assert reg_resp.status_code == 201
        client_data = reg_resp.json()

        resp = test_client.post(
            "/token",
            data={
                "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
                "client_id": client_data["client_id"],
                "client_secret": client_data["client_secret"],
                "subject_token": "fake.jwt.token",
                "subject_token_type": ID_TOKEN_TYPE,
                "audience": "agent:orchestrator",
            },
        )
        assert resp.status_code == 400
        body = resp.json()
        assert (
            "not configured" in body.get("detail", "").lower()
            or "not configured" in body.get("error_description", "").lower()
        )

    def test_token_exchange_default_type_is_access_token(self, test_client):
        """When subject_token_type is omitted, defaults to access_token."""
        reg_resp = test_client.post(
            "/register",
            json={
                "client_name": "test-default-type-client",
                "grant_types": [
                    "client_credentials",
                    "urn:ietf:params:oauth:grant-type:token-exchange",
                ],
                "scope": "tools:execute",
            },
        )
        assert reg_resp.status_code == 201
        client_data = reg_resp.json()

        # Get a real access token first
        creds_resp = test_client.post(
            "/token",
            data={
                "grant_type": "client_credentials",
                "client_id": client_data["client_id"],
                "client_secret": client_data["client_secret"],
                "scope": "tools:execute",
            },
        )
        assert creds_resp.status_code == 200
        access_token = creds_resp.json()["access_token"]

        # Exchange without specifying subject_token_type (should default to access_token)
        exchange_resp = test_client.post(
            "/token",
            data={
                "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
                "client_id": client_data["client_id"],
                "client_secret": client_data["client_secret"],
                "subject_token": access_token,
                # No subject_token_type → default
                "audience": "agent:downstream",
                "scope": "tools:execute",
            },
        )
        assert exchange_resp.status_code == 200
        body = exchange_resp.json()
        assert "access_token" in body


# ===========================================================================
# Constants tests
# ===========================================================================


class TestConstants:
    def test_token_type_uris(self):
        assert ID_TOKEN_TYPE == "urn:ietf:params:oauth:token-type:id_token"
        assert ACCESS_TOKEN_TYPE == "urn:ietf:params:oauth:token-type:access_token"
