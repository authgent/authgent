"""External OIDC ID Token verifier — validates Auth0/Clerk/Okta JWTs.

Fetches and caches JWKS from trusted external identity providers.
Used by token exchange (§4.7) when subject_token_type=id_token.
"""

from __future__ import annotations

import asyncio
import time
from typing import Any

import httpx
import jwt
import structlog
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from authgent_server.config import Settings
from authgent_server.errors import InvalidGrant, InvalidRequest

logger = structlog.get_logger()

# Standard subject_token_type URIs (RFC 8693 §3)
ID_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:id_token"
ACCESS_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:access_token"


class _IssuerJWKSCache:
    """Per-issuer JWKS cache with TTL and thundering-herd protection."""

    def __init__(self, issuer: str, cache_ttl: int = 300):
        self._issuer = issuer.rstrip("/")
        self._cache_ttl = cache_ttl
        self._keys: dict[str, Any] = {}
        self._last_fetch: float = 0
        self._lock = asyncio.Lock()

    def _is_stale(self) -> bool:
        return (time.monotonic() - self._last_fetch) > self._cache_ttl

    async def get_key(self, kid: str) -> Any:
        """Get a public key by kid. Fetches JWKS if stale or unknown kid."""
        if kid in self._keys and not self._is_stale():
            return self._keys[kid]

        await self._refresh()

        if kid not in self._keys:
            # Key rotation: one forced re-fetch
            await self._refresh(force=True)

        if kid not in self._keys:
            raise InvalidGrant(f"Unknown signing key '{kid}' from issuer {self._issuer}")

        return self._keys[kid]

    async def _refresh(self, force: bool = False) -> None:
        async with self._lock:
            if not force and not self._is_stale():
                return

            jwks_url = f"{self._issuer}/.well-known/jwks.json"
            try:
                async with httpx.AsyncClient(timeout=10.0) as client:
                    resp = await client.get(jwks_url)
                    resp.raise_for_status()
                    jwks = resp.json()
            except httpx.HTTPError as e:
                logger.error("external_jwks_fetch_failed", issuer=self._issuer, error=str(e))
                raise InvalidGrant(f"Failed to fetch JWKS from {self._issuer}: {e}")

            self._keys = {}
            for key_data in jwks.get("keys", []):
                key_kid = key_data.get("kid")
                if key_kid:
                    self._keys[key_kid] = key_data

            self._last_fetch = time.monotonic()
            logger.debug(
                "external_jwks_refreshed",
                issuer=self._issuer,
                key_count=len(self._keys),
            )


def _jwk_to_public_key(jwk_data: dict) -> ec.EllipticCurvePublicKey | rsa.RSAPublicKey:
    """Convert a JWK dict to a cryptography public key object."""
    kty = jwk_data.get("kty")
    if kty == "RSA":
        return jwt.algorithms.RSAAlgorithm.from_jwk(jwk_data)  # type: ignore[return-value]
    elif kty == "EC":
        return jwt.algorithms.ECAlgorithm.from_jwk(jwk_data)  # type: ignore[return-value]
    else:
        raise InvalidGrant(f"Unsupported key type: {kty}")


class ExternalIDTokenVerifier:
    """Verifies id_tokens from trusted external OIDC providers.

    Thread-safe. Caches JWKS per issuer. Validates:
    - Issuer is in the trusted allowlist
    - Signature via IdP's JWKS
    - Standard claims (exp, iat, iss)
    - Audience matches configured trusted_oidc_audience
    """

    def __init__(self, settings: Settings):
        self._settings = settings
        self._issuer_caches: dict[str, _IssuerJWKSCache] = {}

    @property
    def is_configured(self) -> bool:
        """True if at least one trusted issuer is configured."""
        return len(self._settings.trusted_oidc_issuers) > 0

    def _get_cache(self, issuer: str) -> _IssuerJWKSCache:
        """Get or create a JWKS cache for an issuer."""
        issuer = issuer.rstrip("/")
        if issuer not in self._issuer_caches:
            self._issuer_caches[issuer] = _IssuerJWKSCache(issuer)
        return self._issuer_caches[issuer]

    def _normalize_issuer(self, issuer: str) -> str:
        """Normalize issuer URL for comparison (strip trailing slash)."""
        return issuer.rstrip("/")

    def _is_trusted_issuer(self, issuer: str) -> bool:
        """Check if an issuer is in the trusted allowlist."""
        normalized = self._normalize_issuer(issuer)
        return any(
            self._normalize_issuer(trusted) == normalized
            for trusted in self._settings.trusted_oidc_issuers
        )

    async def verify_id_token(self, token: str) -> dict:
        """Verify an external id_token and return normalized claims.

        Returns a claims dict with:
        - sub: "user:{idp_sub}" (namespaced to avoid collision with agent subs)
        - idp_iss: original issuer URL
        - idp_sub: original sub claim
        - email: if present in token
        - name: if present in token
        - human_root: True (always — this is the human root of a delegation chain)

        Raises:
            InvalidRequest: if trusted OIDC is not configured
            InvalidGrant: if token is invalid, untrusted, or expired
        """
        if not self.is_configured:
            raise InvalidRequest(
                "External id_token exchange is not configured. Set AUTHGENT_TRUSTED_OIDC_ISSUERS."
            )

        # 1. Decode header + unverified payload to get iss and kid
        try:
            unverified_header = jwt.get_unverified_header(token)
            unverified_payload = jwt.decode(
                token, options={"verify_signature": False}, algorithms=["RS256", "ES256"]
            )
        except jwt.DecodeError as e:
            raise InvalidGrant(f"Malformed id_token: {e}")

        issuer = unverified_payload.get("iss", "")
        kid = unverified_header.get("kid")

        # 2. Check issuer is trusted
        if not issuer or not self._is_trusted_issuer(issuer):
            raise InvalidGrant(
                f"Untrusted issuer: '{issuer}'. "
                f"Must be one of: {self._settings.trusted_oidc_issuers}"
            )

        if not kid:
            raise InvalidGrant("id_token missing 'kid' header")

        # 3. Fetch the IdP's public key
        cache = self._get_cache(issuer)
        jwk_data = await cache.get_key(kid)
        public_key = _jwk_to_public_key(jwk_data)

        # 4. Determine algorithm from JWK or header
        alg = jwk_data.get("alg") or unverified_header.get("alg", "RS256")
        if alg not in ("RS256", "ES256"):
            raise InvalidGrant(f"Unsupported id_token algorithm: {alg}")

        # 5. Full verification
        decode_options: dict[str, Any] = {"require": ["exp", "iat", "sub"]}
        audience = self._settings.trusted_oidc_audience
        if not audience:
            decode_options["verify_aud"] = False

        try:
            claims = jwt.decode(
                token,
                public_key,
                algorithms=[alg],
                issuer=issuer,
                audience=audience,
                options=decode_options,  # type: ignore[arg-type]
            )
        except jwt.ExpiredSignatureError:
            raise InvalidGrant("id_token has expired")
        except jwt.InvalidIssuerError:
            raise InvalidGrant(f"id_token issuer mismatch (expected {issuer})")
        except jwt.InvalidAudienceError:
            raise InvalidGrant(f"id_token audience mismatch (expected {audience})")
        except jwt.PyJWTError as e:
            raise InvalidGrant(f"id_token verification failed: {e}")

        # 6. Build normalized claims for authgent token issuance
        idp_sub = claims["sub"]
        return {
            "sub": f"user:{idp_sub}",
            "idp_iss": issuer,
            "idp_sub": idp_sub,
            "email": claims.get("email"),
            "name": claims.get("name"),
            "human_root": True,
        }
