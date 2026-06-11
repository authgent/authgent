"""Chaining Grant Verifier — verifies inbound JWT authorization grants.

Implements the Domain B side of draft-ietf-oauth-identity-chaining-14 §2.4:
verifies a JWT assertion issued by a trusted Domain A authorization server.

Reuses the JWKS caching pattern from external_oidc.py but is tailored to
identity-chaining grants rather than OIDC id_tokens.
"""

from __future__ import annotations

import asyncio
import base64
import time
from typing import Any

import httpx
import jwt
import structlog
from cryptography.hazmat.primitives.asymmetric import ec
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from authgent_server.config import Settings
from authgent_server.errors import InvalidGrant, InvalidRequest
from authgent_server.models.signing_key import SigningKey

logger = structlog.get_logger()


class _ChainingJWKSCache:
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
        if kid in self._keys and not self._is_stale():
            return self._keys[kid]

        await self._refresh()

        if kid not in self._keys:
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
                logger.error("chaining_jwks_fetch_failed", issuer=self._issuer, error=str(e))
                raise InvalidGrant(f"Failed to fetch JWKS from {self._issuer}: {e}")

            self._keys = {}
            for key_data in jwks.get("keys", []):
                key_kid = key_data.get("kid")
                if key_kid:
                    self._keys[key_kid] = key_data

            self._last_fetch = time.monotonic()


class ChainingGrantVerifier:
    """Verifies a JWT authorization grant from a trusted Domain A AS.

    Per draft-ietf-oauth-identity-chaining-14 §2.4 + RFC 7523 §§3, 3.1:
    - iss MUST be in trusted_chaining_issuers
    - aud MUST identify this AS (token endpoint or issuer URL)
    - Signature MUST verify against issuer's JWKS
    - exp, iat MUST be present and valid
    - jti is required for replay prevention (caller checks single-use)
    """

    def __init__(self, settings: Settings):
        self._settings = settings
        self._caches: dict[str, _ChainingJWKSCache] = {}

    @property
    def is_configured(self) -> bool:
        return len(self._settings.trusted_chaining_issuers) > 0

    def _get_cache(self, issuer: str) -> _ChainingJWKSCache:
        normalized = issuer.rstrip("/")
        if normalized not in self._caches:
            self._caches[normalized] = _ChainingJWKSCache(normalized)
        return self._caches[normalized]

    def _is_trusted_issuer(self, issuer: str) -> bool:
        normalized = issuer.rstrip("/")
        return any(t.rstrip("/") == normalized for t in self._settings.trusted_chaining_issuers)

    def _is_self_issuer(self, issuer: str) -> bool:
        """When this server is also the issuer, skip the network and use the
        local SigningKey table — supports same-instance federation tests and
        single-tenant deployments where Domain A and Domain B are co-located.
        """
        return issuer.rstrip("/") == self._settings.server_url.rstrip("/")

    async def _local_key(self, db: AsyncSession, kid: str) -> dict:
        stmt = select(SigningKey).where(
            SigningKey.kid == kid,
            SigningKey.status.in_(["active", "rotated"]),
        )
        result = await db.execute(stmt)
        signing_key = result.scalar_one_or_none()
        if not signing_key:
            raise InvalidGrant(f"Unknown local signing key '{kid}'")
        return dict(signing_key.public_key_jwk)

    async def verify_assertion(self, assertion: str, db: AsyncSession | None = None) -> dict:
        """Verify a JWT authorization grant. Returns the decoded claims.

        Raises:
            InvalidRequest: if no chaining issuers are configured.
            InvalidGrant: for any spec-defined verification failure.
        """
        if not self.is_configured:
            raise InvalidRequest(
                "Identity chaining is not configured. Set AUTHGENT_TRUSTED_CHAINING_ISSUERS."
            )

        try:
            unverified_header = jwt.get_unverified_header(assertion)
            unverified_payload = jwt.decode(
                assertion,
                options={"verify_signature": False},
                algorithms=["RS256", "ES256"],
            )
        except jwt.DecodeError as e:
            raise InvalidGrant(f"Malformed assertion: {e}")

        issuer = unverified_payload.get("iss", "")
        kid = unverified_header.get("kid")

        if not issuer or not self._is_trusted_issuer(issuer):
            raise InvalidGrant(
                f"Untrusted assertion issuer: '{issuer}'. "
                "Add it to AUTHGENT_TRUSTED_CHAINING_ISSUERS to accept."
            )

        if not kid:
            raise InvalidGrant("Assertion missing 'kid' header")

        if self._is_self_issuer(issuer) and db is not None:
            jwk_data = await self._local_key(db, kid)
        else:
            cache = self._get_cache(issuer)
            jwk_data = await cache.get_key(kid)

        kty = jwk_data.get("kty")
        public_key: Any
        if kty == "RSA":
            public_key = jwt.algorithms.RSAAlgorithm.from_jwk(jwk_data)
        elif kty == "EC":
            # Reconstruct an EC public key from raw x/y coordinates so we don't
            # depend on PyJWT's optional JWK helpers being present.
            x = base64.urlsafe_b64decode(jwk_data["x"] + "==")
            y = base64.urlsafe_b64decode(jwk_data["y"] + "==")
            public_key = ec.EllipticCurvePublicNumbers(
                x=int.from_bytes(x, "big"),
                y=int.from_bytes(y, "big"),
                curve=ec.SECP256R1(),
            ).public_key()
        else:
            raise InvalidGrant(f"Unsupported key type: {kty}")

        alg = jwk_data.get("alg") or unverified_header.get("alg", "ES256")
        if alg not in ("RS256", "ES256"):
            raise InvalidGrant(f"Unsupported assertion algorithm: {alg}")

        # §2.4.2: aud MUST identify this AS — token endpoint or issuer URL.
        # Accept either form.
        token_endpoint = f"{self._settings.server_url.rstrip('/')}/token"
        accepted_audiences = [self._settings.server_url.rstrip("/"), token_endpoint]

        try:
            claims: dict[str, Any] = jwt.decode(
                assertion,
                public_key,
                algorithms=[alg],
                audience=accepted_audiences,
                issuer=issuer,
                options={"require": ["exp", "iat", "jti", "sub", "aud", "iss"]},
            )
        except jwt.ExpiredSignatureError:
            raise InvalidGrant("Assertion has expired")
        except jwt.InvalidAudienceError:
            raise InvalidGrant(
                f"Assertion 'aud' must identify this AS ({self._settings.server_url})"
            )
        except jwt.MissingRequiredClaimError as e:
            raise InvalidGrant(f"Assertion missing required claim: {e}")
        except jwt.PyJWTError as e:
            raise InvalidGrant(f"Assertion verification failed: {e}")

        return claims
