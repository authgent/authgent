"""JWKS Service — ES256 key generation, rotation, signing, and JWKS document."""

from __future__ import annotations

import base64
import hashlib
import json
from datetime import datetime, timezone

import jwt
import structlog
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from authgent_server.config import Settings
from authgent_server.crypto import decrypt_private_key, encrypt_private_key
from authgent_server.models.signing_key import SigningKey

logger = structlog.get_logger()


def _generate_kid() -> str:
    """Generate a short, URL-safe key ID."""
    import secrets
    return secrets.token_urlsafe(16)


def _ec_key_to_jwk(public_key: ec.EllipticCurvePublicKey, kid: str) -> dict:
    """Convert an EC public key to JWK format."""
    numbers = public_key.public_numbers()
    x = base64.urlsafe_b64encode(
        numbers.x.to_bytes(32, byteorder="big")
    ).rstrip(b"=").decode()
    y = base64.urlsafe_b64encode(
        numbers.y.to_bytes(32, byteorder="big")
    ).rstrip(b"=").decode()
    return {
        "kty": "EC",
        "crv": "P-256",
        "x": x,
        "y": y,
        "kid": kid,
        "use": "sig",
        "alg": "ES256",
    }


def _jwk_thumbprint(jwk: dict) -> str:
    """Compute JWK Thumbprint (RFC 7638) for DPoP binding."""
    required = {"crv", "kty", "x", "y"} if jwk["kty"] == "EC" else {"e", "kty", "n"}
    canonical = json.dumps(
        {k: jwk[k] for k in sorted(required) if k in jwk},
        separators=(",", ":"),
        sort_keys=True,
    )
    digest = hashlib.sha256(canonical.encode()).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode()


class JWKSService:
    def __init__(self, settings: Settings):
        self._settings = settings

    async def get_active_key(self, db: AsyncSession) -> SigningKey:
        """Returns the current active signing key. Auto-generates on first call."""
        stmt = select(SigningKey).where(SigningKey.status == "active")
        result = await db.execute(stmt)
        key = result.scalar_one_or_none()

        if key is None:
            key = await self._generate_key(db)

        return key

    async def _generate_key(self, db: AsyncSession) -> SigningKey:
        """Generate a new ES256 signing key pair."""
        private_key = ec.generate_private_key(ec.SECP256R1())
        kid = _generate_kid()

        # Serialize private key to PEM
        pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode()

        # Encrypt at rest
        encrypted_pem = encrypt_private_key(pem, self._settings._kek_key)

        # Build JWK for public key
        public_jwk = _ec_key_to_jwk(private_key.public_key(), kid)

        signing_key = SigningKey(
            kid=kid,
            algorithm=self._settings.signing_algorithm,
            private_key_pem=encrypted_pem,
            public_key_jwk=public_jwk,
            status="active",
        )
        db.add(signing_key)
        await db.commit()
        await db.refresh(signing_key)

        logger.info("signing_key_generated", kid=kid)
        return signing_key

    async def rotate_key(self, db: AsyncSession) -> SigningKey:
        """Create new key, mark old as rotated."""
        # Mark current active key as rotated
        stmt = select(SigningKey).where(SigningKey.status == "active")
        result = await db.execute(stmt)
        old_key = result.scalar_one_or_none()

        if old_key:
            old_key.status = "rotated"
            old_key.rotated_at = datetime.now(timezone.utc)

        new_key = await self._generate_key(db)
        logger.info("signing_key_rotated", old_kid=old_key.kid if old_key else None, new_kid=new_key.kid)
        return new_key

    async def get_jwks_document(self, db: AsyncSession) -> dict:
        """Returns JWKS JSON with all active + recently-rotated keys."""
        stmt = select(SigningKey).where(SigningKey.status.in_(["active", "rotated"]))
        result = await db.execute(stmt)
        keys = result.scalars().all()
        return {"keys": [k.public_key_jwk for k in keys]}

    async def sign_jwt(self, db: AsyncSession, claims: dict, headers: dict | None = None) -> str:
        """Sign claims with the active key."""
        signing_key = await self.get_active_key(db)

        # Decrypt private key
        pem = decrypt_private_key(signing_key.private_key_pem, self._settings._kek_key)
        private_key = serialization.load_pem_private_key(pem.encode(), password=None)

        hdr = {"kid": signing_key.kid, "alg": "ES256"}
        if headers:
            hdr.update(headers)

        return jwt.encode(claims, private_key, algorithm="ES256", headers=hdr)

    async def verify_jwt(
        self, db: AsyncSession, token: str, audience: str | None = None
    ) -> dict:
        """Verify JWT signature against JWKS. Returns decoded claims.

        Validates: signature, kid, expiry, issuer. Optionally audience.
        Does NOT check blocklist — caller must do that separately.
        """
        try:
            unverified_header = jwt.get_unverified_header(token)
        except jwt.DecodeError as e:
            raise jwt.InvalidTokenError(f"Malformed JWT: {e}")

        kid = unverified_header.get("kid")
        if not kid:
            raise jwt.InvalidTokenError("Token missing kid header")

        alg = unverified_header.get("alg")
        if alg != "ES256":
            raise jwt.InvalidTokenError(f"Unsupported algorithm: {alg}")

        # Fetch key by kid
        stmt = select(SigningKey).where(
            SigningKey.kid == kid,
            SigningKey.status.in_(["active", "rotated"]),
        )
        result = await db.execute(stmt)
        signing_key = result.scalar_one_or_none()

        if not signing_key:
            raise jwt.InvalidTokenError(f"Unknown signing key: {kid}")

        # Load public key from JWK
        jwk_data = signing_key.public_key_jwk
        x = base64.urlsafe_b64decode(jwk_data["x"] + "==")
        y = base64.urlsafe_b64decode(jwk_data["y"] + "==")

        public_numbers = ec.EllipticCurvePublicNumbers(
            x=int.from_bytes(x, "big"),
            y=int.from_bytes(y, "big"),
            curve=ec.SECP256R1(),
        )
        public_key = public_numbers.public_key()

        options: dict = {"require": ["exp", "iat", "jti"]}
        if audience is None:
            options["verify_aud"] = False

        return jwt.decode(
            token,
            public_key,
            algorithms=["ES256"],
            issuer=self._settings.server_url,
            audience=audience,
            options=options,
        )
