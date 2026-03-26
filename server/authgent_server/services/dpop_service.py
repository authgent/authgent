"""DPoP service — proof validation with stateless HMAC-based nonces."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time

import jwt
import structlog
from cryptography.hazmat.primitives.asymmetric import ec

from authgent_server.config import Settings
from authgent_server.errors import InvalidDPoPProof, UseDPoPNonce

logger = structlog.get_logger()

BUCKET_DURATION = 300  # 5-minute buckets
GRACE_BUCKETS = 1  # accept current + previous bucket
MAX_CLOCK_SKEW = 60  # seconds


class DPoPService:
    """Stateless DPoP nonce generation and validation.
    Nonce = HMAC-SHA256(server_secret, time_bucket)."""

    def __init__(self, settings: Settings):
        self._dpop_key = settings._dpop_key

    def generate_nonce(self) -> str:
        """Generate nonce for current time bucket."""
        bucket = int(time.time()) // BUCKET_DURATION
        return self._hmac_nonce(bucket)

    def validate_nonce(self, nonce: str) -> bool:
        """Accept nonce from current or previous time bucket."""
        bucket = int(time.time()) // BUCKET_DURATION
        return nonce in {
            self._hmac_nonce(bucket),
            self._hmac_nonce(bucket - GRACE_BUCKETS),
        }

    def _hmac_nonce(self, bucket: int) -> str:
        return hmac.new(self._dpop_key, str(bucket).encode(), "sha256").hexdigest()[:32]

    def verify_dpop_proof(
        self,
        proof_jwt: str,
        access_token: str | None,
        http_method: str,
        http_uri: str,
        expected_jkt: str | None = None,
        require_nonce: bool = False,
    ) -> dict:
        """Full DPoP proof verification per RFC 9449 §4.3.

        Returns the decoded proof payload with added 'jkt' field.
        """
        try:
            unverified_header = jwt.get_unverified_header(proof_jwt)
        except jwt.DecodeError as e:
            raise InvalidDPoPProof(f"Invalid DPoP proof JWT: {e}")

        # 1. Check header
        if unverified_header.get("typ") != "dpop+jwt":
            raise InvalidDPoPProof("DPoP proof must have typ=dpop+jwt")
        if unverified_header.get("alg") != "ES256":
            raise InvalidDPoPProof("DPoP proof must use ES256")

        jwk = unverified_header.get("jwk")
        if not jwk or jwk.get("kty") != "EC":
            raise InvalidDPoPProof("DPoP proof must contain EC JWK in header")

        # 2. Reconstruct public key from JWK
        try:
            x = base64.urlsafe_b64decode(jwk["x"] + "==")
            y = base64.urlsafe_b64decode(jwk["y"] + "==")
            pub_numbers = ec.EllipticCurvePublicNumbers(
                x=int.from_bytes(x, "big"),
                y=int.from_bytes(y, "big"),
                curve=ec.SECP256R1(),
            )
            public_key = pub_numbers.public_key()
        except Exception as e:
            raise InvalidDPoPProof(f"Invalid JWK in DPoP proof: {e}")

        # 3. Verify signature
        try:
            payload = jwt.decode(
                proof_jwt,
                public_key,
                algorithms=["ES256"],
                options={"verify_aud": False, "verify_iss": False, "verify_sub": False},
            )
        except jwt.InvalidTokenError as e:
            raise InvalidDPoPProof(f"DPoP proof signature invalid: {e}")

        # 4. Verify htm and htu
        if payload.get("htm", "").upper() != http_method.upper():
            raise InvalidDPoPProof(
                f"DPoP htm mismatch: expected {http_method}, got {payload.get('htm')}"
            )
        if payload.get("htu") != http_uri:
            raise InvalidDPoPProof(
                f"DPoP htu mismatch: expected {http_uri}, got {payload.get('htu')}"
            )

        # 5. Verify iat is recent
        iat = payload.get("iat")
        if iat is None:
            raise InvalidDPoPProof("DPoP proof missing iat")
        now = time.time()
        if abs(now - iat) > MAX_CLOCK_SKEW:
            raise InvalidDPoPProof("DPoP proof iat too old or in the future")

        # 6. Verify ath (access token hash) if access_token provided
        if access_token:
            expected_ath = (
                base64.urlsafe_b64encode(hashlib.sha256(access_token.encode()).digest())
                .rstrip(b"=")
                .decode()
            )
            if payload.get("ath") != expected_ath:
                raise InvalidDPoPProof("DPoP proof ath mismatch")

        # 7. Compute JWK thumbprint
        jkt = self._compute_jkt(jwk)

        # 8. Verify expected_jkt if provided (cnf.jkt binding)
        if expected_jkt and jkt != expected_jkt:
            raise InvalidDPoPProof(f"DPoP proof JWK thumbprint mismatch: expected {expected_jkt}")

        # 9. Nonce validation
        proof_nonce = payload.get("nonce")
        if require_nonce:
            if not proof_nonce:
                raise UseDPoPNonce(self.generate_nonce())
            if not self.validate_nonce(proof_nonce):
                raise UseDPoPNonce(self.generate_nonce())

        payload["jkt"] = jkt
        return payload

    @staticmethod
    def _compute_jkt(jwk: dict) -> str:
        """Compute JWK Thumbprint (RFC 7638)."""
        required = {"crv", "kty", "x", "y"}
        canonical = json.dumps(
            {k: jwk[k] for k in sorted(required) if k in jwk},
            separators=(",", ":"),
            sort_keys=True,
        )
        digest = hashlib.sha256(canonical.encode()).digest()
        return base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
