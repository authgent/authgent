"""DPoP proof verification and client-side proof generation."""

from __future__ import annotations

import base64
import hashlib
import json
import time

import jwt
from cryptography.hazmat.primitives.asymmetric import ec

from authgent.errors import DPoPError

MAX_CLOCK_SKEW = 60


def verify_dpop_proof(
    token: object,
    dpop_proof: str,
    http_method: str,
    http_uri: str,
) -> dict:
    """Verify a DPoP proof JWT against an access token.

    Args:
        token: AgentIdentity or claims dict with cnf.jkt.
        dpop_proof: The DPoP proof JWT string.
        http_method: Expected HTTP method (e.g., 'POST').
        http_uri: Expected request URI.

    Returns:
        Decoded proof payload with 'jkt' added.

    Raises:
        DPoPError: If verification fails.
    """
    # Get expected JKT from token
    if hasattr(token, "claims"):
        claims = token.claims.raw  # type: ignore[union-attr]
    elif isinstance(token, dict):
        claims = token
    else:
        raise DPoPError("token must be AgentIdentity or dict")

    cnf = claims.get("cnf", {})
    expected_jkt = cnf.get("jkt") if isinstance(cnf, dict) else None

    if not expected_jkt:
        raise DPoPError("Token does not contain cnf.jkt — not DPoP-bound")

    try:
        unverified_header = jwt.get_unverified_header(dpop_proof)
    except jwt.DecodeError as e:
        raise DPoPError(f"Invalid DPoP proof JWT: {e}")

    if unverified_header.get("typ") != "dpop+jwt":
        raise DPoPError("DPoP proof must have typ=dpop+jwt")

    jwk = unverified_header.get("jwk")
    if not jwk or jwk.get("kty") != "EC":
        raise DPoPError("DPoP proof must contain EC JWK in header")

    # Reconstruct public key
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
        raise DPoPError(f"Invalid JWK in DPoP proof: {e}")

    # Verify signature
    try:
        payload = jwt.decode(
            dpop_proof,
            public_key,
            algorithms=["ES256"],
            options={"verify_aud": False, "verify_iss": False, "verify_sub": False},
        )
    except jwt.InvalidTokenError as e:
        raise DPoPError(f"DPoP proof signature invalid: {e}")

    # Verify htm and htu
    if payload.get("htm", "").upper() != http_method.upper():
        raise DPoPError(f"DPoP htm mismatch: expected {http_method}")
    if payload.get("htu") != http_uri:
        raise DPoPError(f"DPoP htu mismatch: expected {http_uri}")

    # Verify iat
    iat = payload.get("iat")
    if iat is None or abs(time.time() - iat) > MAX_CLOCK_SKEW:
        raise DPoPError("DPoP proof iat too old or missing")

    # Verify JWK thumbprint matches cnf.jkt
    jkt = _compute_jkt(jwk)
    if jkt != expected_jkt:
        raise DPoPError("DPoP JWK thumbprint does not match token cnf.jkt")

    payload["jkt"] = jkt
    return payload


def _compute_jkt(jwk: dict) -> str:
    required = {"crv", "kty", "x", "y"}
    canonical = json.dumps(
        {k: jwk[k] for k in sorted(required) if k in jwk},
        separators=(",", ":"),
        sort_keys=True,
    )
    digest = hashlib.sha256(canonical.encode()).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode()


class DPoPClient:
    """Client-side DPoP proof generator. Creates ephemeral key on init."""

    def __init__(self) -> None:
        self._private_key = ec.generate_private_key(ec.SECP256R1())
        pub = self._private_key.public_key()
        numbers = pub.public_numbers()
        self._jwk = {
            "kty": "EC",
            "crv": "P-256",
            "x": base64.urlsafe_b64encode(
                numbers.x.to_bytes(32, "big")
            ).rstrip(b"=").decode(),
            "y": base64.urlsafe_b64encode(
                numbers.y.to_bytes(32, "big")
            ).rstrip(b"=").decode(),
        }
        self._jkt = _compute_jkt(self._jwk)

    @property
    def jkt(self) -> str:
        """JWK Thumbprint for cnf.jkt binding."""
        return self._jkt

    def create_proof(
        self,
        http_method: str,
        http_uri: str,
        access_token: str | None = None,
        nonce: str | None = None,
    ) -> str:
        """Create a DPoP proof JWT."""
        import secrets

        payload: dict = {
            "jti": secrets.token_urlsafe(16),
            "htm": http_method.upper(),
            "htu": http_uri,
            "iat": int(time.time()),
        }

        if access_token:
            ath = base64.urlsafe_b64encode(
                hashlib.sha256(access_token.encode()).digest()
            ).rstrip(b"=").decode()
            payload["ath"] = ath

        if nonce:
            payload["nonce"] = nonce

        headers = {
            "typ": "dpop+jwt",
            "alg": "ES256",
            "jwk": self._jwk,
        }

        return jwt.encode(payload, self._private_key, algorithm="ES256", headers=headers)

    def create_proof_headers(
        self,
        access_token: str,
        http_method: str,
        http_uri: str,
        nonce: str | None = None,
    ) -> dict[str, str]:
        """Create Authorization + DPoP headers for a request."""
        proof = self.create_proof(http_method, http_uri, access_token, nonce)
        return {
            "Authorization": f"DPoP {access_token}",
            "DPoP": proof,
        }
