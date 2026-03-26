"""DPoP proof verification tests — server-side (§12.1)."""

from __future__ import annotations

import base64
import hashlib
import json
import secrets
import time

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import ec


def _ec_keypair():
    """Generate an ES256 keypair and return (private_key, jwk_dict)."""
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()
    pub_numbers = public_key.public_numbers()

    x_bytes = pub_numbers.x.to_bytes(32, "big")
    y_bytes = pub_numbers.y.to_bytes(32, "big")

    jwk = {
        "kty": "EC",
        "crv": "P-256",
        "x": base64.urlsafe_b64encode(x_bytes).rstrip(b"=").decode(),
        "y": base64.urlsafe_b64encode(y_bytes).rstrip(b"=").decode(),
    }
    return private_key, jwk


def _make_dpop_proof(
    private_key,
    jwk: dict,
    htm: str = "POST",
    htu: str = "http://localhost:8000/token",
    access_token: str | None = None,
    nonce: str | None = None,
    iat: int | None = None,
    extra_headers: dict | None = None,
) -> str:
    """Create a DPoP proof JWT."""
    headers = {
        "typ": "dpop+jwt",
        "alg": "ES256",
        "jwk": jwk,
    }
    if extra_headers:
        headers.update(extra_headers)

    payload: dict = {
        "htm": htm,
        "htu": htu,
        "iat": iat or int(time.time()),
        "jti": secrets.token_hex(16),
    }
    if access_token:
        ath = (
            base64.urlsafe_b64encode(hashlib.sha256(access_token.encode()).digest())
            .rstrip(b"=")
            .decode()
        )
        payload["ath"] = ath
    if nonce:
        payload["nonce"] = nonce

    return jwt.encode(payload, private_key, algorithm="ES256", headers=headers)


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


# ── Unit tests for DPoPService ──


class TestDPoPServiceUnit:
    """Direct unit tests for DPoPService methods."""

    def _get_service(self):
        from authgent_server.config import get_settings
        from authgent_server.services.dpop_service import DPoPService

        return DPoPService(get_settings())

    def test_nonce_generation_deterministic(self):
        """Same time bucket produces the same nonce."""
        svc = self._get_service()
        n1 = svc.generate_nonce()
        n2 = svc.generate_nonce()
        assert n1 == n2
        assert len(n1) == 32

    def test_nonce_validation_current_bucket(self):
        """A freshly generated nonce should validate."""
        svc = self._get_service()
        nonce = svc.generate_nonce()
        assert svc.validate_nonce(nonce) is True

    def test_nonce_validation_wrong_nonce_fails(self):
        """A random string should not validate as a nonce."""
        svc = self._get_service()
        assert svc.validate_nonce("totally-random-nonce-value") is False

    def test_valid_proof_accepted(self):
        """A correctly constructed DPoP proof should be accepted."""
        svc = self._get_service()
        priv, jwk = _ec_keypair()
        proof = _make_dpop_proof(priv, jwk)

        result = svc.verify_dpop_proof(
            proof_jwt=proof,
            access_token=None,
            http_method="POST",
            http_uri="http://localhost:8000/token",
        )
        assert "jkt" in result
        assert result["htm"] == "POST"
        assert result["htu"] == "http://localhost:8000/token"

    def test_wrong_htm_rejected(self):
        """DPoP proof with wrong HTTP method must be rejected."""
        svc = self._get_service()
        priv, jwk = _ec_keypair()
        proof = _make_dpop_proof(priv, jwk, htm="POST")

        from authgent_server.errors import InvalidDPoPProof

        with pytest.raises(InvalidDPoPProof):
            svc.verify_dpop_proof(
                proof_jwt=proof,
                access_token=None,
                http_method="GET",  # mismatch
                http_uri="http://localhost:8000/token",
            )

    def test_wrong_htu_rejected(self):
        """DPoP proof with wrong URI must be rejected."""
        svc = self._get_service()
        priv, jwk = _ec_keypair()
        proof = _make_dpop_proof(priv, jwk, htu="http://localhost:8000/token")

        from authgent_server.errors import InvalidDPoPProof

        with pytest.raises(InvalidDPoPProof):
            svc.verify_dpop_proof(
                proof_jwt=proof,
                access_token=None,
                http_method="POST",
                http_uri="http://evil:9999/token",  # mismatch
            )

    def test_expired_iat_rejected(self):
        """DPoP proof with stale iat must be rejected."""
        svc = self._get_service()
        priv, jwk = _ec_keypair()
        proof = _make_dpop_proof(priv, jwk, iat=int(time.time()) - 300)

        from authgent_server.errors import InvalidDPoPProof

        with pytest.raises(InvalidDPoPProof, match="iat too old"):
            svc.verify_dpop_proof(
                proof_jwt=proof,
                access_token=None,
                http_method="POST",
                http_uri="http://localhost:8000/token",
            )

    def test_ath_mismatch_rejected(self):
        """DPoP proof with wrong access token hash must be rejected."""
        svc = self._get_service()
        priv, jwk = _ec_keypair()
        proof = _make_dpop_proof(priv, jwk, access_token="real-token")

        from authgent_server.errors import InvalidDPoPProof

        with pytest.raises(InvalidDPoPProof, match="ath mismatch"):
            svc.verify_dpop_proof(
                proof_jwt=proof,
                access_token="different-token",  # mismatch
                http_method="POST",
                http_uri="http://localhost:8000/token",
            )

    def test_jkt_binding_enforced(self):
        """DPoP proof from wrong key must be rejected when expected_jkt is set."""
        svc = self._get_service()
        priv, jwk = _ec_keypair()
        proof = _make_dpop_proof(priv, jwk)

        # Use a different key's thumbprint
        _, other_jwk = _ec_keypair()
        other_jkt = _compute_jkt(other_jwk)

        from authgent_server.errors import InvalidDPoPProof

        with pytest.raises(InvalidDPoPProof, match="thumbprint mismatch"):
            svc.verify_dpop_proof(
                proof_jwt=proof,
                access_token=None,
                http_method="POST",
                http_uri="http://localhost:8000/token",
                expected_jkt=other_jkt,
            )

    def test_jkt_binding_correct_key_passes(self):
        """DPoP proof from the correct key passes jkt binding check."""
        svc = self._get_service()
        priv, jwk = _ec_keypair()
        proof = _make_dpop_proof(priv, jwk)
        jkt = _compute_jkt(jwk)

        result = svc.verify_dpop_proof(
            proof_jwt=proof,
            access_token=None,
            http_method="POST",
            http_uri="http://localhost:8000/token",
            expected_jkt=jkt,
        )
        assert result["jkt"] == jkt

    def test_nonce_required_but_missing(self):
        """When nonce is required but missing, should raise UseDPoPNonce."""
        svc = self._get_service()
        priv, jwk = _ec_keypair()
        proof = _make_dpop_proof(priv, jwk)  # no nonce

        from authgent_server.errors import UseDPoPNonce

        with pytest.raises(UseDPoPNonce):
            svc.verify_dpop_proof(
                proof_jwt=proof,
                access_token=None,
                http_method="POST",
                http_uri="http://localhost:8000/token",
                require_nonce=True,
            )

    def test_nonce_required_valid_nonce_passes(self):
        """When nonce is required and a valid nonce is provided, should pass."""
        svc = self._get_service()
        priv, jwk = _ec_keypair()
        nonce = svc.generate_nonce()
        proof = _make_dpop_proof(priv, jwk, nonce=nonce)

        result = svc.verify_dpop_proof(
            proof_jwt=proof,
            access_token=None,
            http_method="POST",
            http_uri="http://localhost:8000/token",
            require_nonce=True,
        )
        assert "jkt" in result

    def test_malformed_proof_rejected(self):
        """Completely invalid JWT string must raise InvalidDPoPProof."""
        svc = self._get_service()

        from authgent_server.errors import InvalidDPoPProof

        with pytest.raises(InvalidDPoPProof):
            svc.verify_dpop_proof(
                proof_jwt="not-a-jwt",
                access_token=None,
                http_method="POST",
                http_uri="http://localhost:8000/token",
            )

    def test_wrong_typ_rejected(self):
        """DPoP proof with wrong typ header must be rejected."""
        svc = self._get_service()
        priv, jwk = _ec_keypair()

        # Manually craft a JWT with wrong typ
        headers = {"typ": "JWT", "alg": "ES256", "jwk": jwk}
        payload = {
            "htm": "POST",
            "htu": "http://localhost:8000/token",
            "iat": int(time.time()),
            "jti": secrets.token_hex(16),
        }
        proof = jwt.encode(payload, priv, algorithm="ES256", headers=headers)

        from authgent_server.errors import InvalidDPoPProof

        with pytest.raises(InvalidDPoPProof, match="typ=dpop\\+jwt"):
            svc.verify_dpop_proof(
                proof_jwt=proof,
                access_token=None,
                http_method="POST",
                http_uri="http://localhost:8000/token",
            )
