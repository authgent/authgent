"""Tests for SDK DPoP proof generation and verification."""

import base64
import hashlib
import json
import time

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import ec

from authgent.dpop import DPoPClient, _compute_jkt, verify_dpop_proof
from authgent.errors import DPoPError


def _make_dpop_bound_claims(jkt: str) -> dict:
    """Create mock token claims with cnf.jkt binding."""
    return {
        "sub": "client:test",
        "scope": "read",
        "cnf": {"jkt": jkt},
    }


def test_dpop_client_create_proof():
    client = DPoPClient()
    proof = client.create_proof("POST", "https://example.com/token")
    assert proof  # non-empty string

    # Decode unverified to check structure
    header = jwt.get_unverified_header(proof)
    assert header["typ"] == "dpop+jwt"
    assert header["alg"] == "ES256"
    assert "jwk" in header
    assert header["jwk"]["kty"] == "EC"
    assert header["jwk"]["crv"] == "P-256"


def test_dpop_client_jkt():
    client = DPoPClient()
    assert client.jkt  # non-empty
    assert len(client.jkt) > 10


def test_dpop_client_proof_with_ath():
    client = DPoPClient()
    access_token = "test_access_token_value"
    proof = client.create_proof("GET", "https://example.com/resource", access_token=access_token)

    # Verify ath is present
    payload = jwt.decode(proof, options={"verify_signature": False})
    expected_ath = base64.urlsafe_b64encode(
        hashlib.sha256(access_token.encode()).digest()
    ).rstrip(b"=").decode()
    assert payload["ath"] == expected_ath


def test_dpop_client_proof_with_nonce():
    client = DPoPClient()
    proof = client.create_proof("POST", "https://example.com/token", nonce="server_nonce_123")
    payload = jwt.decode(proof, options={"verify_signature": False})
    assert payload["nonce"] == "server_nonce_123"


def test_dpop_client_create_proof_headers():
    client = DPoPClient()
    headers = client.create_proof_headers(
        access_token="tok_abc",
        http_method="GET",
        http_uri="https://example.com/resource",
    )
    assert "Authorization" in headers
    assert headers["Authorization"].startswith("DPoP ")
    assert "DPoP" in headers


def test_verify_dpop_proof_success():
    client = DPoPClient()
    claims = _make_dpop_bound_claims(client.jkt)

    proof = client.create_proof("POST", "https://example.com/token")
    result = verify_dpop_proof(claims, proof, "POST", "https://example.com/token")
    assert result["jkt"] == client.jkt


def test_verify_dpop_proof_method_mismatch():
    client = DPoPClient()
    claims = _make_dpop_bound_claims(client.jkt)
    proof = client.create_proof("POST", "https://example.com/token")

    with pytest.raises(DPoPError, match="htm mismatch"):
        verify_dpop_proof(claims, proof, "GET", "https://example.com/token")


def test_verify_dpop_proof_uri_mismatch():
    client = DPoPClient()
    claims = _make_dpop_bound_claims(client.jkt)
    proof = client.create_proof("POST", "https://example.com/token")

    with pytest.raises(DPoPError, match="htu mismatch"):
        verify_dpop_proof(claims, proof, "POST", "https://other.com/token")


def test_verify_dpop_proof_no_cnf_jkt():
    claims = {"sub": "test", "scope": "read"}
    with pytest.raises(DPoPError, match="not DPoP-bound"):
        verify_dpop_proof(claims, "dummy", "POST", "https://example.com/token")


def test_verify_dpop_proof_jkt_mismatch():
    client = DPoPClient()
    other_client = DPoPClient()
    # Bind to other_client's jkt but use client's proof
    claims = _make_dpop_bound_claims(other_client.jkt)
    proof = client.create_proof("POST", "https://example.com/token")

    with pytest.raises(DPoPError, match="does not match"):
        verify_dpop_proof(claims, proof, "POST", "https://example.com/token")


def test_compute_jkt():
    jwk = {"kty": "EC", "crv": "P-256", "x": "abc", "y": "def"}
    jkt = _compute_jkt(jwk)
    assert isinstance(jkt, str)
    assert len(jkt) > 10
