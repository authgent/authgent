"""DPoP end-to-end integration tests — full HTTP round-trip.

Tests the complete DPoP lifecycle through the HTTP layer:
  1. Generate ephemeral EC key pair
  2. Build DPoP proof JWT (typ=dpop+jwt, ES256, htm/htu/iat/jti)
  3. Send proof via DPoP header on /token request
  4. Server binds token to key via cnf.jkt claim
  5. Introspection returns token_type=DPoP
  6. Token exchange carries DPoP binding forward
"""

from __future__ import annotations

import base64
import hashlib
import json
import secrets
import time

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat


# ─── DPoP Proof Builder ─────────────────────────────────────────────

def _ec_keypair() -> tuple[ec.EllipticCurvePrivateKey, dict]:
    """Generate an ephemeral ES256 key pair + JWK representation."""
    private_key = ec.generate_private_key(ec.SECP256R1())
    pub = private_key.public_key()
    pub_numbers = pub.public_numbers()

    def _b64(n: int, length: int = 32) -> str:
        return base64.urlsafe_b64encode(n.to_bytes(length, "big")).rstrip(b"=").decode()

    jwk = {
        "kty": "EC",
        "crv": "P-256",
        "x": _b64(pub_numbers.x),
        "y": _b64(pub_numbers.y),
    }
    return private_key, jwk


def _compute_jkt(jwk: dict) -> str:
    """Compute JWK Thumbprint per RFC 7638."""
    required = {"crv", "kty", "x", "y"}
    canonical = json.dumps(
        {k: jwk[k] for k in sorted(required) if k in jwk},
        separators=(",", ":"),
        sort_keys=True,
    )
    return base64.urlsafe_b64encode(
        hashlib.sha256(canonical.encode()).digest()
    ).rstrip(b"=").decode()


def _dpop_proof(
    private_key: ec.EllipticCurvePrivateKey,
    jwk: dict,
    htm: str,
    htu: str,
    access_token: str | None = None,
    nonce: str | None = None,
) -> str:
    """Build a DPoP proof JWT per RFC 9449."""
    headers = {
        "typ": "dpop+jwt",
        "alg": "ES256",
        "jwk": jwk,
    }
    payload: dict = {
        "htm": htm,
        "htu": htu,
        "iat": int(time.time()),
        "jti": secrets.token_urlsafe(16),
    }
    if access_token:
        ath = base64.urlsafe_b64encode(
            hashlib.sha256(access_token.encode()).digest()
        ).rstrip(b"=").decode()
        payload["ath"] = ath
    if nonce:
        payload["nonce"] = nonce

    return jwt.encode(payload, private_key, algorithm="ES256", headers=headers)


# ─── Helpers ─────────────────────────────────────────────────────────

def _register(c, **kw):
    body = {
        "client_name": f"dpop-test-{secrets.token_hex(4)}",
        "grant_types": kw.get("grant_types", ["client_credentials"]),
        "scope": kw.get("scope", "read write"),
    }
    if kw.get("dpop_bound"):
        body["dpop_bound_access_tokens"] = True
    resp = c.post("/register", json=body)
    assert resp.status_code == 201
    return resp.json()


def _introspect(c, token):
    resp = c.post("/introspect", data={"token": token})
    assert resp.status_code == 200
    return resp.json()


# ═════════════════════════════════════════════════════════════════════
# DPoP END-TO-END INTEGRATION TESTS
# ═════════════════════════════════════════════════════════════════════

class TestDPoPClientCredentialsFlow:
    """Client sends DPoP proof with client_credentials grant → gets DPoP-bound token."""

    def test_dpop_proof_binds_token_to_key(self, test_client):
        """Full flow: DPoP header → cnf.jkt in token → introspection shows DPoP."""
        creds = _register(test_client, scope="read write")
        private_key, jwk = _ec_keypair()
        jkt = _compute_jkt(jwk)

        # Build DPoP proof for POST /token
        # TestClient uses http://testserver as base URL
        proof = _dpop_proof(
            private_key, jwk,
            htm="POST",
            htu="http://testserver/token",
        )

        # Send token request with DPoP header
        resp = test_client.post("/token",
            data={
                "grant_type": "client_credentials",
                "client_id": creds["client_id"],
                "client_secret": creds["client_secret"],
                "scope": "read",
            },
            headers={"DPoP": proof},
        )
        assert resp.status_code == 200
        body = resp.json()

        # Token type should be DPoP, not Bearer
        assert body["token_type"] == "DPoP"
        access_token = body["access_token"]

        # Introspect — should show DPoP binding
        intro = _introspect(test_client, access_token)
        assert intro["active"] is True
        assert intro["token_type"] == "DPoP"

    def test_dpop_token_has_cnf_jkt_claim(self, test_client):
        """The issued JWT contains cnf.jkt matching the proof key's thumbprint."""
        creds = _register(test_client, scope="read")
        private_key, jwk = _ec_keypair()
        expected_jkt = _compute_jkt(jwk)

        proof = _dpop_proof(private_key, jwk, htm="POST", htu="http://testserver/token")

        resp = test_client.post("/token",
            data={
                "grant_type": "client_credentials",
                "client_id": creds["client_id"],
                "client_secret": creds["client_secret"],
                "scope": "read",
            },
            headers={"DPoP": proof},
        )
        assert resp.status_code == 200
        access_token = resp.json()["access_token"]

        # Decode the JWT without verification to inspect cnf claim
        claims = jwt.decode(access_token, options={"verify_signature": False})
        assert "cnf" in claims
        assert claims["cnf"]["jkt"] == expected_jkt

    def test_without_dpop_header_gets_bearer_token(self, test_client):
        """Without DPoP header, token is regular Bearer (no cnf)."""
        creds = _register(test_client, scope="read")

        resp = test_client.post("/token", data={
            "grant_type": "client_credentials",
            "client_id": creds["client_id"],
            "client_secret": creds["client_secret"],
            "scope": "read",
        })
        assert resp.status_code == 200
        body = resp.json()
        assert body["token_type"] == "Bearer"

        claims = jwt.decode(body["access_token"], options={"verify_signature": False})
        assert "cnf" not in claims


class TestDPoPProofValidation:
    """Server rejects invalid DPoP proofs at the HTTP layer."""

    def test_malformed_dpop_proof_rejected(self, test_client):
        """Garbage DPoP header → 401 (InvalidDPoPProof per RFC 9449)."""
        creds = _register(test_client)
        resp = test_client.post("/token",
            data={
                "grant_type": "client_credentials",
                "client_id": creds["client_id"],
                "client_secret": creds["client_secret"],
            },
            headers={"DPoP": "this.is.not.a.valid.dpop.proof"},
        )
        assert resp.status_code == 401

    def test_wrong_htm_rejected(self, test_client):
        """DPoP proof with htm=GET for a POST endpoint → rejected."""
        creds = _register(test_client)
        private_key, jwk = _ec_keypair()

        proof = _dpop_proof(private_key, jwk, htm="GET", htu="http://testserver/token")

        resp = test_client.post("/token",
            data={
                "grant_type": "client_credentials",
                "client_id": creds["client_id"],
                "client_secret": creds["client_secret"],
            },
            headers={"DPoP": proof},
        )
        assert resp.status_code == 401

    def test_wrong_htu_rejected(self, test_client):
        """DPoP proof with wrong htu → rejected."""
        creds = _register(test_client)
        private_key, jwk = _ec_keypair()

        proof = _dpop_proof(
            private_key, jwk,
            htm="POST",
            htu="http://evil.com/token",  # wrong URI
        )

        resp = test_client.post("/token",
            data={
                "grant_type": "client_credentials",
                "client_id": creds["client_id"],
                "client_secret": creds["client_secret"],
            },
            headers={"DPoP": proof},
        )
        assert resp.status_code == 401

    def test_dpop_proof_with_wrong_key_type_rejected(self, test_client):
        """DPoP proof signed with a different key than the one in the header → rejected."""
        creds = _register(test_client)
        signing_key, _ = _ec_keypair()
        _, header_jwk = _ec_keypair()  # different key in header

        # Sign with signing_key but put header_jwk in the JWT header
        headers = {"typ": "dpop+jwt", "alg": "ES256", "jwk": header_jwk}
        payload = {
            "htm": "POST",
            "htu": "http://testserver/token",
            "iat": int(time.time()),
            "jti": secrets.token_urlsafe(16),
        }
        bad_proof = jwt.encode(payload, signing_key, algorithm="ES256", headers=headers)

        resp = test_client.post("/token",
            data={
                "grant_type": "client_credentials",
                "client_id": creds["client_id"],
                "client_secret": creds["client_secret"],
            },
            headers={"DPoP": bad_proof},
        )
        assert resp.status_code == 401


class TestDPoPTokenExchange:
    """DPoP binding carries through token exchange."""

    def test_exchanged_token_can_be_dpop_bound(self, test_client):
        """Token exchange with DPoP header → exchanged token is also DPoP-bound."""
        parent = _register(test_client, scope="read write")
        child = _register(
            test_client,
            grant_types=["client_credentials", "urn:ietf:params:oauth:grant-type:token-exchange"],
            scope="read",
        )

        # Parent gets a regular Bearer token
        parent_resp = test_client.post("/token", data={
            "grant_type": "client_credentials",
            "client_id": parent["client_id"],
            "client_secret": parent["client_secret"],
            "scope": "read write",
        })
        parent_token = parent_resp.json()["access_token"]

        # Child exchanges with DPoP proof
        child_key, child_jwk = _ec_keypair()
        child_jkt = _compute_jkt(child_jwk)

        proof = _dpop_proof(child_key, child_jwk, htm="POST", htu="http://testserver/token")

        exchange_resp = test_client.post("/token",
            data={
                "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
                "client_id": child["client_id"],
                "client_secret": child["client_secret"],
                "subject_token": parent_token,
                "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
                "audience": "https://api.example.com",
                "scope": "read",
            },
            headers={"DPoP": proof},
        )
        assert exchange_resp.status_code == 200
        body = exchange_resp.json()
        assert body["token_type"] == "DPoP"

        # Verify cnf.jkt matches the child's key
        claims = jwt.decode(body["access_token"], options={"verify_signature": False})
        assert claims["cnf"]["jkt"] == child_jkt

        # Introspection confirms DPoP type
        intro = _introspect(test_client, body["access_token"])
        assert intro["active"] is True
        assert intro["token_type"] == "DPoP"

    def test_each_agent_gets_own_dpop_binding(self, test_client):
        """Two different agents exchanging the same token get different cnf.jkt bindings."""
        parent = _register(test_client, scope="read write")
        child_a = _register(
            test_client,
            grant_types=["client_credentials", "urn:ietf:params:oauth:grant-type:token-exchange"],
            scope="read",
        )
        child_b = _register(
            test_client,
            grant_types=["client_credentials", "urn:ietf:params:oauth:grant-type:token-exchange"],
            scope="read",
        )

        parent_token = test_client.post("/token", data={
            "grant_type": "client_credentials",
            "client_id": parent["client_id"],
            "client_secret": parent["client_secret"],
            "scope": "read write",
        }).json()["access_token"]

        # Agent A exchanges with its key
        key_a, jwk_a = _ec_keypair()
        jkt_a = _compute_jkt(jwk_a)
        proof_a = _dpop_proof(key_a, jwk_a, htm="POST", htu="http://testserver/token")

        resp_a = test_client.post("/token",
            data={
                "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
                "client_id": child_a["client_id"],
                "client_secret": child_a["client_secret"],
                "subject_token": parent_token,
                "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
                "audience": "https://api-a.example.com",
                "scope": "read",
            },
            headers={"DPoP": proof_a},
        )
        assert resp_a.status_code == 200, f"Agent A exchange failed: {resp_a.json()}"
        claims_a = jwt.decode(resp_a.json()["access_token"], options={"verify_signature": False})

        # Agent B exchanges with its own key
        key_b, jwk_b = _ec_keypair()
        jkt_b = _compute_jkt(jwk_b)
        proof_b = _dpop_proof(key_b, jwk_b, htm="POST", htu="http://testserver/token")

        resp_b = test_client.post("/token",
            data={
                "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
                "client_id": child_b["client_id"],
                "client_secret": child_b["client_secret"],
                "subject_token": parent_token,
                "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
                "audience": "https://api-b.example.com",
                "scope": "read",
            },
            headers={"DPoP": proof_b},
        )
        assert resp_b.status_code == 200, f"Agent B exchange failed: {resp_b.json()}"
        claims_b = jwt.decode(resp_b.json()["access_token"], options={"verify_signature": False})

        # Each agent's token is bound to its own key
        assert claims_a["cnf"]["jkt"] == jkt_a
        assert claims_b["cnf"]["jkt"] == jkt_b
        assert jkt_a != jkt_b
