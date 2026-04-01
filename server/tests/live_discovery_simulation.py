#!/usr/bin/env python3
"""Real-world foreign agent discovery simulation.

Starts NO mocks. Makes real HTTP calls against a live authgent server.
Simulates a foreign agent with ZERO prior config bootstrapping itself:

  1. Hit endpoint cold → get 401 with WWW-Authenticate discovery URIs
  2. Parse resource_metadata → fetch RFC 9728 protected resource metadata
  3. Fetch RFC 8414 authorization server metadata → learn all endpoints
  4. Fetch JWKS → verify signing keys
  5. Fetch /openapi.json → verify securitySchemes
  6. Register Agent A via RFC 7591 dynamic registration (with new fields)
  7. Register Agent B with token exchange capability
  8. Agent A gets a scoped token
  9. Introspect Agent A's token
  10. Agent B exchanges Agent A's token (RFC 8693 delegation)
  11. Introspect delegated token → verify delegation chain
  12. Scope escalation blocked
  13. Revoke Agent A's original token
  14. RFC 7591 schema validation (jwks_uri/jwks mutual exclusion, HTTPS, structure)

Usage:
    python live_discovery_simulation.py [BASE_URL]
    # default: http://localhost:8000
"""

from __future__ import annotations

import json
import sys

import httpx

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8000"
client = httpx.Client(timeout=10)
passed = 0
failed = 0


def step(name: str, ok: bool, detail: str = "") -> None:
    global passed, failed
    if ok:
        passed += 1
        print(f"  \u2705 {name}")
    else:
        failed += 1
        print(f"  \u274c {name}: {detail}")


# ══════════════════════════════════════════════════════════════════════
print()
print("=" * 70)
print("  REAL-WORLD FOREIGN AGENT DISCOVERY SIMULATION")
print(f"  Live server: {BASE}")
print("=" * 70)

# ── STEP 1: Cold 401 ──────────────────────────────────────────────────
print()
print("-- Step 1: Cold 401 -> parse WWW-Authenticate for discovery URIs --")
r = client.post(
    f"{BASE}/token",
    data={
        "grant_type": "client_credentials",
        "client_id": "totally_unknown_foreign_agent",
        "client_secret": "wrong",
    },
)
step("Got 401", r.status_code == 401, f"got {r.status_code}")
www_auth = r.headers.get("WWW-Authenticate", "")
step("WWW-Authenticate present", bool(www_auth))
step('realm="authgent"', 'realm="authgent"' in www_auth, www_auth[:120])
step("authorization_uri present", "authorization_uri=" in www_auth)
step("resource_metadata present", "resource_metadata=" in www_auth)
step("error code present", "error=" in www_auth)

# Extract resource_metadata URI
resource_meta_uri = None
for part in www_auth.split(","):
    part = part.strip()
    if part.startswith("resource_metadata="):
        resource_meta_uri = part.split("=", 1)[1].strip('"')
print(f"  -> Extracted resource_metadata: {resource_meta_uri}")

# ── STEP 2: Protected resource metadata (RFC 9728) ───────────────────
print()
print("-- Step 2: Fetch protected resource metadata (RFC 9728) --")
r = client.get(resource_meta_uri)
step("PRM returns 200", r.status_code == 200, f"got {r.status_code}")
prm = r.json()
step("Has authorization_servers", "authorization_servers" in prm)
step("Has resource field", "resource" in prm)
auth_server = prm["authorization_servers"][0]
print(f"  -> Authorization server: {auth_server}")

# ── STEP 3: Authorization server metadata (RFC 8414) ─────────────────
print()
print("-- Step 3: Fetch authorization server metadata (RFC 8414) --")
r = client.get(f"{auth_server}/.well-known/oauth-authorization-server")
step("Metadata returns 200", r.status_code == 200, f"got {r.status_code}")
meta = r.json()
step("Has issuer", "issuer" in meta)
step("Has token_endpoint", "token_endpoint" in meta)
step("Has registration_endpoint", "registration_endpoint" in meta)
step("Has jwks_uri", "jwks_uri" in meta)
step(
    "Supports client_credentials",
    "client_credentials" in meta.get("grant_types_supported", []),
)
step(
    "Supports token_exchange",
    "urn:ietf:params:oauth:grant-type:token-exchange"
    in meta.get("grant_types_supported", []),
)
step("Requires S256 PKCE", "S256" in meta.get("code_challenge_methods_supported", []))
step(
    "Does NOT advertise private_key_jwt",
    "private_key_jwt" not in meta.get("token_endpoint_auth_methods_supported", []),
)
print(f"  -> Token endpoint: {meta['token_endpoint']}")
print(f"  -> Registration endpoint: {meta['registration_endpoint']}")

# ── STEP 4: JWKS (RFC 7517) ──────────────────────────────────────────
print()
print("-- Step 4: Fetch JWKS (RFC 7517) --")
r = client.get(meta["jwks_uri"])
step("JWKS returns 200", r.status_code == 200, f"got {r.status_code}")
jwks = r.json()
step("Has keys array", "keys" in jwks)
step("At least 1 key", len(jwks.get("keys", [])) > 0, f'{len(jwks.get("keys", []))} keys')
if jwks.get("keys"):
    k = jwks["keys"][0]
    step("Key has kty", "kty" in k)
    step("Key has kid", "kid" in k)
    print(f"  -> Key: kty={k.get('kty')}, kid={k.get('kid', '')[:16]}...")

# ── STEP 5: OpenAPI spec ─────────────────────────────────────────────
print()
print("-- Step 5: Fetch /openapi.json -- verify securitySchemes --")
r = client.get(f"{BASE}/openapi.json")
step("OpenAPI returns 200", r.status_code == 200)
spec = r.json()
schemes = spec.get("components", {}).get("securitySchemes", {})
step("Has OAuth2ClientCredentials", "OAuth2ClientCredentials" in schemes)
step("Has OAuth2AuthorizationCode", "OAuth2AuthorizationCode" in schemes)
step("Has BearerToken", "BearerToken" in schemes)
step("Has DPoP", "DPoP" in schemes)
step("Has servers array", len(spec.get("servers", [])) > 0)
step(
    "Description mentions discovery",
    "/.well-known" in spec.get("info", {}).get("description", ""),
)

# ── STEP 6: Register Agent A (RFC 7591) ──────────────────────────────
print()
print("-- Step 6: Register Agent A via RFC 7591 dynamic registration --")
r = client.post(
    meta["registration_endpoint"],
    json={
        "client_name": "live-foreign-agent-alpha",
        "grant_types": ["client_credentials"],
        "scope": "read write search",
        "client_uri": "https://alpha.foreign-agents.io",
        "contacts": ["ops@alpha.foreign-agents.io"],
    },
)
step("Registration returns 201", r.status_code == 201, f"got {r.status_code}: {r.text[:200]}")
agent_a = r.json()
step("Got client_id", "client_id" in agent_a)
step("Got client_secret", "client_secret" in agent_a)
step(
    "client_uri echoed back",
    agent_a.get("client_uri") == "https://alpha.foreign-agents.io",
)
step(
    "contacts echoed back",
    agent_a.get("contacts") == ["ops@alpha.foreign-agents.io"],
)
print(f"  -> Agent A: {agent_a['client_id']}")

# ── STEP 7: Register Agent B ─────────────────────────────────────────
print()
print("-- Step 7: Register Agent B (with token exchange) --")
r = client.post(
    meta["registration_endpoint"],
    json={
        "client_name": "live-foreign-agent-beta",
        "grant_types": [
            "client_credentials",
            "urn:ietf:params:oauth:grant-type:token-exchange",
        ],
        "scope": "read search",
        "client_uri": "https://beta.foreign-agents.io",
    },
)
step("Registration returns 201", r.status_code == 201, f"got {r.status_code}: {r.text[:200]}")
agent_b = r.json()
print(f"  -> Agent B: {agent_b['client_id']}")

# ── STEP 8: Agent A gets token ───────────────────────────────────────
print()
print("-- Step 8: Agent A requests client_credentials token --")
r = client.post(
    meta["token_endpoint"],
    data={
        "grant_type": "client_credentials",
        "client_id": agent_a["client_id"],
        "client_secret": agent_a["client_secret"],
        "scope": "read write search",
    },
)
step("Token returns 200", r.status_code == 200, f"got {r.status_code}: {r.text[:200]}")
tok_a = r.json()
step("Got access_token", "access_token" in tok_a)
step("token_type is Bearer", tok_a.get("token_type", "").lower() == "bearer")
step("expires_in present", "expires_in" in tok_a)
print(f"  -> Token: {tok_a['access_token'][:40]}...")

# ── STEP 9: Introspect Agent A token ─────────────────────────────────
print()
print("-- Step 9: Introspect Agent A token --")
r = client.post(f"{BASE}/introspect", data={"token": tok_a["access_token"]})
step("Introspect returns 200", r.status_code == 200)
intro_a = r.json()
step("Token is active", intro_a.get("active") is True)
step("client_id matches", intro_a.get("client_id") == agent_a["client_id"])
step("Scope includes read", "read" in intro_a.get("scope", ""))
step("Has iss claim", "iss" in intro_a)
step("Has sub claim", "sub" in intro_a)
step("Has jti claim", "jti" in intro_a)

# ── STEP 10: Token exchange (RFC 8693) ───────────────────────────────
print()
print("-- Step 10: Agent B exchanges Agent A token (RFC 8693 delegation) --")
r = client.post(
    meta["token_endpoint"],
    data={
        "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
        "client_id": agent_b["client_id"],
        "client_secret": agent_b["client_secret"],
        "subject_token": tok_a["access_token"],
        "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
        "audience": "https://beta.foreign-agents.io",
        "scope": "read",
    },
)
step("Exchange returns 200", r.status_code == 200, f"got {r.status_code}: {r.text[:300]}")
tok_b = r.json()
step("Got delegated access_token", "access_token" in tok_b)

# ── STEP 11: Introspect delegated token ──────────────────────────────
print()
print("-- Step 11: Introspect delegated token -- verify delegation chain --")
r = client.post(f"{BASE}/introspect", data={"token": tok_b["access_token"]})
intro_b = r.json()
step("Delegated token active", intro_b.get("active") is True)
step("Scope narrowed to read", intro_b.get("scope") == "read")
step("Has act claim (delegation)", intro_b.get("act") is not None)
step("act.sub identifies Agent B", "sub" in intro_b.get("act", {}))
print(f"  -> Delegation chain: {json.dumps(intro_b.get('act'), indent=2)[:200]}")

# ── STEP 12: Scope escalation blocked ────────────────────────────────
print()
print("-- Step 12: Verify scope escalation is BLOCKED --")
r = client.post(
    meta["token_endpoint"],
    data={
        "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
        "client_id": agent_b["client_id"],
        "client_secret": agent_b["client_secret"],
        "subject_token": tok_b["access_token"],
        "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
        "audience": "https://gamma.foreign-agents.io",
        "scope": "read write",
    },
)
step("Escalation blocked (403)", r.status_code == 403, f"got {r.status_code}")

# ── STEP 13: Revocation ──────────────────────────────────────────────
print()
print("-- Step 13: Revoke Agent A original token --")
r = client.post(
    f"{BASE}/revoke",
    data={
        "token": tok_a["access_token"],
        "client_id": agent_a["client_id"],
        "client_secret": agent_a["client_secret"],
    },
)
step("Revocation returns 200", r.status_code == 200, f"got {r.status_code}")
r = client.post(f"{BASE}/introspect", data={"token": tok_a["access_token"]})
step("Revoked token now inactive", r.json().get("active") is False)

# ── STEP 14: RFC 7591 validation ─────────────────────────────────────
print()
print("-- Step 14: RFC 7591 validation -- jwks_uri/jwks mutual exclusion --")
r = client.post(
    meta["registration_endpoint"],
    json={
        "client_name": "bad-both-jwks",
        "jwks_uri": "https://example.com/jwks.json",
        "jwks": {"keys": [{"kty": "EC", "crv": "P-256", "x": "a", "y": "b"}]},
    },
)
step("Mutual exclusion rejected (422)", r.status_code == 422, f"got {r.status_code}")

r = client.post(
    meta["registration_endpoint"],
    json={
        "client_name": "bad-http-jwks",
        "jwks_uri": "http://external.example.com/jwks.json",
    },
)
step("Non-localhost HTTP jwks_uri rejected (422)", r.status_code == 422, f"got {r.status_code}")

r = client.post(
    meta["registration_endpoint"],
    json={
        "client_name": "bad-jwks-structure",
        "jwks": {"not_keys": "invalid"},
    },
)
step("Invalid jwks structure rejected (422)", r.status_code == 422, f"got {r.status_code}")

# ══════════════════════════════════════════════════════════════════════
print()
print("=" * 70)
total = passed + failed
print(f"  RESULTS: {passed}/{total} passed, {failed} failed")
print("=" * 70)
print()
sys.exit(1 if failed else 0)
