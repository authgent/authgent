#!/usr/bin/env python3
"""Adversarial live test suite — runs against a live authgent-server on localhost:8000.

Tests cover:
  1. Protocol compliance (content-type, missing fields, wrong methods)
  2. Authentication (wrong secrets, missing auth, forged tokens)
  3. Scope enforcement (escalation, invalid scopes, empty scopes)
  4. Delegation chains (multi-hop, self-delegation, depth limits, revoked parent exchange)
  5. Token lifecycle (double revoke, introspect garbage, expired token behavior)
  6. Edge cases (duplicate names, deactivated agents, huge payloads, SQL injection)
  7. Discovery endpoints (JWKS, metadata, health)
"""

import base64
import hashlib
import json
import sys
import time
import hmac

import httpx

BASE = "http://localhost:8000"
PASS = 0
FAIL = 0
WARN = 0
BUGS = []


def result(test_name: str, passed: bool, detail: str = "", warn: bool = False):
    global PASS, FAIL, WARN
    if warn:
        WARN += 1
        icon = "⚠️ "
        label = "WARN"
    elif passed:
        PASS += 1
        icon = "✅"
        label = "PASS"
    else:
        FAIL += 1
        icon = "❌"
        label = "FAIL"
        BUGS.append((test_name, detail))
    print(f"  {icon} [{label}] {test_name}" + (f" — {detail}" if detail else ""))


def section(name: str):
    print(f"\n{'=' * 60}")
    print(f"  {name}")
    print(f"{'=' * 60}")


# ─── Setup: create test agents ───────────────────────────────────────


def setup():
    """Create the agents we'll use for testing."""
    agents = {}
    for name, scopes in [
        ("admin-orch", ["search:execute", "db:read", "db:write", "admin:manage"]),
        ("search-worker", ["search:execute", "db:read"]),
        ("db-reader", ["db:read"]),
        ("narrow-agent", ["db:read"]),
    ]:
        r = httpx.post(
            f"{BASE}/agents",
            json={
                "name": name,
                "allowed_scopes": scopes,
                "owner": "test@adversarial.dev",
            },
        )
        assert r.status_code in (200, 201), f"Failed to create {name}: {r.status_code} {r.text}"
        d = r.json()
        agents[name] = {
            "client_id": d["client_id"],
            "client_secret": d["client_secret"],
            "id": d["id"],
        }
    return agents


def get_token(client_id, client_secret, scope):
    """Get a client_credentials token."""
    r = httpx.post(
        f"{BASE}/token",
        data={
            "grant_type": "client_credentials",
            "client_id": client_id,
            "client_secret": client_secret,
            "scope": scope,
        },
    )
    return r


def exchange_token(subject_token, audience_client_id, audience_secret, scope):
    """Token exchange."""
    r = httpx.post(
        f"{BASE}/token",
        data={
            "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
            "subject_token": subject_token,
            "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
            "audience": audience_client_id,
            "client_id": audience_client_id,
            "client_secret": audience_secret,
            "scope": scope,
        },
    )
    return r


def decode_jwt_payload(token):
    """Decode JWT payload without verification."""
    parts = token.split(".")
    if len(parts) != 3:
        return {}
    payload = parts[1]
    payload += "=" * (4 - len(payload) % 4)
    return json.loads(base64.urlsafe_b64decode(payload))


# ══════════════════════════════════════════════════════════════════════
#  TEST SUITE
# ══════════════════════════════════════════════════════════════════════


def test_discovery_endpoints():
    section("1. Discovery & Health Endpoints")

    # Health
    r = httpx.get(f"{BASE}/health")
    result("GET /health returns 200", r.status_code == 200)

    # OAuth metadata
    r = httpx.get(f"{BASE}/.well-known/oauth-authorization-server")
    result("GET /.well-known/oauth-authorization-server", r.status_code == 200)
    meta = r.json()
    result("Metadata has token_endpoint", "token_endpoint" in meta)
    result("Metadata has jwks_uri", "jwks_uri" in meta)
    result(
        "grant_types includes client_credentials",
        "client_credentials" in meta.get("grant_types_supported", []),
    )
    result(
        "grant_types includes token-exchange",
        "urn:ietf:params:oauth:grant-type:token-exchange" in meta.get("grant_types_supported", []),
    )

    # JWKS
    r = httpx.get(f"{BASE}/.well-known/jwks.json")
    result("GET /.well-known/jwks.json returns 200", r.status_code == 200)
    jwks = r.json()
    result("JWKS has keys array", "keys" in jwks and len(jwks["keys"]) > 0)
    key = jwks["keys"][0]
    result("Key has kid", "kid" in key)
    result("Key has kty=EC", key.get("kty") == "EC")
    result("Key has alg=ES256", key.get("alg") == "ES256")

    # Non-existent endpoint
    r = httpx.get(f"{BASE}/nonexistent")
    result("GET /nonexistent returns 404", r.status_code == 404)


def test_protocol_compliance(agents):
    section("2. Protocol Compliance")
    a = agents["admin-orch"]

    # Wrong content type on /token
    r = httpx.post(
        f"{BASE}/token",
        json={"grant_type": "client_credentials", "client_id": a["client_id"]},
        headers={"Content-Type": "application/json"},
    )
    result(
        "POST /token with JSON content-type rejected",
        r.status_code == 400,
        f"status={r.status_code}",
    )

    # Missing grant_type
    r = httpx.post(
        f"{BASE}/token", data={"client_id": a["client_id"], "client_secret": a["client_secret"]}
    )
    result(
        "POST /token without grant_type rejected", r.status_code == 400, f"status={r.status_code}"
    )

    # Unknown grant_type
    r = httpx.post(
        f"{BASE}/token",
        data={
            "grant_type": "password",
            "client_id": a["client_id"],
            "client_secret": a["client_secret"],
        },
    )
    result(
        "POST /token with grant_type=password rejected",
        r.status_code in (400, 401),
        f"status={r.status_code}",
    )

    # Empty client_id
    r = httpx.post(
        f"{BASE}/token",
        data={"grant_type": "client_credentials", "client_id": "", "client_secret": "x"},
    )
    result(
        "POST /token with empty client_id rejected",
        r.status_code in (400, 401),
        f"status={r.status_code}",
    )

    # GET on POST-only endpoints
    r = httpx.get(f"{BASE}/token")
    result(
        "GET /token rejected (method not allowed)", r.status_code == 405, f"status={r.status_code}"
    )

    r = httpx.get(f"{BASE}/revoke")
    result("GET /revoke rejected", r.status_code == 405, f"status={r.status_code}")

    r = httpx.get(f"{BASE}/introspect")
    result("GET /introspect rejected", r.status_code == 405, f"status={r.status_code}")


def test_authentication(agents):
    section("3. Authentication Attacks")
    a = agents["admin-orch"]

    # Wrong client_secret
    r = get_token(a["client_id"], "wrong_secret_here", "db:read")
    result("Wrong client_secret rejected", r.status_code == 401, f"status={r.status_code}")

    # Non-existent client_id
    r = get_token("agnt_DOESNOTEXIST", "some_secret", "db:read")
    result("Non-existent client_id rejected", r.status_code == 401, f"status={r.status_code}")

    # HTTP Basic auth with wrong creds
    bad_basic = base64.b64encode(f"{a['client_id']}:wrongpassword".encode()).decode()
    r = httpx.post(
        f"{BASE}/token",
        data={"grant_type": "client_credentials", "scope": "db:read"},
        headers={"Authorization": f"Basic {bad_basic}"},
    )
    result(
        "HTTP Basic with wrong password rejected", r.status_code == 401, f"status={r.status_code}"
    )

    # HTTP Basic auth with correct creds
    good_basic = base64.b64encode(f"{a['client_id']}:{a['client_secret']}".encode()).decode()
    r = httpx.post(
        f"{BASE}/token",
        data={"grant_type": "client_credentials", "scope": "db:read"},
        headers={"Authorization": f"Basic {good_basic}"},
    )
    result("HTTP Basic with correct creds works", r.status_code == 200, f"status={r.status_code}")


def test_forged_tokens(agents):
    section("4. Forged / Tampered Token Attacks")
    a = agents["admin-orch"]

    # Get a real token first
    r = get_token(a["client_id"], a["client_secret"], "db:read")
    real_token = r.json()["access_token"]

    # Introspect a completely garbage token
    r = httpx.post(
        f"{BASE}/introspect",
        data={
            "token": "this.is.garbage",
            "client_id": a["client_id"],
            "client_secret": a["client_secret"],
        },
    )
    result(
        "Introspect garbage token returns active=false",
        r.status_code == 200 and r.json().get("active") is False,
        f"status={r.status_code}, body={r.text[:100]}",
    )

    # Introspect empty token
    r = httpx.post(
        f"{BASE}/introspect",
        data={
            "token": "",
            "client_id": a["client_id"],
            "client_secret": a["client_secret"],
        },
    )
    result(
        "Introspect empty token handled gracefully",
        r.status_code in (200, 400),
        f"status={r.status_code}, body={r.text[:100]}",
    )

    # Tamper with the payload — change scope to admin
    parts = real_token.split(".")
    payload = json.loads(base64.urlsafe_b64decode(parts[1] + "=="))
    payload["scope"] = "admin:manage db:write db:read search:execute god_mode"
    tampered_payload = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=").decode()
    tampered_token = f"{parts[0]}.{tampered_payload}.{parts[2]}"

    r = httpx.post(
        f"{BASE}/introspect",
        data={
            "token": tampered_token,
            "client_id": a["client_id"],
            "client_secret": a["client_secret"],
        },
    )
    result(
        "Tampered JWT (modified payload) rejected",
        r.status_code == 200 and r.json().get("active") is False,
        f"active={r.json().get('active')}",
    )

    # Token with wrong issuer (craft a fake header.payload, invalid sig)
    fake_payload = {
        "iss": "http://evil-server.com",
        "sub": f"client:{a['client_id']}",
        "scope": "admin:manage",
        "exp": int(time.time()) + 3600,
        "iat": int(time.time()),
    }
    fake_b64 = base64.urlsafe_b64encode(json.dumps(fake_payload).encode()).rstrip(b"=").decode()
    fake_token = f"{parts[0]}.{fake_b64}.{parts[2]}"

    r = httpx.post(
        f"{BASE}/introspect",
        data={
            "token": fake_token,
            "client_id": a["client_id"],
            "client_secret": a["client_secret"],
        },
    )
    result(
        "Token with wrong issuer rejected",
        r.status_code == 200 and r.json().get("active") is False,
        f"active={r.json().get('active')}",
    )

    # Use tampered token for exchange
    r = exchange_token(
        tampered_token,
        agents["search-worker"]["client_id"],
        agents["search-worker"]["client_secret"],
        "search:execute",
    )
    result(
        "Exchange with tampered token rejected",
        r.status_code in (400, 401),
        f"status={r.status_code}, body={r.text[:100]}",
    )


def test_scope_enforcement(agents):
    section("5. Scope Enforcement")
    a = agents["admin-orch"]
    s = agents["search-worker"]
    n = agents["narrow-agent"]

    # Request scope beyond allowed
    r = get_token(n["client_id"], n["client_secret"], "db:read db:write admin:manage")
    result(
        "Token request beyond allowed scopes rejected",
        r.status_code in (400, 403) or "error" in r.json(),
        f"status={r.status_code}, body={r.text[:100]}",
    )

    # Request with empty scope
    r = get_token(a["client_id"], a["client_secret"], "")
    result(
        "Empty scope request handled",
        r.status_code == 200,
        f"status={r.status_code}, body={r.text[:100]}",
    )

    # Request with made-up scopes
    r = get_token(a["client_id"], a["client_secret"], "launch_missiles destroy_world")
    result(
        "Made-up scopes rejected",
        r.status_code in (400, 403) or "error" in r.json(),
        f"status={r.status_code}, body={r.text[:100]}",
    )

    # Scope escalation on exchange: search-worker tries to get db:write
    orch_token = get_token(a["client_id"], a["client_secret"], "search:execute db:read").json()[
        "access_token"
    ]
    r = exchange_token(
        orch_token, s["client_id"], s["client_secret"], "search:execute db:read db:write"
    )
    result(
        "Scope escalation on exchange blocked (db:write not in search-worker)",
        r.status_code in (400, 403) or "error" in r.json(),
        f"status={r.status_code}, body={r.text[:100]}",
    )

    # Exchange requesting more scope than parent token has
    narrow_orch = get_token(a["client_id"], a["client_secret"], "db:read").json()["access_token"]
    r = exchange_token(narrow_orch, s["client_id"], s["client_secret"], "search:execute db:read")
    result(
        "Exchange can't escalate beyond parent token scope",
        r.status_code in (400, 403) or "error" in r.json(),
        f"status={r.status_code}, body={r.text[:120]}",
    )


def test_delegation_chains(agents):
    section("6. Delegation Chain Attacks")
    a = agents["admin-orch"]
    s = agents["search-worker"]
    d = agents["db-reader"]
    n = agents["narrow-agent"]

    # Normal 3-hop chain: orch → search → db → narrow
    t1 = get_token(a["client_id"], a["client_secret"], "search:execute db:read").json()[
        "access_token"
    ]
    r2 = exchange_token(t1, s["client_id"], s["client_secret"], "search:execute db:read")
    result("1-hop delegation works", r2.status_code == 200)
    t2 = r2.json()["access_token"]

    r3 = exchange_token(t2, d["client_id"], d["client_secret"], "db:read")
    result("2-hop delegation works", r3.status_code == 200)
    t3 = r3.json()["access_token"]

    r4 = exchange_token(t3, n["client_id"], n["client_secret"], "db:read")
    result("3-hop delegation works", r4.status_code == 200)

    # Verify 3-hop token has nested act claims
    if r4.status_code == 200:
        payload = decode_jwt_payload(r4.json()["access_token"])
        depth = 0
        act = payload.get("act")
        while act:
            depth += 1
            act = act.get("act")
        result("3-hop token has correct act depth (3)", depth == 3, f"depth={depth}")

    # Self-delegation: agent exchanges its own token to itself
    self_token = get_token(s["client_id"], s["client_secret"], "search:execute db:read").json()[
        "access_token"
    ]
    r = exchange_token(self_token, s["client_id"], s["client_secret"], "search:execute")
    # This may or may not be allowed — let's see
    if r.status_code == 200:
        result(
            "Self-delegation allowed (document behavior)",
            True,
            warn=True,
            detail="Agent can delegate to itself — consider if this is intended",
        )
    else:
        result("Self-delegation rejected", True, f"status={r.status_code}")

    # Exchange with non-existent audience
    r = httpx.post(
        f"{BASE}/token",
        data={
            "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
            "subject_token": t1,
            "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
            "audience": "agnt_DOESNOTEXIST",
            "client_id": "agnt_DOESNOTEXIST",
            "client_secret": "fake_secret",
            "scope": "db:read",
        },
    )
    result(
        "Exchange to non-existent audience rejected",
        r.status_code in (400, 401),
        f"status={r.status_code}",
    )


def test_token_lifecycle(agents):
    section("7. Token Lifecycle Edge Cases")
    a = agents["admin-orch"]
    s = agents["search-worker"]

    # Get a token, revoke it, try to use it
    t = get_token(a["client_id"], a["client_secret"], "db:read").json()["access_token"]

    # Revoke
    r = httpx.post(
        f"{BASE}/revoke",
        data={
            "token": t,
            "client_id": a["client_id"],
            "client_secret": a["client_secret"],
        },
    )
    result("Token revocation succeeds", r.status_code == 200)

    # Double revoke (should be idempotent per RFC 7009)
    r = httpx.post(
        f"{BASE}/revoke",
        data={
            "token": t,
            "client_id": a["client_id"],
            "client_secret": a["client_secret"],
        },
    )
    result(
        "Double revocation is idempotent (RFC 7009)",
        r.status_code == 200,
        f"status={r.status_code}",
    )

    # Introspect revoked token
    r = httpx.post(
        f"{BASE}/introspect",
        data={
            "token": t,
            "client_id": a["client_id"],
            "client_secret": a["client_secret"],
        },
    )
    result(
        "Introspect revoked token → active=false",
        r.status_code == 200 and r.json().get("active") is False,
    )

    # Try to exchange a revoked token
    r = exchange_token(t, s["client_id"], s["client_secret"], "db:read")
    result(
        "Exchange with revoked token rejected",
        r.status_code in (400, 401),
        f"status={r.status_code}, body={r.text[:120]}",
    )

    # Revoke a garbage token (should not error per RFC 7009)
    r = httpx.post(
        f"{BASE}/revoke",
        data={
            "token": "not.a.real.token",
            "client_id": a["client_id"],
            "client_secret": a["client_secret"],
        },
    )
    result(
        "Revoke garbage token doesn't error (RFC 7009)",
        r.status_code == 200,
        f"status={r.status_code}",
    )

    # Revoke with wrong client credentials
    real_t = get_token(a["client_id"], a["client_secret"], "db:read").json()["access_token"]
    r = httpx.post(
        f"{BASE}/revoke",
        data={
            "token": real_t,
            "client_id": a["client_id"],
            "client_secret": "wrong_secret",
        },
    )
    result("Revoke with wrong secret rejected", r.status_code == 401, f"status={r.status_code}")


def test_agent_edge_cases(agents):
    section("8. Agent Registration Edge Cases")

    # Create agent with empty name
    r = httpx.post(
        f"{BASE}/agents",
        json={
            "name": "",
            "allowed_scopes": ["db:read"],
            "owner": "test@test.com",
        },
    )
    result(
        "Empty agent name rejected",
        r.status_code in (400, 422),
        f"status={r.status_code}"
        if r.status_code in (400, 422)
        else f"BUG: accepted empty name, status={r.status_code}",
    )

    # Create agent with no scopes
    r = httpx.post(
        f"{BASE}/agents",
        json={
            "name": "no-scope-agent",
            "allowed_scopes": [],
            "owner": "test@test.com",
        },
    )
    if r.status_code == 200:
        result(
            "Agent with empty scopes created",
            True,
            warn=True,
            detail="Agent with no scopes is allowed — consider if this is intended",
        )
    else:
        result("Agent with empty scopes rejected", True)

    # Duplicate agent name
    r1 = httpx.post(
        f"{BASE}/agents",
        json={
            "name": "duplicate-test",
            "allowed_scopes": ["db:read"],
            "owner": "test@test.com",
        },
    )
    r2 = httpx.post(
        f"{BASE}/agents",
        json={
            "name": "duplicate-test",
            "allowed_scopes": ["db:read"],
            "owner": "test@test.com",
        },
    )
    if r1.status_code in (200, 201) and r2.status_code in (200, 201):
        result(
            "Duplicate agent names allowed",
            True,
            warn=True,
            detail="Two agents with same name — could confuse users/audit",
        )
    else:
        result("Duplicate agent names rejected", r2.status_code in (400, 409))

    # Create agent with very long name
    long_name = "a" * 10000
    r = httpx.post(
        f"{BASE}/agents",
        json={
            "name": long_name,
            "allowed_scopes": ["db:read"],
            "owner": "test@test.com",
        },
    )
    result(
        "Very long agent name handled", r.status_code in (200, 400, 422), f"status={r.status_code}"
    )

    # Create agent with special characters / injection
    r = httpx.post(
        f"{BASE}/agents",
        json={
            "name": "'; DROP TABLE agents; --",
            "allowed_scopes": ["db:read"],
            "owner": "test@test.com",
        },
    )
    result(
        "SQL injection in agent name handled safely",
        r.status_code in (200, 201, 400, 422),
        f"status={r.status_code}",
    )

    # Verify agents table still works after injection attempt
    r = httpx.post(
        f"{BASE}/agents",
        json={
            "name": "post-injection-test",
            "allowed_scopes": ["db:read"],
            "owner": "verify@test.com",
        },
    )
    result("Agents table intact after injection attempt", r.status_code in (200, 201))

    # Create agent with no owner
    r = httpx.post(
        f"{BASE}/agents",
        json={
            "name": "no-owner-agent",
            "allowed_scopes": ["db:read"],
        },
    )
    if r.status_code in (200, 201):
        result(
            "Agent without owner accepted",
            True,
            warn=True,
            detail="Agent created without owner field — consider requiring it",
        )
    else:
        result("Agent without owner rejected", r.status_code in (400, 422))

    # Create agent with completely invalid JSON
    r = httpx.post(
        f"{BASE}/agents", content=b"not json at all", headers={"Content-Type": "application/json"}
    )
    result("Invalid JSON body rejected", r.status_code == 422, f"status={r.status_code}")


def test_deactivated_agent(agents):
    section("9. Deactivated Agent Behavior")

    # Create and immediately try to use an agent, then check if we can deactivate
    r = httpx.post(
        f"{BASE}/agents",
        json={
            "name": "soon-deactivated",
            "allowed_scopes": ["db:read"],
            "owner": "test@test.com",
        },
    )
    ag = r.json()

    # Get token while active
    r = get_token(ag["client_id"], ag["client_secret"], "db:read")
    result("Token for active agent works", r.status_code == 200)
    active_token = r.json()["access_token"]

    # Try to deactivate via PATCH/PUT (check if endpoint exists)
    r = httpx.patch(f"{BASE}/agents/{ag['id']}", json={"status": "inactive"})
    if r.status_code == 200:
        result("Agent deactivation via PATCH works", True)
        # Now try to get a new token
        r = get_token(ag["client_id"], ag["client_secret"], "db:read")
        result(
            "Token for deactivated agent rejected",
            r.status_code in (400, 401, 403),
            f"status={r.status_code}",
        )
        # Old token should still introspect but...
        r = httpx.post(
            f"{BASE}/introspect",
            data={
                "token": active_token,
                "client_id": ag["client_id"],
                "client_secret": ag["client_secret"],
            },
        )
        result(
            "Old token of deactivated agent introspection",
            r.status_code == 200,
            f"active={r.json().get('active')}",
        )
    elif r.status_code == 405:
        result(
            "Agent deactivation endpoint not available (PATCH)",
            True,
            warn=True,
            detail="No PATCH /agents/:id — can't deactivate agents via API",
        )
    else:
        result("Agent deactivation via PATCH", False, f"status={r.status_code}")


def test_injection_attacks(agents):
    section("10. Injection & Boundary Attacks")
    a = agents["admin-orch"]

    # SQL injection in client_id
    r = httpx.post(
        f"{BASE}/token",
        data={
            "grant_type": "client_credentials",
            "client_id": "' OR '1'='1",
            "client_secret": "anything",
        },
    )
    result(
        "SQL injection in client_id rejected",
        r.status_code in (400, 401),
        f"status={r.status_code}",
    )

    # SQL injection in scope
    r = get_token(a["client_id"], a["client_secret"], "db:read' OR '1'='1")
    result(
        "SQL injection in scope handled",
        r.status_code in (200, 400, 403),
        f"status={r.status_code}",
    )

    # Very long scope string
    huge_scope = " ".join([f"scope_{i}" for i in range(10000)])
    r = get_token(a["client_id"], a["client_secret"], huge_scope)
    result(
        "Huge scope string handled gracefully",
        r.status_code in (200, 400, 403, 413, 422),
        f"status={r.status_code}",
    )

    # Null bytes in various fields
    try:
        r = httpx.post(
            f"{BASE}/token",
            data={
                "grant_type": "client_credentials",
                "client_id": a["client_id"] + "\x00admin",
                "client_secret": a["client_secret"],
            },
            timeout=5,
        )
        result(
            "Null byte in client_id handled", r.status_code in (400, 401), f"status={r.status_code}"
        )
    except Exception as e:
        result(
            "Null byte in client_id — SERVER CRASHED",
            False,
            detail=f"DoS vulnerability: {type(e).__name__}: {e}",
        )

    # Unicode tricks
    try:
        r = httpx.post(
            f"{BASE}/agents",
            json={
                "name": "test\u200bagent",  # zero-width space
                "allowed_scopes": ["db:read"],
                "owner": "test@test.com",
            },
            timeout=5,
        )
        result(
            "Unicode zero-width space in name handled",
            r.status_code in (200, 201, 400, 422),
            f"status={r.status_code}",
        )
    except Exception as e:
        result("Unicode in name — server error", False, detail=str(e))

    # CRLF injection in headers (via scope)
    try:
        r = get_token(a["client_id"], a["client_secret"], "db:read\r\nX-Injected: true")
        result(
            "CRLF injection in scope handled",
            r.status_code in (200, 400, 403),
            f"status={r.status_code}",
        )
    except Exception as e:
        result("CRLF injection — server error", False, detail=str(e))


def test_jwks_key_confusion():
    section("11. JWKS & Key Confusion")

    # Fetch JWKS
    r = httpx.get(f"{BASE}/.well-known/jwks.json")
    jwks = r.json()
    result("JWKS endpoint accessible", r.status_code == 200)

    # Verify no private key material is exposed
    for key in jwks.get("keys", []):
        has_private = any(k in key for k in ("d", "p", "q", "dp", "dq", "qi"))
        result(
            f"Key {key.get('kid', '?')} — no private material exposed",
            not has_private,
            detail="CRITICAL: Private key exposed in JWKS!" if has_private else "",
        )


def test_concurrent_and_timing(agents):
    section("12. Timing & Race Conditions")
    a = agents["admin-orch"]

    # Rapid-fire token requests
    tokens = []
    for i in range(10):
        r = get_token(a["client_id"], a["client_secret"], "db:read")
        if r.status_code == 200:
            tokens.append(r.json()["access_token"])
    result(f"10 rapid token requests all succeeded", len(tokens) == 10, f"got {len(tokens)}/10")

    # All tokens should have unique JTIs
    jtis = set()
    for t in tokens:
        payload = decode_jwt_payload(t)
        jtis.add(payload.get("jti"))
    result("All 10 tokens have unique JTIs", len(jtis) == 10, f"unique={len(jtis)}/10")

    # Token issued at time is reasonable
    payload = decode_jwt_payload(tokens[0])
    now = int(time.time())
    iat = payload.get("iat", 0)
    drift = abs(now - iat)
    result(f"Token iat is within 5s of wall clock", drift < 5, f"drift={drift}s")


def test_exchange_with_wrong_audience(agents):
    section("13. Cross-Agent Confusion Attacks")
    a = agents["admin-orch"]
    s = agents["search-worker"]
    d = agents["db-reader"]

    # Get orchestrator token
    t = get_token(a["client_id"], a["client_secret"], "search:execute db:read").json()[
        "access_token"
    ]

    # Exchange: use search-worker's credentials but claim db-reader as audience
    r = httpx.post(
        f"{BASE}/token",
        data={
            "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
            "subject_token": t,
            "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
            "audience": d["client_id"],  # audience is db-reader
            "client_id": s["client_id"],  # but authenticating as search-worker
            "client_secret": s["client_secret"],
            "scope": "db:read",
        },
    )
    if r.status_code == 200:
        payload = decode_jwt_payload(r.json()["access_token"])
        aud_match = payload.get("aud") == d["client_id"]
        act_match = s["client_id"] in str(payload.get("act", {}))
        result(
            "Audience/client mismatch — token issued",
            True,
            warn=True,
            detail=f"aud={payload.get('aud')}, act has search-worker. Audience != client_id allowed",
        )
    else:
        result("Audience/client mismatch rejected", True, f"status={r.status_code}")


def test_token_without_scope(agents):
    section("14. Minimal / Edge Token Requests")
    a = agents["admin-orch"]

    # Token with no scope at all
    r = httpx.post(
        f"{BASE}/token",
        data={
            "grant_type": "client_credentials",
            "client_id": a["client_id"],
            "client_secret": a["client_secret"],
        },
    )
    result(
        "Token without scope parameter",
        r.status_code in (200, 400),
        f"status={r.status_code}, scope={r.json().get('scope', 'N/A')}",
    )

    # Exchange with no scope
    if r.status_code == 200:
        t = r.json()["access_token"]
        r2 = exchange_token(
            t, agents["search-worker"]["client_id"], agents["search-worker"]["client_secret"], ""
        )
        result(
            "Exchange with empty scope string",
            r2.status_code in (200, 400),
            f"status={r2.status_code}",
        )


def test_revoke_other_agents_token(agents):
    section("15. Cross-Agent Token Revocation")
    a = agents["admin-orch"]
    s = agents["search-worker"]

    # Get orchestrator's token
    t = get_token(a["client_id"], a["client_secret"], "db:read").json()["access_token"]

    # Search-worker tries to revoke orchestrator's token
    r = httpx.post(
        f"{BASE}/revoke",
        data={
            "token": t,
            "client_id": s["client_id"],
            "client_secret": s["client_secret"],
        },
    )
    # Per RFC 7009, the server should either reject or silently accept
    result(
        "Cross-agent revocation handled",
        r.status_code in (200, 400, 401, 403),
        f"status={r.status_code}",
    )

    # Check if the token is still valid
    r = httpx.post(
        f"{BASE}/introspect",
        data={
            "token": t,
            "client_id": a["client_id"],
            "client_secret": a["client_secret"],
        },
    )
    if r.status_code == 200:
        still_active = r.json().get("active")
        if still_active is False:
            result(
                "Cross-agent revocation actually revoked the token!",
                False,
                detail="SECURITY: search-worker revoked orchestrator's token!",
            )
        else:
            result("Orchestrator's token still active after cross-agent revoke attempt", True)


# ══════════════════════════════════════════════════════════════════════
#  MAIN
# ══════════════════════════════════════════════════════════════════════


def main():
    global PASS, FAIL, WARN, BUGS
    print("\n" + "🔥" * 30)
    print("  ADVERSARIAL LIVE TEST SUITE")
    print("  Target: http://localhost:8000")
    print("🔥" * 30)

    # Verify server is up
    try:
        r = httpx.get(f"{BASE}/health", timeout=3)
        assert r.status_code == 200
    except Exception as e:
        print(f"\n❌ Server not reachable: {e}")
        sys.exit(1)

    # Setup
    section("0. Setup — Creating Test Agents")
    agents = setup()
    for name, info in agents.items():
        print(f"  Created: {name} → {info['client_id']}")

    # Run all test suites
    test_discovery_endpoints()
    test_protocol_compliance(agents)
    test_authentication(agents)
    test_forged_tokens(agents)
    test_scope_enforcement(agents)
    test_delegation_chains(agents)
    test_token_lifecycle(agents)
    test_agent_edge_cases(agents)
    test_deactivated_agent(agents)
    test_injection_attacks(agents)
    test_jwks_key_confusion()
    test_concurrent_and_timing(agents)
    test_exchange_with_wrong_audience(agents)
    test_token_without_scope(agents)
    test_revoke_other_agents_token(agents)

    # Summary
    print(f"\n{'=' * 60}")
    print(f"  RESULTS: {PASS} passed, {FAIL} failed, {WARN} warnings")
    print(f"{'=' * 60}")

    if BUGS:
        print(f"\n🐛 BUGS FOUND ({len(BUGS)}):")
        for name, detail in BUGS:
            print(f"  ❌ {name}: {detail}")

    if WARN > 0:
        print(f"\n⚠️  {WARN} warnings — behavior worth reviewing")

    if FAIL == 0:
        print(f"\n🎉 All tests passed!")
    else:
        print(f"\n💀 {FAIL} failures need investigation")

    sys.exit(1 if FAIL > 0 else 0)


if __name__ == "__main__":
    main()
