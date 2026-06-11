"""Calibration: feed the scanner synthetic AS metadata for each known
class of MCP server and assert the grade matches expectations.

These fixtures double as the published calibration set in
``docs/calibration.md``. If you change a scoring weight, this file is
where you have to confirm the trade-off; if a row's expected grade no
longer matches reality, the calibration assertion fails before
production traffic ever sees the new grade.
"""

from __future__ import annotations

import httpx
import pytest

from authgent_server.endpoints.scan import _grade
from authgent_server.scanner import scan


def _good_prm(base: str, as_url: str) -> dict:
    return {
        "resource": base,
        "authorization_servers": [as_url],
        "scopes_supported": ["read"],
        "bearer_methods_supported": ["header"],
    }


def _good_as_meta(as_url: str) -> dict:
    return {
        "issuer": as_url,
        "authorization_endpoint": f"{as_url}/authorize",
        "token_endpoint": f"{as_url}/token",
        "registration_endpoint": f"{as_url}/register",
        "jwks_uri": f"{as_url}/.well-known/jwks.json",
        "response_types_supported": ["code"],
        "grant_types_supported": [
            "authorization_code",
            "client_credentials",
            "refresh_token",
        ],
        "code_challenge_methods_supported": ["S256"],
        "resource_indicators_supported": True,
        "dpop_signing_alg_values_supported": ["ES256"],
        "authorization_response_iss_parameter_supported": True,
    }


def _make_handler(routes):
    queues = {}
    for k, v in routes.items():
        queues[k] = iter(v) if isinstance(v, list) else iter([v] * 100)

    def handler(req: httpx.Request) -> httpx.Response:
        key = (req.method, str(req.url).rstrip("/"))
        if key in queues:
            try:
                return next(queues[key])
            except StopIteration:
                return httpx.Response(404)
        no_q = (req.method, str(req.url).split("?", 1)[0].rstrip("/"))
        if no_q in queues:
            try:
                return next(queues[no_q])
            except StopIteration:
                return httpx.Response(404)
        return httpx.Response(404)

    return handler


def _client(routes):
    return httpx.AsyncClient(transport=httpx.MockTransport(_make_handler(routes)))


@pytest.mark.asyncio
async def test_calibration_perfect_mcp_2026_grades_a():
    """A fully MCP-2026-conformant server (all spec_required + advisory pass) → A/100."""
    base = "http://mcp.good"
    as_url = "http://as.good"
    routes = {
        ("GET", f"{base}/.well-known/oauth-protected-resource"): httpx.Response(
            200, json=_good_prm(base, as_url)
        ),
        ("GET", f"{as_url}/.well-known/oauth-authorization-server"): httpx.Response(
            200, json=_good_as_meta(as_url)
        ),
        ("GET", f"{as_url}/authorize"): httpx.Response(
            400, text="invalid_request: code_challenge_method 'plain' not supported; use S256"
        ),
        ("GET", base): httpx.Response(404),
        ("POST", f"{as_url}/register"): [
            httpx.Response(201, json={"client_id": "agnt_a"}),
            httpx.Response(201, json={"client_id": "agnt_b"}),
        ],
    }
    async with _client(routes) as c:
        findings = await scan(base, http_client=c)
    grade, score = _grade(findings)
    assert (grade, score) == ("A", 100), f"got {grade}/{score}, findings={findings}"


@pytest.mark.asyncio
async def test_calibration_legacy_idp_no_mcp_yet_grades_a():
    """A legacy IdP that's spec-correct but advertises none of the
    *advisory* MCP-2026 features (no iss param, no DPoP) MUST still grade
    A — those are advisory, not graded.

    This is the calibration-set defense: without the spec_required /
    advisory tier split, this case would previously grade B/C and make
    readers conclude the scanner was broken.
    """
    base = "http://mcp.legacy"
    as_url = "http://as.legacy"
    legacy_meta = _good_as_meta(as_url)
    legacy_meta.pop("authorization_response_iss_parameter_supported", None)
    legacy_meta.pop("dpop_signing_alg_values_supported", None)
    routes = {
        ("GET", f"{base}/.well-known/oauth-protected-resource"): httpx.Response(
            200, json=_good_prm(base, as_url)
        ),
        ("GET", f"{as_url}/.well-known/oauth-authorization-server"): httpx.Response(
            200, json=legacy_meta
        ),
        ("GET", f"{as_url}/authorize"): httpx.Response(
            400, text="invalid_request: code_challenge_method must be S256"
        ),
        ("GET", base): httpx.Response(404),
        ("POST", f"{as_url}/register"): [
            httpx.Response(201, json={"client_id": "agnt_a"}),
            httpx.Response(201, json={"client_id": "agnt_b"}),
        ],
    }
    async with _client(routes) as c:
        findings = await scan(base, http_client=c)
    grade, score = _grade(findings)
    assert grade == "A", f"legacy IdP without MCP-only fields should grade A, got {grade}/{score}"


@pytest.mark.asyncio
async def test_calibration_advertises_pkce_plain_grades_below_a():
    """Server that advertises ``plain`` violates OAuth 2.1 (spec_required).

    Isolate to one finding: distinct DCR client_ids so MCP-DCR-MIRROR-001
    does not also fire. PKCE-001 alone is severity=error (-15) → score 85
    → grade B.
    """
    base = "http://mcp.plain"
    as_url = "http://as.plain"
    bad = _good_as_meta(as_url)
    bad["code_challenge_methods_supported"] = ["S256", "plain"]
    routes = {
        ("GET", f"{base}/.well-known/oauth-protected-resource"): httpx.Response(
            200, json=_good_prm(base, as_url)
        ),
        ("GET", f"{as_url}/.well-known/oauth-authorization-server"): httpx.Response(200, json=bad),
        ("GET", f"{as_url}/authorize"): httpx.Response(
            400, text="invalid_request: code_challenge_method"
        ),
        ("GET", base): httpx.Response(404),
        ("POST", f"{as_url}/register"): [
            httpx.Response(201, json={"client_id": "agnt_a"}),
            httpx.Response(201, json={"client_id": "agnt_b"}),
        ],
    }
    async with _client(routes) as c:
        findings = await scan(base, http_client=c)
    grade, _ = _grade(findings)
    assert grade in ("B", "C"), f"PKCE plain alone should be B/C, got {grade}"


@pytest.mark.asyncio
async def test_calibration_no_prm_grades_d_or_f():
    """Missing PRM is critical — no MCP client can discover the AS."""
    base = "http://mcp.noprm"
    routes = {("GET", f"{base}/.well-known/oauth-protected-resource"): httpx.Response(404)}
    async with _client(routes) as c:
        findings = await scan(base, http_client=c)
    grade, _ = _grade(findings)
    assert grade in ("D", "F"), f"no PRM should be D/F, got {grade}"


@pytest.mark.asyncio
async def test_calibration_implicit_grant_advertised_grades_d_or_f():
    """``response_type=token`` advertised is forbidden by OAuth 2.1."""
    base = "http://mcp.implicit"
    as_url = "http://as.implicit"
    bad = _good_as_meta(as_url)
    bad["response_types_supported"] = ["code", "token"]
    routes = {
        ("GET", f"{base}/.well-known/oauth-protected-resource"): httpx.Response(
            200, json=_good_prm(base, as_url)
        ),
        ("GET", f"{as_url}/.well-known/oauth-authorization-server"): httpx.Response(200, json=bad),
        ("GET", f"{as_url}/authorize"): httpx.Response(
            400, text="invalid_request: code_challenge_method must be S256"
        ),
        ("GET", base): httpx.Response(404),
        ("POST", f"{as_url}/register"): httpx.Response(201, json={"client_id": "x"}),
    }
    async with _client(routes) as c:
        findings = await scan(base, http_client=c)
    grade, _ = _grade(findings)
    assert grade in ("D", "F"), f"implicit grant advertised should be D/F, got {grade}"


@pytest.mark.asyncio
async def test_calibration_dcr_mirror_grades_d_or_f():
    """DCR returning the same client_id for two registrations is the
    Obsidian-disclosed consent-cache-bypass pattern. Critical."""
    base = "http://mcp.mirror"
    as_url = "http://as.mirror"
    same = httpx.Response(201, json={"client_id": "agnt_static"})
    routes = {
        ("GET", f"{base}/.well-known/oauth-protected-resource"): httpx.Response(
            200, json=_good_prm(base, as_url)
        ),
        ("GET", f"{as_url}/.well-known/oauth-authorization-server"): httpx.Response(
            200, json=_good_as_meta(as_url)
        ),
        ("GET", f"{as_url}/authorize"): httpx.Response(
            400, text="invalid_request: code_challenge_method must be S256"
        ),
        ("GET", base): httpx.Response(404),
        ("POST", f"{as_url}/register"): [same, same],
    }
    async with _client(routes) as c:
        findings = await scan(base, http_client=c)
    grade, _ = _grade(findings)
    assert grade in ("D", "F"), f"DCR mirror should be D/F, got {grade}"
