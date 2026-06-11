"""Tests for ``authgent-server lint`` (the MCP-OAuth scanner).

We stub HTTP responses with ``httpx.MockTransport`` so the tests are
hermetic and add no new dependency. Each test injects exactly one bad
config and asserts the matching check fires.
"""

from __future__ import annotations

import json
from collections.abc import Iterator

import httpx
import pytest

from authgent_server.scanner import (
    Finding,
    check_audience_binding,
    check_dcr_redirect_validation,
    check_pkce,
    check_refresh_for_public_clients,
    check_state_csrf_advertised,
    format_github,
    format_human,
    format_json,
    has_blocking,
    scan,
)

# ---- Pure synchronous checks ----------------------------------------------


def test_pkce_missing_s256_is_critical():
    findings = check_pkce({"code_challenge_methods_supported": []})
    assert any(f.check_id == "MCP-PKCE-001" and f.severity == "critical" for f in findings)


def test_pkce_plain_advertised_is_error():
    findings = check_pkce({"code_challenge_methods_supported": ["S256", "plain"]})
    assert any("plain" in f.detail for f in findings)


def test_pkce_s256_only_is_clean():
    assert check_pkce({"code_challenge_methods_supported": ["S256"]}) == []


def test_audience_binding_missing_is_error():
    findings = check_audience_binding({})
    assert any(f.check_id == "MCP-AUD-001" and f.severity == "error" for f in findings)


def test_audience_binding_present_is_clean():
    assert check_audience_binding({"resource_indicators_supported": True}) == []


def test_dcr_missing_is_warning():
    findings = check_dcr_redirect_validation({})
    assert any(f.check_id == "MCP-DCR-001" and f.severity == "warning" for f in findings)


def test_implicit_grant_advertised_is_critical():
    findings = check_state_csrf_advertised({"response_types_supported": ["code", "token"]})
    assert any(f.check_id == "MCP-CSRF-001" and f.severity == "critical" for f in findings)


def test_refresh_without_dpop_is_warning():
    findings = check_refresh_for_public_clients(
        {"grant_types_supported": ["refresh_token"], "dpop_signing_alg_values_supported": []}
    )
    assert any(f.check_id == "MCP-REFRESH-001" for f in findings)


def test_refresh_with_dpop_is_clean():
    assert (
        check_refresh_for_public_clients(
            {
                "grant_types_supported": ["refresh_token"],
                "dpop_signing_alg_values_supported": ["ES256"],
            }
        )
        == []
    )


# ---- End-to-end scan against a stubbed HTTP transport --------------------


def _good_prm(base: str, as_url: str) -> dict:
    return {
        "resource": base,
        "authorization_servers": [as_url],
        "scopes_supported": ["search:execute"],
        "bearer_methods_supported": ["header"],
    }


def _good_as_meta(as_url: str) -> dict:
    return {
        "issuer": as_url,
        "authorization_endpoint": f"{as_url}/authorize",
        "token_endpoint": f"{as_url}/token",
        "registration_endpoint": f"{as_url}/register",
        "revocation_endpoint": f"{as_url}/revoke",
        "introspection_endpoint": f"{as_url}/introspect",
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


def _make_handler(routes: dict[tuple[str, str], httpx.Response | list[httpx.Response]]):
    """Build an httpx.MockTransport handler from a route table.

    routes: { (method, url) -> Response | [Response, Response, ...] }
    Multiple responses are returned in order across successive calls.
    """
    queues: dict[tuple[str, str], Iterator[httpx.Response]] = {}
    for key, value in routes.items():
        if isinstance(value, list):
            queues[key] = iter(value)
        else:
            queues[key] = iter([value] * 100)

    def handler(request: httpx.Request) -> httpx.Response:
        key = (request.method, str(request.url).rstrip("/"))
        if key in queues:
            try:
                return next(queues[key])
            except StopIteration:  # pragma: no cover
                return httpx.Response(404)
        # Fallback: match without query string for endpoint-only routes.
        url_no_query = str(request.url).split("?", 1)[0].rstrip("/")
        key_no_query = (request.method, url_no_query)
        if key_no_query in queues:
            try:
                return next(queues[key_no_query])
            except StopIteration:  # pragma: no cover
                return httpx.Response(404)
        return httpx.Response(404)

    return handler


@pytest.fixture
def scanner_client():
    """Yield a builder that returns an httpx.AsyncClient backed by a
    MockTransport configured from a dict of routes."""

    clients: list[httpx.AsyncClient] = []

    def build(routes):
        transport = httpx.MockTransport(_make_handler(routes))
        c = httpx.AsyncClient(transport=transport)
        clients.append(c)
        return c

    yield build

    # Tests await scan() which closes the client only when it owns it; we
    # injected an external one so we close them here.
    import asyncio

    async def _close_all():
        for c in clients:
            await c.aclose()

    asyncio.run(_close_all())


@pytest.mark.asyncio
async def test_scan_clean_server_has_no_blocking_findings(scanner_client):
    base = "http://mcp.example"
    as_url = "http://as.example"
    routes = {
        ("GET", f"{base}/.well-known/oauth-protected-resource"): httpx.Response(
            200, json=_good_prm(base, as_url)
        ),
        ("GET", f"{as_url}/.well-known/oauth-authorization-server"): httpx.Response(
            200, json=_good_as_meta(as_url)
        ),
        ("GET", base): httpx.Response(404),
        ("POST", f"{as_url}/register"): [
            httpx.Response(201, json={"client_id": "agnt_a", "client_secret": "s"}),
            httpx.Response(201, json={"client_id": "agnt_b", "client_secret": "s"}),
        ],
    }
    client = scanner_client(routes)
    findings = await scan(base, http_client=client)
    assert not has_blocking(findings)


@pytest.mark.asyncio
async def test_scan_missing_prm_is_blocking(scanner_client):
    base = "http://mcp.example"
    routes = {
        ("GET", f"{base}/.well-known/oauth-protected-resource"): httpx.Response(404),
    }
    client = scanner_client(routes)
    findings = await scan(base, http_client=client)
    assert any(f.check_id == "MCP-PRM-001" for f in findings)
    assert has_blocking(findings)


@pytest.mark.asyncio
async def test_scan_pkce_plain_is_blocking(scanner_client):
    base = "http://mcp.example"
    as_url = "http://as.example"
    bad_meta = _good_as_meta(as_url)
    bad_meta["code_challenge_methods_supported"] = ["S256", "plain"]
    routes = {
        ("GET", f"{base}/.well-known/oauth-protected-resource"): httpx.Response(
            200, json=_good_prm(base, as_url)
        ),
        ("GET", f"{as_url}/.well-known/oauth-authorization-server"): httpx.Response(
            200, json=bad_meta
        ),
        ("GET", base): httpx.Response(404),
        ("POST", f"{as_url}/register"): httpx.Response(
            201, json={"client_id": "agnt_x", "client_secret": "s"}
        ),
    }
    client = scanner_client(routes)
    findings = await scan(base, http_client=client)
    assert any(f.check_id == "MCP-PKCE-001" for f in findings)
    assert has_blocking(findings)


@pytest.mark.asyncio
async def test_scan_dcr_mirror_critical_when_clientid_repeats(scanner_client):
    """DCR-mirror is opt-in via probe_registrations=True so registry
    refresh doesn't litter vendor databases. Verify it still fires for
    the explicit interactive scan path."""
    base = "http://mcp.example"
    as_url = "http://as.example"
    same = httpx.Response(201, json={"client_id": "agnt_static", "client_secret": "s"})
    routes = {
        ("GET", f"{base}/.well-known/oauth-protected-resource"): httpx.Response(
            200, json=_good_prm(base, as_url)
        ),
        ("GET", f"{as_url}/.well-known/oauth-authorization-server"): httpx.Response(
            200, json=_good_as_meta(as_url)
        ),
        ("GET", base): httpx.Response(404),
        ("POST", f"{as_url}/register"): [same, same],
    }
    client = scanner_client(routes)
    findings = await scan(base, http_client=client, probe_registrations=True)
    assert any(f.check_id == "MCP-DCR-MIRROR-001" and f.severity == "critical" for f in findings)
    assert has_blocking(findings)


@pytest.mark.asyncio
async def test_scan_dcr_mirror_skipped_when_probing_disabled(scanner_client):
    """Default scan() (registry refresh path) MUST NOT make POST /register
    calls. This is the abuse-mitigation fix for P0-3."""
    base = "http://mcp.example"
    as_url = "http://as.example"
    register_calls = {"count": 0}

    def counting_register(req):
        register_calls["count"] += 1
        return httpx.Response(201, json={"client_id": "agnt_static", "client_secret": "s"})

    transport = httpx.MockTransport(
        lambda req: (
            httpx.Response(200, json=_good_prm(base, as_url))
            if req.method == "GET"
            and str(req.url).rstrip("/") == f"{base}/.well-known/oauth-protected-resource"
            else httpx.Response(200, json=_good_as_meta(as_url))
            if req.method == "GET"
            and str(req.url).rstrip("/") == f"{as_url}/.well-known/oauth-authorization-server"
            else counting_register(req)
            if req.method == "POST" and str(req.url).rstrip("/") == f"{as_url}/register"
            else httpx.Response(404)
        )
    )
    client = httpx.AsyncClient(transport=transport)
    findings = await scan(base, http_client=client)
    await client.aclose()
    assert register_calls["count"] == 0, "DCR mirror should be skipped by default"
    assert not any(f.check_id == "MCP-DCR-MIRROR-001" for f in findings)


# ---- Output formatters ----------------------------------------------------


def _sample_findings() -> list[Finding]:
    return [
        Finding(
            check_id="MCP-PKCE-001",
            severity="critical",
            title="PKCE missing",
            detail="no S256",
            spec_link="https://example/spec",
            remediation="add S256",
        ),
        Finding(
            check_id="MCP-DCR-001",
            severity="warning",
            title="DCR missing",
            detail="register endpoint absent",
            spec_link="https://example/dcr",
            remediation="add /register",
        ),
    ]


def test_format_human_includes_severity_and_remediation():
    out = format_human(_sample_findings())
    assert "[CRITICAL]" in out
    assert "[WARNING]" in out
    assert "add S256" in out


def test_format_json_round_trips():
    out = format_json(_sample_findings())
    parsed = json.loads(out)
    assert len(parsed) == 2
    assert parsed[0]["check_id"] == "MCP-PKCE-001"


def test_format_github_uses_workflow_commands():
    out = format_github(_sample_findings())
    assert "::error::" in out
    assert "::warning::" in out


def test_clean_findings_format_human_is_concise():
    assert format_human([]) == "✓ No findings."


# --- MCP-PKCE-002 PKCE-drift probe -----------------------------------------


@pytest.mark.asyncio
async def test_pkce_drift_clean_when_method_called_out_in_response(scanner_client):
    """If the AS rejects ``plain`` and explicitly mentions the method in
    its error body, we treat that as enforcement and emit no finding."""
    from authgent_server.scanner import check_pkce_drift

    as_meta = {
        "authorization_endpoint": "http://as.example/authorize",
        "code_challenge_methods_supported": ["S256"],
    }
    body = "error=invalid_request: unsupported code_challenge_method 'plain'"
    routes = {("GET", "http://as.example/authorize"): httpx.Response(400, text=body)}
    client = scanner_client(routes)
    out = await check_pkce_drift(client, as_meta)
    assert out == []


@pytest.mark.asyncio
async def test_pkce_drift_fires_when_method_silently_ignored(scanner_client):
    """If the AS redirects without naming the method in its error, we
    surface a drift finding (the Obsidian Jan 2026 pattern)."""
    from authgent_server.scanner import check_pkce_drift

    as_meta = {
        "authorization_endpoint": "http://as.example/authorize",
        "code_challenge_methods_supported": ["S256"],
    }
    # The strongest drift signal: server redirects back to the redirect_uri
    # with no error at all, meaning it accepted code_challenge_method=plain.
    # The Obsidian Jan 2026 disclosure showed exactly this shape.
    routes = {
        ("GET", "http://as.example/authorize"): httpx.Response(
            302,
            headers={
                "location": "https://authgent.dev/lint-probe?code=fake_auth_code&state=lintprobe"
            },
        )
    }
    client = scanner_client(routes)
    out = await check_pkce_drift(client, as_meta)
    assert any(f.check_id == "MCP-PKCE-002" for f in out)


@pytest.mark.asyncio
async def test_pkce_drift_suppressed_on_invalid_client(scanner_client):
    """P0-4: Auth0/Okta/Keycloak validate client_id BEFORE PKCE. They
    return invalid_client to our unregistered probe, which is correct
    behavior. Don't flag those as drift — that produces a wave of
    false-positives from exactly the vendors we need on our side."""
    from authgent_server.scanner import check_pkce_drift

    as_meta = {
        "authorization_endpoint": "http://as.example/authorize",
        "code_challenge_methods_supported": ["S256"],
    }
    routes = {
        ("GET", "http://as.example/authorize"): httpx.Response(
            302,
            headers={
                "location": "https://authgent.dev/lint-probe?error=invalid_client&error_description=Unknown+client"
            },
        )
    }
    client = scanner_client(routes)
    out = await check_pkce_drift(client, as_meta)
    assert out == [], f"invalid_client response should suppress, got {out}"


@pytest.mark.asyncio
async def test_pkce_drift_suppressed_on_unauthorized_client(scanner_client):
    """Same protection for unauthorized_client and invalid_redirect_uri."""
    from authgent_server.scanner import check_pkce_drift

    as_meta = {
        "authorization_endpoint": "http://as.example/authorize",
        "code_challenge_methods_supported": ["S256"],
    }
    routes = {
        ("GET", "http://as.example/authorize"): httpx.Response(
            400, text='{"error":"unauthorized_client","error_description":"Client not registered"}'
        )
    }
    client = scanner_client(routes)
    out = await check_pkce_drift(client, as_meta)
    assert out == []


@pytest.mark.asyncio
async def test_pkce_drift_skipped_when_plain_already_advertised(scanner_client):
    """If the AS advertises ``plain``, MCP-PKCE-001 fires and the drift
    probe is redundant — skip it."""
    from authgent_server.scanner import check_pkce_drift

    as_meta = {
        "authorization_endpoint": "http://as.example/authorize",
        "code_challenge_methods_supported": ["S256", "plain"],
    }
    routes: dict = {}
    client = scanner_client(routes)
    out = await check_pkce_drift(client, as_meta)
    assert out == []
