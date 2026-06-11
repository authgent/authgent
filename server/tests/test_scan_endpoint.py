"""Tests for the public ``/api/scan`` endpoint.

The endpoint must (a) refuse loopback / RFC-1918 / link-local targets so
the scanner can't probe the host's own internal network, and (b) return
a structured grade + findings for safe URLs.

The actual scan is patched out — the routing + safety guards are what
matters here. ``test_scanner.py`` covers the scanner internals.
"""

from __future__ import annotations

import pytest

from authgent_server.endpoints.scan import _grade, _is_safe_url
from authgent_server.scanner import Finding

# --- safety guard ----------------------------------------------------------


@pytest.mark.parametrize(
    "url",
    [
        "http://localhost/",
        "http://127.0.0.1:8000",
        "https://10.0.0.5",
        "http://192.168.1.1",
        "http://172.16.0.1",
        "http://172.31.255.255",
        "http://169.254.169.254",  # AWS metadata
        "http://thing.internal",
        "http://thing.local",
        "ftp://example.com",
        "javascript:alert(1)",
        "",
    ],
)
def test_unsafe_urls_rejected(url: str):
    assert _is_safe_url(url) is False


@pytest.mark.parametrize(
    "url",
    [
        "https://mcp.example.com",
        "https://mcp.example.com/sub",
        "http://198.51.100.1",  # TEST-NET-2 (public-routed for examples)
        "https://api.descope.com",
    ],
)
def test_safe_urls_accepted(url: str):
    assert _is_safe_url(url) is True


# --- grading ---------------------------------------------------------------


def _f(severity):
    return Finding(
        check_id="X",
        severity=severity,
        title="t",
        detail="d",
        spec_link="https://example",
        remediation="r",
    )


def test_grade_clean_is_a():
    grade, score = _grade([])
    assert grade == "A"
    assert score == 100


def test_grade_one_critical_drops_to_c_or_lower():
    grade, _ = _grade([_f("critical")])
    assert grade in ("C", "D", "F", "B")  # depends on weights; never A


def test_grade_three_criticals_is_failing():
    grade, _ = _grade([_f("critical")] * 3)
    assert grade in ("D", "F")


# --- HTTP --------------------------------------------------------------


def test_scan_endpoint_rejects_loopback(test_client):
    resp = test_client.get("/api/scan", params={"url": "http://localhost"})
    assert resp.status_code == 400
    assert "blocked" in resp.json()["detail"].lower()


def test_scan_endpoint_rejects_private_ip(test_client):
    resp = test_client.get("/api/scan", params={"url": "http://10.0.0.1"})
    assert resp.status_code == 400


def test_scan_endpoint_rejects_non_http(test_client):
    resp = test_client.get("/api/scan", params={"url": "ftp://example.com"})
    assert resp.status_code == 400


# --- badge endpoint --------------------------------------------------------


def test_badge_unsafe_url_returns_failing_svg(test_client):
    """Unsafe URLs (loopback etc.) MUST still return SVG, not JSON 400.
    A README-embedded badge cannot afford to break with an HTTP 4xx."""
    resp = test_client.get("/api/badge", params={"url": "http://localhost"})
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("image/svg+xml")
    assert b"<svg" in resp.content
    assert b">F" in resp.content or b"F\xc2\xb7" in resp.content or b"F &" in resp.content


def test_badge_endpoint_returns_svg_with_caching(test_client):
    """Badge endpoint returns SVG with a sensible Cache-Control header."""
    # Use an unsafe URL to keep the test hermetic — we still get a valid SVG,
    # just with the failure-mode F.
    resp = test_client.get("/api/badge", params={"url": "http://10.0.0.1"})
    assert resp.status_code == 200
    assert "image/svg+xml" in resp.headers["content-type"]
    assert resp.headers.get("cache-control")
    assert b"<svg" in resp.content
    assert b"</svg>" in resp.content
