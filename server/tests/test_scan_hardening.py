"""Hardening tests for the public scanner surfaces.

These tests cover the launch-day fixes:

1. Per-IP rate limiting on /api/scan and /api/badge stops burst abuse.
2. The global semaphore + outer wait_for caps event-loop saturation
   from slow targets.
3. The PKCE-Drift paper (docs/attacks/pkce-drift.md) exists and is
   linked from the MCP-PKCE-002 finding the scanner emits, so the
   named-class explanation is one click away from any failed scan.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

# ── 1. Rate limiting ────────────────────────────────────────────────────────


def test_scan_endpoint_rate_limit_returns_429(test_client: TestClient, monkeypatch):
    """Burst /api/scan past the configured cap and expect 429.

    We patch the bounded scan to return immediately so the test doesn't
    spend time on outbound HTTP — the path through the rate-limit
    middleware is what matters.
    """

    async def _fake_scan(url, *, timeout, probe_registrations):
        return []

    monkeypatch.setattr("authgent_server.endpoints.scan._bounded_scan", _fake_scan)
    # Default scan_rate_limit is 30/min. 35 hits over the window must
    # surface at least one 429.
    statuses = []
    for _ in range(35):
        resp = test_client.get("/api/scan", params={"url": "https://mcp.example.com"})
        statuses.append(resp.status_code)
    assert 429 in statuses, f"expected at least one 429, got {sorted(set(statuses))}"


def test_badge_endpoint_rate_limit_separate_from_scan(test_client: TestClient, monkeypatch):
    """The badge bucket is independent and higher (default 120/min) so
    README-embedded badges keep working under HN-scale load even when
    /api/scan is throttling individual interactive sessions."""

    async def _fake_scan(url, *, timeout, probe_registrations):
        return []

    monkeypatch.setattr("authgent_server.endpoints.scan._bounded_scan", _fake_scan)
    # 50 hits should be well under the 120/min badge cap.
    for _ in range(50):
        resp = test_client.get("/api/badge", params={"url": "https://mcp.example.com"})
        assert resp.status_code == 200


# ── 2. Outer wait_for + concurrency semaphore ───────────────────────────────


@pytest.mark.asyncio
async def test_bounded_scan_raises_timeout_error_on_slow_target():
    """The outer wait_for MUST cancel a slow scan rather than tying up
    a worker indefinitely. Without this, one packet-dropping target
    saturates one event-loop slot for the full HTTP server timeout."""
    from authgent_server.endpoints.scan import _bounded_scan

    async def _slow(*args, **kwargs):
        await asyncio.sleep(60)
        return []

    with patch("authgent_server.endpoints.scan.scan", _slow):
        with pytest.raises((TimeoutError, asyncio.TimeoutError)):
            await _bounded_scan(
                "https://mcp.example.com",
                timeout=0.05,
                probe_registrations=False,
            )


def test_scan_endpoint_returns_504_on_timeout(test_client: TestClient, monkeypatch):
    """A slow target must surface as 504 to the caller, not a hung
    connection. /api/badge degrades to F-grade SVG; /api/scan returns
    a structured error so the UI can render 'try again' rather than
    spinning."""

    async def _hang(url, *, timeout, probe_registrations):
        raise TimeoutError()

    monkeypatch.setattr("authgent_server.endpoints.scan._bounded_scan", _hang)
    resp = test_client.get("/api/scan", params={"url": "https://mcp.example.com"})
    assert resp.status_code == 504
    assert "timed out" in resp.json()["detail"].lower()


def test_badge_endpoint_degrades_to_failing_svg_on_timeout(test_client: TestClient, monkeypatch):
    """Badge endpoints embed in READMEs; we cannot afford a 5xx. A
    timeout maps to F-grade so the badge still renders something."""

    async def _hang(url, *, timeout, probe_registrations):
        raise TimeoutError()

    monkeypatch.setattr("authgent_server.endpoints.scan._bounded_scan", _hang)
    resp = test_client.get("/api/badge", params={"url": "https://mcp.example.com"})
    assert resp.status_code == 200
    assert "image/svg+xml" in resp.headers["content-type"]
    assert b"<svg" in resp.content


# ── 3. PKCE-Drift named-class paper ────────────────────────────────────────


def test_pkce_drift_paper_exists():
    """The PKCE-advertise-drift explainer MUST live in the repo so the
    scanner finding can link to it. The scanner emits a link to this file
    in its detail string; if the file is missing or moved, the link is
    dead."""
    paper = Path(__file__).resolve().parents[2] / "docs" / "attacks" / "pkce-drift.md"
    assert paper.exists(), f"PKCE advertise-drift paper missing at {paper}"
    text = paper.read_text()
    # Sanity-check the load-bearing identifiers the README + scanner reference.
    assert "MCP-PKCE-002" in text
    assert "CWE-757" in text
    # Prior-art citations must be present — the scanner finding cites
    # them by name, and the disclosure policy depends on them being one
    # click away from the finding.
    assert "OAuch" in text or "BCP_4_8" in text
    assert "GHSA-9h47-pqcx-hjr4" in text or "Better-Auth" in text


def test_pkce_002_finding_references_paper_and_prior_art():
    """The scanner's MCP-PKCE-002 finding MUST link to the paper and
    cite the prior-art family the check belongs to. This is the contract
    between the runtime check and the named-class catalog."""
    # Inspect the source so we don't have to drive a full scan to assert.
    import inspect

    from authgent_server import scanner as scanner_mod
    from authgent_server.scanner import Finding, check_pkce_drift  # noqa: F401

    src = inspect.getsource(scanner_mod.check_pkce_drift)
    assert "pkce-drift.md" in src, "MCP-PKCE-002 finding must link to docs/attacks/pkce-drift.md"
    # The finding must cite *some* prior-art anchor so the scanner output
    # itself doesn't read as an originality claim.
    assert any(anchor in src for anchor in ("OAuch", "BCP_4_8", "GHSA", "PKCE-downgrade")), (
        "Finding text must cite the parent PKCE-downgrade family"
    )
