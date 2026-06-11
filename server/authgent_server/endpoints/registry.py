"""GET /api/registry — public MCP-OAuth registry.

A curated list of public MCP servers, scanned nightly, ranked A-F. This
is the inbound-link generator: each row links to a permalink scan report
and an embeddable SVG badge.

Operational model
-----------------
- The list of curated targets lives in :data:`_REGISTRY_TARGETS` below.
  Editing the list requires a server restart; that's deliberate so the
  list isn't user-mutable.
- Results are cached in process memory keyed by URL with a 1-hour TTL.
  A ``GET /api/registry`` triggers a refresh of stale entries on demand
  (lazy refresh — no background thread, no scheduler dependency).
- Each cache entry stores ``grade``, ``score``, ``finding_count``,
  ``last_scanned``, plus the headline finding for at-a-glance display.
- The endpoint never blocks on slow targets: per-target scans have a
  2-second budget; on timeout the cached value (or "Pending") is
  returned. Render-then-refresh is the user experience, not wait-then-render.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, HTTPException, Query

from authgent_server.endpoints.scan import _grade, _is_safe_url
from authgent_server.scanner import Finding, scan

router = APIRouter(tags=["registry"])


# Curated list of public MCP servers worth tracking. Sourced from the public
# modelcontextprotocol/servers org, the awesome-mcp lists, vendor announcements,
# and direct ToS-checked browsing. Each entry is the well-known *resource*
# URL (the one MCP clients point at), not the OAuth issuer.
#
# Per-entry fields:
# - ``name``, ``url``, ``vendor`` — display data.
# - ``embargo_until`` (optional ISO-8601 date): if set and in the future,
#   the registry shows the entry as "Pending — vendor notified YYYY-MM-DD"
#   and does not publish the grade. This implements the SSL-Labs / Obsidian-
#   style 14-day responsible-disclosure window.
# - ``opted_out`` (optional bool): if true, the entry is hidden entirely.
#   Vendors who don't want to be listed can email
#   security@authgent.dev with the URL; we set this flag.
_REGISTRY_TARGETS: list[dict[str, object]] = [
    # NOTE: authgent's own demo deployment is deliberately NOT in this list.
    # A registry that grades its own author A while everyone else gets D/F is
    # not a credible public good. We test against the demo via the calibration
    # suite instead (server/tests/test_calibration.py) so the dogfooding
    # signal is preserved in CI, not in the user-facing scoreboard.
    {"name": "Stripe MCP", "url": "https://access.stripe.com/mcp", "vendor": "Stripe"},
    {"name": "Notion MCP", "url": "https://mcp.notion.com", "vendor": "Notion"},
    {
        "name": "Atlassian MCP",
        "url": "https://mcp.atlassian.com",
        "vendor": "Atlassian",
    },
    {
        "name": "Cloudflare MCP",
        "url": "https://mcp.cloudflare.com",
        "vendor": "Cloudflare",
    },
    {"name": "Linear MCP", "url": "https://mcp.linear.app", "vendor": "Linear"},
    {"name": "Descope MCP", "url": "https://mcp.descope.com", "vendor": "Descope"},
    # P1-5 expansion (June 2026): notable additional MCP servers from the
    # public modelcontextprotocol/servers org, vendor announcements, and
    # awesome-mcp lists. Each URL is the well-known resource endpoint MCP
    # clients connect to.
    {"name": "GitHub MCP", "url": "https://api.github.com/mcp", "vendor": "GitHub"},
    {"name": "Asana MCP", "url": "https://mcp.asana.com", "vendor": "Asana"},
    {"name": "Intercom MCP", "url": "https://mcp.intercom.com", "vendor": "Intercom"},
    {"name": "Plaid MCP", "url": "https://mcp.plaid.com", "vendor": "Plaid"},
    {"name": "Square MCP", "url": "https://mcp.squareup.com", "vendor": "Square"},
    {
        "name": "PayPal MCP",
        "url": "https://mcp-server.paypal.com",
        "vendor": "PayPal",
    },
    {"name": "Sentry MCP", "url": "https://mcp.sentry.dev", "vendor": "Sentry"},
    {
        "name": "PagerDuty MCP",
        "url": "https://mcp.pagerduty.com",
        "vendor": "PagerDuty",
    },
    {"name": "Workato MCP", "url": "https://mcp.workato.com", "vendor": "Workato"},
    {"name": "Box MCP", "url": "https://mcp.box.com", "vendor": "Box"},
    {"name": "HubSpot MCP", "url": "https://mcp.hubspot.com", "vendor": "HubSpot"},
    {"name": "Zapier MCP", "url": "https://mcp.zapier.com", "vendor": "Zapier"},
]


def _is_embargoed(target: dict[str, object]) -> bool:
    """True if the target is still inside its disclosure-window embargo."""
    embargo = target.get("embargo_until")
    if not isinstance(embargo, str):
        return False
    try:
        deadline = datetime.fromisoformat(embargo.replace("Z", "+00:00"))
    except ValueError:
        return False
    if deadline.tzinfo is None:
        deadline = deadline.replace(tzinfo=UTC)
    return datetime.now(UTC) < deadline


def _visible_targets() -> list[dict[str, object]]:
    """Drop opted-out entries; embargoed entries stay but display as pending."""
    return [t for t in _REGISTRY_TARGETS if not t.get("opted_out", False)]


@dataclass
class _CacheEntry:
    grade: str
    score: int
    blocking: bool
    finding_count: int
    headline_finding: dict[str, Any] | None
    last_scanned: float
    findings: list[dict[str, Any]] = field(default_factory=list)


_cache: dict[str, _CacheEntry] = {}
_CACHE_TTL_SECONDS = 3600
# Tight enough that one slow target can't DOS the registry, generous enough
# that cold DNS + TLS + 3 round trips on a real vendor (typically 6-8s)
# completes. Was 4s; bumped for the P1 timeout fix.
_PER_TARGET_TIMEOUT = 12.0


async def _scan_one(url: str) -> _CacheEntry | None:
    """Scan a single target with a tight timeout. Returns None on failure."""
    try:
        findings = await asyncio.wait_for(scan(url), timeout=_PER_TARGET_TIMEOUT)
    except (TimeoutError, Exception):
        return None
    grade, score = _grade(findings)
    blocking = any(f.severity in ("error", "critical") for f in findings)
    headline: dict[str, Any] | None = None
    for sev in ("critical", "error", "warning", "info"):
        match = next((f for f in findings if f.severity == sev), None)
        if match:
            headline = {
                "check_id": match.check_id,
                "severity": match.severity,
                "title": match.title,
            }
            break
    return _CacheEntry(
        grade=grade,
        score=score,
        blocking=blocking,
        finding_count=len(findings),
        headline_finding=headline,
        last_scanned=time.time(),
        findings=[_finding_dict(f) for f in findings],
    )


def _finding_dict(f: Finding) -> dict[str, Any]:
    return {
        "check_id": f.check_id,
        "severity": f.severity,
        "title": f.title,
        "detail": f.detail,
        "spec_link": f.spec_link,
        "remediation": f.remediation,
    }


def _is_stale(entry: _CacheEntry) -> bool:
    return (time.time() - entry.last_scanned) > _CACHE_TTL_SECONDS


def _serialize_entry(target: dict[str, object], entry: _CacheEntry | None) -> dict[str, Any]:
    base: dict[str, Any] = {
        "name": target["name"],
        "url": target["url"],
        "vendor": target["vendor"],
    }
    # Embargoed entries are listed but not graded. The headline tells
    # readers the vendor was notified and gives the disclosure date.
    if _is_embargoed(target):
        base.update(
            {
                "grade": None,
                "score": None,
                "blocking": None,
                "finding_count": None,
                "headline_finding": {
                    "check_id": "EMBARGO",
                    "severity": "info",
                    "title": f"Vendor notified · grade publishes {target.get('embargo_until')}",
                },
                "last_scanned": None,
                "last_scanned_iso": None,
                "status": "embargoed",
                "embargo_until": target.get("embargo_until"),
            }
        )
        return base
    if entry is None:
        base.update(
            {
                "grade": None,
                "score": None,
                "blocking": None,
                "finding_count": None,
                "headline_finding": None,
                "last_scanned": None,
                "last_scanned_iso": None,
                "status": "pending",
            }
        )
    else:
        base.update(
            {
                "grade": entry.grade,
                "score": entry.score,
                "blocking": entry.blocking,
                "finding_count": entry.finding_count,
                "headline_finding": entry.headline_finding,
                "last_scanned": int(entry.last_scanned),
                "last_scanned_iso": datetime.fromtimestamp(entry.last_scanned, tz=UTC).isoformat(),
                "status": "ok",
            }
        )
    return base


@router.get("/api/registry")
async def registry_endpoint(
    refresh: bool = Query(
        False,
        description="If true, force a re-scan of stale entries. "
        "If false, return cached values where available.",
    ),
) -> dict[str, Any]:
    """Return the registry table.

    On first hit (cold cache), kicks off a parallel scan of every target
    with a tight per-target timeout and returns whatever finishes within
    a small overall budget. Subsequent calls within the TTL return the
    cached snapshot instantly.
    """
    visible = _visible_targets()
    targets_to_scan = [
        t
        for t in visible
        if not _is_embargoed(t)
        and (str(t["url"]) not in _cache or (refresh and _is_stale(_cache[str(t["url"])])))
    ]

    if targets_to_scan:
        tasks = [_scan_one(str(t["url"])) for t in targets_to_scan]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for target, result in zip(targets_to_scan, results, strict=True):
            if isinstance(result, _CacheEntry):
                _cache[str(target["url"])] = result

    rows = [_serialize_entry(t, _cache.get(str(t["url"]))) for t in visible]

    grade_counts: dict[str, int] = {}
    for r in rows:
        g = r["grade"]
        if g:
            grade_counts[g] = grade_counts.get(g, 0) + 1

    return {
        "total": len(rows),
        "scanned": sum(1 for r in rows if r["status"] == "ok"),
        "embargoed": sum(1 for r in rows if r["status"] == "embargoed"),
        "grade_counts": grade_counts,
        "rows": rows,
        "cache_ttl_seconds": _CACHE_TTL_SECONDS,
        "generated_at": datetime.now(UTC).isoformat(),
        "disclosure_policy_url": (
            "https://github.com/authgent/authgent/blob/main/docs/disclosure-policy.md"
        ),
    }


@router.get("/api/registry/{vendor_or_name}")
async def registry_detail(vendor_or_name: str) -> dict[str, Any]:
    """Return the detailed scan for a single registry entry, by vendor
    or display-name (URL-safe slug).
    """
    needle = vendor_or_name.lower().replace("-", " ")
    target = next(
        (
            t
            for t in _visible_targets()
            if str(t["vendor"]).lower() == needle or str(t["name"]).lower() == needle
        ),
        None,
    )
    if target is None:
        raise HTTPException(status_code=404, detail=f"Not in registry: {vendor_or_name}")

    if _is_embargoed(target):
        return _serialize_entry(target, None)

    url = str(target["url"])
    if url not in _cache or _is_stale(_cache[url]):
        result = await _scan_one(url)
        if result is not None:
            _cache[url] = result

    entry = _cache.get(url)
    base = _serialize_entry(target, entry)
    if entry is not None:
        base["findings"] = entry.findings
    return base


@router.get("/api/scan/cached")
async def scan_cached(
    url: str = Query(..., description="MCP server URL to look up", max_length=2048),
) -> dict[str, Any]:
    """Return the most recent cached scan for ``url``, scanning fresh if
    not yet cached. Same semantics as ``/api/scan`` but cheap on repeat
    calls — designed for the registry-detail UI to use without re-running
    the scanner on every page load.
    """
    if not _is_safe_url(url):
        raise HTTPException(
            status_code=400,
            detail="url must be an http(s) URL pointing at a public host",
        )
    entry = _cache.get(url)
    if entry is None or _is_stale(entry):
        result = await _scan_one(url)
        if result is not None:
            _cache[url] = result
            entry = result
    if entry is None:
        raise HTTPException(status_code=502, detail="Scanner failed to reach target")
    return {
        "url": url,
        "grade": entry.grade,
        "score": entry.score,
        "blocking": entry.blocking,
        "finding_count": entry.finding_count,
        "findings": entry.findings,
        "last_scanned": int(entry.last_scanned),
        "last_scanned_iso": datetime.fromtimestamp(entry.last_scanned, tz=UTC).isoformat(),
    }
