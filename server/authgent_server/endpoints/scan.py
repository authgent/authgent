"""GET /api/scan — public MCP-OAuth conformance scanner endpoint.

Wraps :func:`authgent_server.scanner.scan` so the static GitHub Pages
``/scan`` page can call it without bundling the scanner. Stateless;
no DB writes; safe to expose publicly. Per-IP rate limiting is provided
by the existing :class:`RateLimitMiddleware`.
"""

from __future__ import annotations

from dataclasses import asdict
from typing import Literal
from urllib.parse import urlparse

from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import Response
from pydantic import BaseModel

from authgent_server.scanner import (
    Finding,
    has_blocking,
    scan,
)

router = APIRouter(tags=["scan"])


class ScanResponse(BaseModel):
    target: str
    grade: Literal["A", "B", "C", "D", "F"]
    score: int  # 0-100
    blocking: bool
    finding_count: int
    findings: list[dict]


def _grade(findings: list[Finding]) -> tuple[str, int]:
    """Compute a letter grade and 0-100 score from findings.

    A single ``critical`` finding (e.g. PRM missing entirely) drops the
    server below D — those are spec-fatal failures that mean MCP clients
    cannot use the target as an authorization-protected resource at all.
    """
    weight = {"info": 1, "warning": 5, "error": 15, "critical": 50}
    penalty = sum(weight.get(f.severity, 5) for f in findings)
    score = max(0, 100 - penalty)
    if score >= 95:
        return "A", score
    if score >= 85:
        return "B", score
    if score >= 70:
        return "C", score
    if score >= 50:
        return "D", score
    return "F", score


def _is_safe_url(url: str) -> bool:
    """Reject URLs that target the Oracle host's own internal network.

    The scanner makes outbound HTTP. If a visitor pastes
    ``http://localhost`` / ``127.0.0.1`` / a private IP, the scanner would
    probe authgent's own internal services. Block those.
    """
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        return False
    host = (parsed.hostname or "").lower()
    if not host:
        return False
    blocked_hosts = {"localhost", "0.0.0.0", "::1"}
    if host in blocked_hosts:
        return False
    if host.startswith("127.") or host.startswith("169.254."):
        return False
    if host.startswith("10.") or host.startswith("192.168."):
        return False
    if host.startswith("172.") and len(host.split(".")) > 1:
        try:
            second = int(host.split(".")[1])
            if 16 <= second <= 31:
                return False
        except ValueError:
            pass
    if host.endswith(".internal") or host.endswith(".local"):
        return False
    return True


@router.get("/api/scan", response_model=ScanResponse)
async def scan_endpoint(
    url: str = Query(
        ...,
        description="MCP server base URL to audit, e.g. https://mcp.example.com",
        max_length=2048,
    ),
) -> ScanResponse:
    """Run the MCP-OAuth conformance scanner against ``url`` and return JSON."""
    if not _is_safe_url(url):
        raise HTTPException(
            status_code=400,
            detail=(
                "url must be an http(s) URL pointing at a public host. "
                "Loopback, link-local, and RFC 1918 addresses are blocked."
            ),
        )
    try:
        findings = await scan(url)
    except Exception as exc:  # noqa: BLE001 — surface a friendly error
        raise HTTPException(
            status_code=502,
            detail=f"Scanner failed: {exc}",
        ) from exc

    grade, score = _grade(findings)
    return ScanResponse(
        target=url,
        grade=grade,  # type: ignore[arg-type]
        score=score,
        blocking=has_blocking(findings),
        finding_count=len(findings),
        findings=[asdict(f) for f in findings],
    )


# Shields.io-style colors so the badge fits in any README palette.
_GRADE_COLOR = {
    "A": "#10b981",  # emerald
    "B": "#14b8a6",  # teal
    "C": "#f59e0b",  # amber
    "D": "#f97316",  # orange
    "F": "#ef4444",  # red
}


def _svg_badge(grade: str, score: int) -> str:
    """Render a shields.io-style two-section SVG badge.

    Pure-python with hand-tuned widths so we don't pull in a dependency.
    Returned bytes are cacheable for an hour at the CDN edge by the
    caller's response headers.
    """
    color = _GRADE_COLOR.get(grade, "#71717a")
    label = "MCP-OAuth"
    label_w = 78
    value = f"{grade} · {score}"
    value_w = 70
    total_w = label_w + value_w
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{total_w}" height="20" '
        f'role="img" aria-label="{label}: {value}">'
        '<linearGradient id="s" x2="0" y2="100%">'
        '<stop offset="0" stop-color="#bbb" stop-opacity=".1"/>'
        '<stop offset="1" stop-opacity=".1"/></linearGradient>'
        '<clipPath id="r"><rect width="' + str(total_w) + '" height="20" rx="3"/></clipPath>'
        '<g clip-path="url(#r)">'
        f'<rect width="{label_w}" height="20" fill="#27272a"/>'
        f'<rect x="{label_w}" width="{value_w}" height="20" fill="{color}"/>'
        f'<rect width="{total_w}" height="20" fill="url(#s)"/></g>'
        '<g fill="#fff" text-anchor="middle" '
        'font-family="Verdana,Geneva,DejaVu Sans,sans-serif" '
        'text-rendering="geometricPrecision" font-size="110">'
        f'<text x="{label_w * 5}" y="150" transform="scale(.1)" '
        f'fill="#000" fill-opacity=".25" textLength="{(label_w - 10) * 10}">{label}</text>'
        f'<text x="{label_w * 5}" y="140" transform="scale(.1)" '
        f'textLength="{(label_w - 10) * 10}">{label}</text>'
        f'<text x="{(label_w + value_w / 2) * 10}" y="150" transform="scale(.1)" '
        f'fill="#000" fill-opacity=".25" textLength="{(value_w - 10) * 10}">{value}</text>'
        f'<text x="{(label_w + value_w / 2) * 10}" y="140" transform="scale(.1)" '
        f'textLength="{(value_w - 10) * 10}">{value}</text></g></svg>'
    )


@router.get("/api/badge")
async def scan_badge(
    url: str = Query(..., description="MCP server URL to grade", max_length=2048),
) -> Response:
    """Return an SVG shield badge with the target's MCP-OAuth grade.

    Designed to be embedded as ``![](https://.../api/badge?url=...)`` in
    an MCP server's README. Cached for 5 minutes to keep load bounded.
    """
    if not _is_safe_url(url):
        return Response(
            content=_svg_badge("F", 0),
            media_type="image/svg+xml",
            headers={"Cache-Control": "public, max-age=60"},
        )
    try:
        findings = await scan(url)
        grade, score = _grade(findings)
    except Exception:  # noqa: BLE001 — never 500 on a badge endpoint
        grade, score = "F", 0
    return Response(
        content=_svg_badge(grade, score),
        media_type="image/svg+xml",
        headers={"Cache-Control": "public, max-age=300"},
    )
