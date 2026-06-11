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
    """Compute a letter grade and 0-100 score from findings."""
    weight = {"info": 1, "warning": 5, "critical": 25, "error": 15}
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
