"""authgent lint — MCP-OAuth conformance scanner.

A single-binary lint tool that audits a remote MCP server's authorization
posture. Each check maps to a known CVE-class issue or a normative spec
requirement. Designed to be runnable in CI via the GitHub Action wrapper
in ``.github/actions/mcp-lint``.

Outputs:
- ``human`` — Rich-formatted table for terminals.
- ``json`` — machine-readable list of findings (for piping into other
  tools or storing as artifacts).
- ``github`` — GitHub Actions workflow-command annotations
  (``::error file=...``) so failed checks surface in PR review.

Each check returns a :class:`Finding`. The CLI exits non-zero when any
finding has severity ``error`` or higher.
"""

from __future__ import annotations

import asyncio
import json
import sys
from dataclasses import asdict, dataclass, field
from typing import Literal
from urllib.parse import urljoin, urlparse

import httpx

Severity = Literal["info", "warning", "error", "critical"]

# Whether a finding affects the letter grade.
#
# - ``spec_required``: a NORMATIVE requirement of the MCP 2025-11-25 /
#   2026-07-28 authorization spec, OAuth 2.1, or a cited RFC. These
#   findings drive the A-F grade.
# - ``advisory``: a best-practice (e.g. DPoP-by-default) that improves
#   posture but is not a 2026-spec requirement. Surfaced in the report
#   but does NOT affect the letter grade. This is what stops a legacy
#   IdP from grading D before it ships MCP support.
Tier = Literal["spec_required", "advisory"]


@dataclass
class Finding:
    check_id: str
    severity: Severity
    title: str
    detail: str
    spec_link: str
    remediation: str
    tier: Tier = "spec_required"
    extra: dict[str, object] = field(default_factory=dict)


# --- HTTP helpers -----------------------------------------------------------


async def _get_json(client: httpx.AsyncClient, url: str) -> tuple[int, dict | None, dict]:
    """GET ``url``, return (status, parsed-json-or-None, headers)."""
    try:
        resp = await client.get(url, follow_redirects=False, timeout=10.0)
    except httpx.HTTPError as exc:
        return 0, None, {"_error": str(exc)}
    try:
        body = resp.json()
    except ValueError:
        body = None
    return resp.status_code, body, dict(resp.headers)


# --- Individual checks ------------------------------------------------------
# Each function takes an MCP-resource base URL and the AS metadata it points
# at, and returns a list of findings. A check returns the empty list when it
# detects no problems.


async def check_protected_resource_metadata(
    client: httpx.AsyncClient, base_url: str
) -> tuple[list[Finding], dict | None]:
    """MCP-PRM-001: RFC 9728 PRM endpoint MUST exist and be well-formed.

    PRM is the discovery gate; MCP clients require it to find the
    authorization server. Treat its absence as ``critical`` so the score
    reflects "this is not actually an MCP server" rather than "this MCP
    server has one missing field".
    """
    url = urljoin(base_url + "/", ".well-known/oauth-protected-resource")
    status, body, _ = await _get_json(client, url)
    findings: list[Finding] = []
    if status != 200 or not isinstance(body, dict):
        findings.append(
            Finding(
                check_id="MCP-PRM-001",
                severity="critical",
                title="Missing or malformed Protected Resource Metadata",
                detail=(
                    f"GET {url} returned {status}. MCP clients require RFC 9728 "
                    "metadata to discover the authorization server. Without "
                    "this endpoint a target is not a valid MCP server per the "
                    "2025-11-25 / 2026-07-28 spec."
                ),
                spec_link="https://datatracker.ietf.org/doc/html/rfc9728",
                remediation=(
                    "Expose /.well-known/oauth-protected-resource returning "
                    "{ resource, authorization_servers, scopes_supported }."
                ),
            )
        )
        return findings, None
    for required in ("resource", "authorization_servers"):
        if required not in body:
            findings.append(
                Finding(
                    check_id="MCP-PRM-001",
                    severity="error",
                    title=f"PRM missing '{required}' field",
                    detail=f"GET {url} returned a JSON object without '{required}'.",
                    spec_link="https://datatracker.ietf.org/doc/html/rfc9728#section-2",
                    remediation=f"Include '{required}' in the PRM response.",
                )
            )
    return findings, body


async def check_as_metadata(
    client: httpx.AsyncClient, as_url: str
) -> tuple[list[Finding], dict | None]:
    """MCP-AS-001: RFC 8414 AS metadata MUST exist."""
    url = urljoin(as_url.rstrip("/") + "/", ".well-known/oauth-authorization-server")
    status, body, _ = await _get_json(client, url)
    findings: list[Finding] = []
    if status != 200 or not isinstance(body, dict):
        findings.append(
            Finding(
                check_id="MCP-AS-001",
                severity="error",
                title="Missing Authorization Server Metadata",
                detail=f"GET {url} returned {status}.",
                spec_link="https://datatracker.ietf.org/doc/html/rfc8414",
                remediation=(
                    "Expose /.well-known/oauth-authorization-server with "
                    "issuer, token_endpoint, authorization_endpoint, "
                    "jwks_uri, code_challenge_methods_supported."
                ),
            )
        )
        return findings, None

    return findings, body


def check_pkce(as_meta: dict) -> list[Finding]:
    """MCP-PKCE-001: PKCE S256 MUST be advertised; ``plain`` is forbidden."""
    methods = as_meta.get("code_challenge_methods_supported", []) or []
    findings: list[Finding] = []
    if "S256" not in methods:
        findings.append(
            Finding(
                check_id="MCP-PKCE-001",
                severity="critical",
                title="PKCE S256 not advertised",
                detail=(
                    "MCP 2025-11-25 requires clients to enforce PKCE with S256. "
                    f"AS advertises code_challenge_methods_supported={methods}."
                ),
                spec_link="https://datatracker.ietf.org/doc/html/rfc7636",
                remediation="Set code_challenge_methods_supported to include 'S256'.",
            )
        )
    if "plain" in methods:
        findings.append(
            Finding(
                check_id="MCP-PKCE-001",
                severity="error",
                title="PKCE 'plain' method advertised",
                detail="OAuth 2.1 forbids the 'plain' code challenge method.",
                spec_link="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1",
                remediation="Remove 'plain' from code_challenge_methods_supported.",
            )
        )
    return findings


async def check_iss_in_authorize(client: httpx.AsyncClient, as_meta: dict) -> list[Finding]:
    """MCP-ISS-001 / SEP-2468: /authorize redirect MUST include ``iss=``."""
    authorize_endpoint = as_meta.get("authorization_endpoint")
    if not authorize_endpoint:
        return []
    findings: list[Finding] = []
    # We can't actually drive a full /authorize here without a registered
    # client + PKCE pair, but we can at least detect `iss=` advertisement
    # in metadata when the AS sets `authorization_response_iss_parameter_supported`
    # per RFC 9207 §3.
    if not as_meta.get("authorization_response_iss_parameter_supported"):
        findings.append(
            Finding(
                check_id="MCP-ISS-001",
                severity="warning",
                tier="advisory",  # Mandatory only in MCP 2026-07-28; pre-spec IdPs get a pass.
                title="iss parameter on /authorize not advertised",
                detail=(
                    "AS metadata lacks `authorization_response_iss_parameter_supported=true`. "
                    "MCP clients implementing SEP-2468 (RFC 9207) cannot verify the "
                    "issuer of the auth-code callback without it."
                ),
                spec_link="https://datatracker.ietf.org/doc/html/rfc9207",
                remediation=(
                    "Set `authorization_response_iss_parameter_supported: true` and "
                    "include `iss=<server_url>` in every /authorize redirect."
                ),
            )
        )
    return findings


async def check_pkce_drift(client: httpx.AsyncClient, as_meta: dict) -> list[Finding]:
    """MCP-PKCE-002: probe for advertise-vs-enforce drift.

    OAuth 2.1 forbids ``code_challenge_method=plain``. A server that
    advertises ``S256`` only in metadata but still accepts ``plain`` at
    the authorize endpoint is the Obsidian Jan 2026 disclosure pattern.

    We send a minimal GET to ``/authorize`` with ``code_challenge_method=plain``
    and look at what the server complains about. If it rejects ``plain``
    explicitly (mentions the method or returns ``invalid_request`` with
    a method-related error), the server enforces the spec — clean. If it
    returns 200/302 (i.e. accepts ``plain`` for an unregistered client)
    or rejects only on ``client_id`` while ignoring the method, that's
    drift signal worth surfacing.

    This is a heuristic; we never complete the flow. False positives
    are possible — operators should re-test with ``authgent-server lint
    --probe`` to confirm.
    """
    authorize_endpoint = as_meta.get("authorization_endpoint")
    methods = as_meta.get("code_challenge_methods_supported", []) or []
    if not authorize_endpoint or "plain" in methods:
        # If the AS already advertises plain, MCP-PKCE-001 fires; no
        # need to probe.
        return []
    findings: list[Finding] = []
    # Use a deliberately invalid-looking client_id so the response can't
    # accidentally redirect us anywhere meaningful.
    probe_url = (
        f"{authorize_endpoint}?response_type=code&client_id=authgent-lint-probe"
        "&redirect_uri=https%3A%2F%2Fauthgent.dev%2Flint-probe"
        "&code_challenge=plain-probe&code_challenge_method=plain&state=lintprobe"
    )
    try:
        resp = await client.get(probe_url, follow_redirects=False, timeout=5.0)
    except httpx.HTTPError:
        return []
    body_text = ""
    try:
        body_text = resp.text[:2000]
    except Exception:
        pass
    location = resp.headers.get("location", "")
    haystack = (body_text + " " + location).lower()
    # Strong signal: server mentions the method by name in its complaint.
    method_called_out = (
        "code_challenge_method" in haystack
        or "challenge method" in haystack
        or "pkce" in haystack
        or "s256" in haystack
    )
    if method_called_out:
        return []  # server is correctly rejecting plain
    # P0-4: suppress false-positives when the server rejected the request
    # before reaching the PKCE check. Auth0 / Okta / Keycloak all validate
    # client_id BEFORE looking at code_challenge_method, so an unregistered
    # probe client triggers invalid_client / unauthorized_client instead of
    # invalid_request. That's correct behavior — the server enforces PKCE
    # at /token (or after a real client lookup), but our probe never gets
    # that far. Treating those responses as drift would false-flag every
    # major commercial IdP.
    pre_pkce_rejection_signals = (
        "invalid_client",
        "unauthorized_client",
        "invalid_redirect_uri",
        "unregistered",
        "unknown_client",
        "client_not_found",
    )
    if any(sig in haystack for sig in pre_pkce_rejection_signals):
        return []  # server rejected before getting to the PKCE check
    # Server complained but only about something we can't tie to a
    # specific check. That's drift signal.
    if resp.status_code in (302, 303):
        if "error=invalid_request" not in location:
            findings.append(
                Finding(
                    check_id="MCP-PKCE-002",
                    severity="error",
                    tier="spec_required",
                    title="PKCE method not enforced at /authorize (advertise-vs-enforce drift)",
                    detail=(
                        f"GET /authorize with code_challenge_method=plain returned "
                        f"HTTP {resp.status_code} without naming the method in the "
                        "error response. OAuth 2.1 forbids 'plain' (RFC 7636). "
                        "When metadata advertises 'S256' only but the endpoint "
                        "accepts 'plain', the server has the advertise-vs-enforce "
                        "sub-variant of the known PKCE-downgrade family (CWE-757; "
                        "OAuch BCP_4_8; Better-Auth GHSA-9h47-pqcx-hjr4). See "
                        "https://github.com/authgent/authgent/blob/main/docs/attacks/pkce-drift.md"
                    ),
                    spec_link="https://github.com/authgent/authgent/blob/main/docs/attacks/pkce-drift.md",
                    remediation=(
                        "Validate code_challenge_method at /authorize and reject "
                        "any value other than S256 with error=invalid_request."
                    ),
                )
            )
    return findings


def check_audience_binding(as_meta: dict) -> list[Finding]:
    """MCP-AUD-001: RFC 8707 resource indicators MUST be supported."""
    findings: list[Finding] = []
    if not as_meta.get("resource_indicators_supported"):
        findings.append(
            Finding(
                check_id="MCP-AUD-001",
                severity="error",
                title="RFC 8707 resource indicators not supported",
                detail=(
                    "Without resource binding, an MCP server cannot ensure that "
                    "tokens minted for it aren't replayable against a different "
                    "MCP server (the Obsidian-disclosed confused-deputy pattern)."
                ),
                spec_link="https://datatracker.ietf.org/doc/html/rfc8707",
                remediation=(
                    "Set `resource_indicators_supported: true` and enforce the "
                    "`resource` parameter on /token requests."
                ),
            )
        )
    return findings


def check_dcr_redirect_validation(as_meta: dict) -> list[Finding]:
    """MCP-DCR-001: registration_endpoint must exist and validate redirect_uri.

    We surface this as a warning when DCR is advertised because we cannot
    actually attempt the open-redirect probe from this endpoint without
    side effects; the lint only flags missing registration support, which
    forces every MCP client to be pre-registered (which is itself an
    integration burden).
    """
    if as_meta.get("registration_endpoint"):
        return []
    return [
        Finding(
            check_id="MCP-DCR-001",
            severity="warning",
            title="Dynamic Client Registration not advertised",
            detail=(
                "Without RFC 7591 DCR, MCP clients (Claude Desktop, Cursor, "
                "Continue, VS Code MCP) cannot self-register. Every user must "
                "manually obtain a client_id."
            ),
            spec_link="https://datatracker.ietf.org/doc/html/rfc7591",
            remediation="Expose a /register endpoint validated to RFC 7591 §2.",
        )
    ]


def check_state_csrf_advertised(as_meta: dict) -> list[Finding]:
    """MCP-CSRF-001: response_modes_supported should not include modes that
    sidestep state binding (e.g. fragment for non-implicit flows)."""
    response_types = as_meta.get("response_types_supported", []) or []
    findings: list[Finding] = []
    if "token" in response_types:
        findings.append(
            Finding(
                check_id="MCP-CSRF-001",
                severity="critical",
                title="Implicit grant advertised (response_type=token)",
                detail=(
                    "The implicit flow returns tokens in the URL fragment and "
                    "is forbidden by OAuth 2.1. Its presence breaks state "
                    "binding and enables the Obsidian-disclosed CSRF/auth-code "
                    "leak pattern."
                ),
                spec_link="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1",
                remediation="Remove 'token' from response_types_supported.",
            )
        )
    return findings


def check_refresh_for_public_clients(as_meta: dict) -> list[Finding]:
    """MCP-REFRESH-001: refresh tokens issued to public clients MUST require
    sender constraint (DPoP or mTLS).

    Heuristic: if `refresh_token` is in grant_types_supported but
    `dpop_signing_alg_values_supported` is absent, warn. This catches
    common misconfigurations without false-flagging RP servers that
    have legitimate alternative key binding.
    """
    grant_types = as_meta.get("grant_types_supported", []) or []
    dpop_algs = as_meta.get("dpop_signing_alg_values_supported", []) or []
    if "refresh_token" in grant_types and not dpop_algs:
        return [
            Finding(
                check_id="MCP-REFRESH-001",
                severity="warning",
                tier="advisory",  # DPoP is best-practice, not currently MCP-mandatory.
                title="Refresh tokens without DPoP support",
                detail=(
                    "AS supports refresh_token but does not advertise DPoP "
                    "(RFC 9449). Public MCP clients cannot sender-constrain "
                    "their refresh tokens, increasing token-theft impact."
                ),
                spec_link="https://datatracker.ietf.org/doc/html/rfc9449",
                remediation=(
                    "Set `dpop_signing_alg_values_supported: ['ES256']` and "
                    "issue DPoP-bound refresh tokens to public clients."
                ),
            )
        ]
    return []


async def check_passthrough(client: httpx.AsyncClient, base_url: str) -> list[Finding]:
    """MCP-PASSTHROUGH-001: detect anonymous tool execution.

    If a `GET /` or `GET /tools/list` returns 200 without an
    Authorization header, the MCP server is unprotected. This catches
    the most common auth misconfiguration.
    """
    findings: list[Finding] = []
    try:
        resp = await client.get(base_url, timeout=5.0, follow_redirects=False)
    except httpx.HTTPError:
        return []
    if resp.status_code == 200:
        # Heuristic: unauthenticated 200 on root suggests a server that
        # may also be serving tools without auth. This is a soft check —
        # operators may legitimately serve a landing page anonymously.
        findings.append(
            Finding(
                check_id="MCP-PASSTHROUGH-001",
                severity="info",
                tier="advisory",  # Heuristic; legitimate operators may host a landing.
                title="Root URL responds 200 without authentication",
                detail=(
                    f"GET {base_url} returned 200 unauthenticated. Verify that "
                    "tool endpoints require authentication and return 401 with "
                    "WWW-Authenticate when called without a token."
                ),
                spec_link="https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization",
                remediation=(
                    "Ensure all tool endpoints respond 401 + WWW-Authenticate "
                    "when called without a valid token."
                ),
            )
        )
    return findings


# DCR-mirror probe rate limit. The probe makes two unsolicited POST
# /register calls against a target registration endpoint; without a
# rate limit, /api/scan visitors could pollute a vendor's registration
# table by replaying the same target. Cache key is the registration
# endpoint URL; the value is a JSON-encoded list of finding dicts.
_DCR_MIRROR_TTL_SECONDS = 3600

# Process-local fallback used in tests and when the Redis backend is
# unavailable. Mirrors the cache.AsyncCache shape but keyed slightly
# differently so existing tests that introspect _dcr_mirror_cache keep
# working without a Redis container. Production deployments with
# AUTHGENT_REDIS_URL set bypass this entirely.
_dcr_mirror_cache: dict[str, tuple[float, list[Finding]]] = {}


def _findings_to_json(findings: list[Finding]) -> str:
    return json.dumps([asdict(f) for f in findings])


def _findings_from_json(payload: str) -> list[Finding]:
    return [Finding(**item) for item in json.loads(payload)]


async def check_dcr_mirror(client: httpx.AsyncClient, as_meta: dict) -> list[Finding]:
    """MCP-DCR-MIRROR-001: Two DCR registrations MUST yield distinct
    client_ids. A static client_id across users is the Obsidian-disclosed
    consent-cache-bypass pattern.

    Process-wide rate-limited: at most one probe per registration endpoint
    per ``_DCR_MIRROR_TTL_SECONDS``. When ``AUTHGENT_REDIS_URL`` is set
    the rate limit is shared across uvicorn workers; otherwise it is
    process-local. Either way, the public ``/api/scan`` endpoint can run
    with ``probe_registrations=True`` without becoming an abuse vector.
    """
    import time as _time

    reg = as_meta.get("registration_endpoint")
    if not reg:
        return []

    # L1: in-process cache (fast path for hot keys within one worker)
    cached = _dcr_mirror_cache.get(reg)
    if cached and (_time.time() - cached[0]) < _DCR_MIRROR_TTL_SECONDS:
        return list(cached[1])

    # L2: Redis (or in-process fallback) for cross-worker sharing.
    from authgent_server.cache import get_cache

    cache = get_cache()
    cache_key = f"dcr-mirror:{reg}"
    serialized = await cache.get(cache_key)
    if serialized is not None:
        findings_cached = _findings_from_json(serialized)
        _dcr_mirror_cache[reg] = (_time.time(), findings_cached)
        return findings_cached

    payload = {
        "client_name": "authgent-lint-probe",
        "grant_types": ["client_credentials"],
        "redirect_uris": [],
    }
    findings: list[Finding] = []
    try:
        r1 = await client.post(reg, json=payload, timeout=10.0)
        r2 = await client.post(reg, json=payload, timeout=10.0)
    except httpx.HTTPError:
        return []
    if r1.status_code in (200, 201) and r2.status_code in (200, 201):
        try:
            id1 = r1.json().get("client_id")
            id2 = r2.json().get("client_id")
        except ValueError:
            return []
        if id1 and id1 == id2:
            findings.append(
                Finding(
                    check_id="MCP-DCR-MIRROR-001",
                    severity="critical",
                    title="DCR returns identical client_id for distinct registrations",
                    detail=(
                        "Two consecutive POSTs to the registration endpoint "
                        f"returned the same client_id ({id1}). This is the "
                        "consent-cache-bypass pattern Obsidian disclosed in "
                        "January 2026 against multiple production MCP servers."
                    ),
                    spec_link="https://www.obsidiansecurity.com/blog/when-mcp-meets-oauth-common-pitfalls-leading-to-one-click-account-takeover",
                    remediation=(
                        "Generate a fresh client_id on every registration; do "
                        "not deduplicate by client_name."
                    ),
                )
            )
    _dcr_mirror_cache[reg] = (_time.time(), list(findings))
    await cache.set(cache_key, _findings_to_json(findings), ttl=_DCR_MIRROR_TTL_SECONDS)
    return findings


# --- Top-level scanner -------------------------------------------------------


async def scan(
    base_url: str,
    *,
    http_client: httpx.AsyncClient | None = None,
    probe_registrations: bool = False,
) -> list[Finding]:
    """Run every check against the MCP resource at ``base_url``.

    Resolves the AS via PRM, then runs the AS-metadata checks plus any
    MCP-server-level checks against ``base_url`` itself.

    ``probe_registrations`` (default False) gates the DCR-mirror probe.
    The probe creates two unsolicited ``POST /register`` calls against
    the target's registration endpoint, which is fine for a one-shot
    user-initiated scan but litters real third-party databases when run
    on a schedule. Registry refresh leaves it False; the public
    ``/api/scan?url=...`` endpoint sets it True so an interactive user
    gets the full audit.

    ``http_client`` is exposed for tests to inject an
    ``httpx.MockTransport``.
    """
    findings: list[Finding] = []
    parsed = urlparse(base_url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError(f"base_url must be http(s); got {base_url!r}")

    owns_client = http_client is None
    client = http_client or httpx.AsyncClient()
    try:
        prm_findings, prm = await check_protected_resource_metadata(client, base_url)
        findings.extend(prm_findings)

        if (
            prm
            and isinstance(prm.get("authorization_servers"), list)
            and prm["authorization_servers"]
        ):
            as_url = prm["authorization_servers"][0]
        else:
            return findings

        as_findings, as_meta = await check_as_metadata(client, as_url)
        findings.extend(as_findings)

        if as_meta is None:
            return findings

        findings.extend(check_pkce(as_meta))
        findings.extend(await check_pkce_drift(client, as_meta))
        findings.extend(await check_iss_in_authorize(client, as_meta))
        findings.extend(check_audience_binding(as_meta))
        findings.extend(check_dcr_redirect_validation(as_meta))
        findings.extend(check_state_csrf_advertised(as_meta))
        findings.extend(check_refresh_for_public_clients(as_meta))
        findings.extend(await check_passthrough(client, base_url))
        if probe_registrations:
            findings.extend(await check_dcr_mirror(client, as_meta))
    finally:
        if owns_client:
            await client.aclose()

    return findings


# --- Output formatters ------------------------------------------------------


def format_human(findings: list[Finding]) -> str:
    if not findings:
        return "✓ No findings."
    lines = []
    for f in findings:
        lines.append(f"[{f.severity.upper()}] {f.check_id}: {f.title}")
        lines.append(f"  {f.detail}")
        lines.append(f"  spec: {f.spec_link}")
        lines.append(f"  fix:  {f.remediation}")
        lines.append("")
    return "\n".join(lines)


def format_json(findings: list[Finding]) -> str:
    return json.dumps([asdict(f) for f in findings], indent=2)


def format_github(findings: list[Finding]) -> str:
    """GitHub Actions workflow-command annotations.

    https://docs.github.com/en/actions/using-workflows/workflow-commands-for-github-actions
    """
    lines = []
    for f in findings:
        level = "error" if f.severity in ("error", "critical") else "warning"
        msg = f"{f.check_id}: {f.title} — {f.detail} (see {f.spec_link})"
        # ::warning::msg or ::error::msg ; one line per finding.
        lines.append(f"::{level}::{msg}")
    return "\n".join(lines)


def has_blocking(findings: list[Finding]) -> bool:
    return any(f.severity in ("error", "critical") for f in findings)


def _finding_signature(f: Finding) -> tuple[str, str, str]:
    """Stable identity tuple for diff comparison.

    The (check_id, severity, title) triple is sufficient: a finding's
    detail string contains run-specific data (URLs, status codes,
    response excerpts) and would produce noisy diffs. The triple is what
    a CI gate cares about: "is this a new TYPE of problem?"
    """
    return (f.check_id, f.severity, f.title)


def diff_findings(
    current: list[Finding], baseline: list[Finding]
) -> tuple[list[Finding], list[Finding]]:
    """Return (new_findings, resolved_findings) relative to baseline.

    new_findings: in current but not in baseline (signature-equal).
    resolved_findings: in baseline but not in current.
    """
    baseline_sigs = {_finding_signature(f) for f in baseline}
    current_sigs = {_finding_signature(f) for f in current}
    new = [f for f in current if _finding_signature(f) not in baseline_sigs]
    resolved = [f for f in baseline if _finding_signature(f) not in current_sigs]
    return new, resolved


def _load_baseline(path: str) -> list[Finding]:
    """Parse a baseline JSON file produced by ``--save-baseline`` (or any
    prior ``-f json`` run). Returns an empty list if the file is absent so
    the first CI run does not need a pre-seeded baseline."""
    import os
    from pathlib import Path as _Path

    if not os.path.exists(path):
        return []
    raw = _Path(path).read_text()
    return [Finding(**item) for item in json.loads(raw)]


def main_cli(
    url: str,
    fmt: str = "human",
    diff_baseline: str | None = None,
    save_baseline: str | None = None,
) -> int:
    """Entry point used by the CLI subcommand.

    Modes:

    - default: print findings, exit non-zero if any are blocking.
    - ``save_baseline``: also write the JSON of all findings to that
      path. Returned status code follows the default mode.
    - ``diff_baseline``: load the baseline from the given path, compute
      new vs. resolved findings, print only the new ones, and exit
      non-zero only when the new set contains a blocking finding. The
      resolved set is shown as informational at the end. CI-friendly
      gate-on-regression mode.
    """
    findings = asyncio.run(scan(url))

    if save_baseline is not None:
        from pathlib import Path as _Path

        _Path(save_baseline).write_text(format_json(findings) + "\n")
        sys.stderr.write(f"baseline written to {save_baseline}\n")

    if diff_baseline is not None:
        baseline = _load_baseline(diff_baseline)
        new, resolved = diff_findings(findings, baseline)
        # Output only the new findings in the requested format.
        if fmt == "json":
            sys.stdout.write(format_json(new) + "\n")
        elif fmt == "github":
            sys.stdout.write(format_github(new) + "\n")
        else:
            sys.stdout.write(format_human(new) + "\n")
        if resolved:
            sys.stderr.write(
                f"\n{len(resolved)} previously-reported finding(s) resolved "
                "since baseline (not blocking):\n"
            )
            for f in resolved:
                sys.stderr.write(f"  resolved: [{f.severity}] {f.check_id}: {f.title}\n")
        rc = 1 if has_blocking(new) else 0
        try:
            from authgent_server.telemetry import emit_lint_event

            emit_lint_event(findings, rc)
        except Exception:  # noqa: BLE001
            pass
        return rc

    if fmt == "json":
        sys.stdout.write(format_json(findings) + "\n")
    elif fmt == "github":
        sys.stdout.write(format_github(findings) + "\n")
    else:
        sys.stdout.write(format_human(findings) + "\n")
    rc = 1 if has_blocking(findings) else 0
    try:
        from authgent_server.telemetry import emit_lint_event

        emit_lint_event(findings, rc)
    except Exception:  # noqa: BLE001 — telemetry must never break a real scan
        pass
    return rc
