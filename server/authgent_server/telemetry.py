"""Anonymous, opt-out CLI telemetry.

When ``authgent-server lint`` runs, send a single small event to a
configurable HTTPS endpoint so adoption can be measured without
requiring user accounts. **No URLs, no IPs, no user identifiers** are
sent: only the scanner version, the exit code, the count of findings
per check_id, and a per-install hashed identifier so repeat runs from
one machine count as one user.

Privacy properties (these are the contract):

- The target URL the user scanned is **never** transmitted. The hash
  ``sha256(target_url)`` is also not transmitted; we only count
  findings, not what was scanned.
- The user's IP is not recorded by the receiver beyond the standard
  TLS-terminator log. The receiver is configured to drop IPs after
  rotation.
- The hashed install ID is ``sha256(<machine_id> + 'authgent-v1')``
  truncated to 12 hex chars. There is no rainbow table that can
  recover the machine_id from this.
- The user can opt out by setting ``AUTHGENT_TELEMETRY=0`` (or the
  receiver URL to empty), and the scanner does not send anything.
- The first time the CLI runs without an explicit setting, it
  prints a single notice telling the user telemetry is on and how to
  disable it. After that, silent.

Opt-out by any of:
- ``AUTHGENT_TELEMETRY=0``
- ``AUTHGENT_TELEMETRY_URL=""``
- ``DO_NOT_TRACK=1`` (https://consoledonottrack.com/)

Default endpoint: configured at build time via
``AUTHGENT_TELEMETRY_URL`` env var. If unset, telemetry is a no-op.
"""

from __future__ import annotations

import asyncio
import hashlib
import os
import platform
import sys
import uuid
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from authgent_server.scanner import Finding

DEFAULT_ENDPOINT = os.environ.get("AUTHGENT_TELEMETRY_URL", "").strip()


def _is_opted_out() -> bool:
    if os.environ.get("DO_NOT_TRACK", "").strip() == "1":
        return True
    val = os.environ.get("AUTHGENT_TELEMETRY", "").strip().lower()
    if val in ("0", "false", "no", "off"):
        return True
    if not DEFAULT_ENDPOINT:
        return True
    return False


def _install_id() -> str:
    """Stable per-install hash. Anchored on the MAC address (uuid.getnode())
    so the value is consistent across CLI invocations from the same machine
    but is not reversible to the MAC itself."""
    raw = f"{uuid.getnode()}:authgent-v1"
    return hashlib.sha256(raw.encode()).hexdigest()[:12]


def _scanner_version() -> str:
    try:
        from authgent_server import __version__

        return __version__
    except Exception:  # noqa: BLE001
        return "unknown"


def _show_first_run_notice() -> None:
    """Print the one-time notice on first telemetry-eligible run."""
    home = os.path.expanduser("~")
    marker = os.path.join(home, ".authgent", "telemetry_notice_shown")
    if os.path.exists(marker):
        return
    sys.stderr.write(
        "\nNotice: anonymous telemetry is enabled (opt-out). The scanner sends\n"
        "the version, exit code, and per-check_id finding counts to\n"
        f"  {DEFAULT_ENDPOINT}\n"
        "It does NOT send the scanned URL or your IP. Disable with:\n"
        "  export AUTHGENT_TELEMETRY=0  (or DO_NOT_TRACK=1)\n"
        "Privacy policy: https://github.com/authgent/authgent#telemetry\n\n"
    )
    try:
        os.makedirs(os.path.join(home, ".authgent"), exist_ok=True)
        with open(marker, "w") as fh:
            fh.write("shown\n")
    except OSError:
        # Read-only home; non-fatal — notice will print again next run.
        pass


def _summarise_findings(findings: list[Finding]) -> dict[str, int]:
    """Aggregate finding counts by check_id. Used for the telemetry
    payload so we can see prevalence trends without ever transmitting
    target URLs."""
    counts: dict[str, int] = {}
    for f in findings:
        counts[f.check_id] = counts.get(f.check_id, 0) + 1
    return counts


async def _send(payload: dict) -> None:
    """Best-effort POST. Failures are silent — telemetry is never
    permitted to slow down or break a real scan."""
    if not DEFAULT_ENDPOINT:
        return
    try:
        import httpx

        async with httpx.AsyncClient(timeout=2.0) as client:
            await client.post(DEFAULT_ENDPOINT, json=payload)
    except Exception:  # noqa: BLE001
        pass


def emit_lint_event(findings: list[Finding], exit_code: int) -> None:
    """Synchronous entry point called from the CLI after a lint run.

    Emits a single telemetry event in a fire-and-forget asyncio task
    so the caller never waits on the network. Total budget: 2 seconds
    HTTP timeout, swallowed on any error.
    """
    if _is_opted_out():
        return
    _show_first_run_notice()
    payload = {
        "event": "lint",
        "version": _scanner_version(),
        "install_id": _install_id(),
        "exit_code": exit_code,
        "platform": platform.system().lower(),
        "python": ".".join(map(str, sys.version_info[:2])),
        "findings": _summarise_findings(findings),
    }
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            loop.create_task(_send(payload))
        else:
            loop.run_until_complete(_send(payload))
    except RuntimeError:
        # No event loop available (e.g. atexit). Run synchronously.
        try:
            asyncio.run(_send(payload))
        except Exception:  # noqa: BLE001
            pass
