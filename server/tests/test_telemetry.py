"""Tests for the opt-out CLI telemetry.

The contract is privacy-first: we never transmit the scanned URL, the
user's IP, or any user identifier other than a hashed install ID. We
must also be silent on opt-out and on network failure. These tests
encode those properties.
"""

from __future__ import annotations

import pytest

from authgent_server import telemetry
from authgent_server.scanner import Finding


def _f(check_id: str) -> Finding:
    return Finding(
        check_id=check_id,
        severity="warning",
        title="t",
        detail="d",
        spec_link="s",
        remediation="r",
    )


def test_opt_out_via_authgent_telemetry_zero(monkeypatch):
    monkeypatch.setenv("AUTHGENT_TELEMETRY", "0")
    monkeypatch.setattr(telemetry, "DEFAULT_ENDPOINT", "https://collector.example/e")
    assert telemetry._is_opted_out() is True


def test_opt_out_via_do_not_track(monkeypatch):
    monkeypatch.setenv("DO_NOT_TRACK", "1")
    monkeypatch.setattr(telemetry, "DEFAULT_ENDPOINT", "https://collector.example/e")
    assert telemetry._is_opted_out() is True


def test_opt_out_when_endpoint_unset(monkeypatch):
    monkeypatch.delenv("AUTHGENT_TELEMETRY", raising=False)
    monkeypatch.delenv("DO_NOT_TRACK", raising=False)
    monkeypatch.setattr(telemetry, "DEFAULT_ENDPOINT", "")
    assert telemetry._is_opted_out() is True


def test_install_id_is_stable_and_short():
    a = telemetry._install_id()
    b = telemetry._install_id()
    assert a == b
    assert len(a) == 12
    assert all(c in "0123456789abcdef" for c in a)


def test_summarise_findings_aggregates_by_check_id():
    findings = [_f("MCP-PRM-001"), _f("MCP-PRM-001"), _f("MCP-AS-001")]
    counts = telemetry._summarise_findings(findings)
    assert counts == {"MCP-PRM-001": 2, "MCP-AS-001": 1}


@pytest.mark.asyncio
async def test_send_swallows_network_errors(monkeypatch):
    """If the collector is unreachable, the function must silently
    succeed. A failed telemetry post must never break a real scan."""
    monkeypatch.setattr(telemetry, "DEFAULT_ENDPOINT", "https://localhost:1/never-reached")
    # No exception should propagate.
    await telemetry._send({"event": "lint", "version": "test"})


def test_emit_lint_event_no_payload_contains_url(monkeypatch, capsys):
    """The telemetry payload contract: NEVER transmit the scanned URL.
    We assert this by inspecting the payload that emit_lint_event would
    construct, before it gets POSTed.

    We achieve that by patching _send to capture the payload and then
    checking it has no URL-shaped string."""
    captured: list[dict] = []

    async def _capture(payload):
        captured.append(payload)

    monkeypatch.setattr(telemetry, "_send", _capture)
    monkeypatch.setattr(telemetry, "DEFAULT_ENDPOINT", "https://collector.example/e")
    monkeypatch.setenv("AUTHGENT_TELEMETRY", "1")
    monkeypatch.delenv("DO_NOT_TRACK", raising=False)
    # Suppress the first-run notice path side effects.
    monkeypatch.setattr(telemetry, "_show_first_run_notice", lambda: None)

    findings = [_f("MCP-PRM-001"), _f("MCP-AS-001")]
    telemetry.emit_lint_event(findings, exit_code=1)

    # The async _send was scheduled. Drain it.
    import asyncio

    pending = [t for t in asyncio.all_tasks() if not t.done()] if _has_loop() else []
    if pending:
        asyncio.get_event_loop().run_until_complete(
            asyncio.gather(*pending, return_exceptions=True)
        )

    assert len(captured) == 1, "exactly one event per emit_lint_event call"
    payload = captured[0]
    flat = repr(payload)
    # Negative invariants: nothing URL-like, nothing host-like.
    assert "http://" not in flat
    assert "https://" not in flat
    assert "mcp." not in flat
    # Positive invariants: required fields present.
    assert payload["event"] == "lint"
    assert payload["exit_code"] == 1
    assert payload["findings"] == {"MCP-PRM-001": 1, "MCP-AS-001": 1}
    assert "install_id" in payload
    assert len(payload["install_id"]) == 12


def _has_loop() -> bool:
    import asyncio

    try:
        asyncio.get_event_loop()
        return True
    except RuntimeError:
        return False


def test_emit_lint_event_silent_when_opted_out(monkeypatch):
    """When opted out, no _send calls happen at all."""
    captured: list = []

    async def _capture(payload):
        captured.append(payload)

    monkeypatch.setattr(telemetry, "_send", _capture)
    monkeypatch.setenv("AUTHGENT_TELEMETRY", "0")
    telemetry.emit_lint_event([_f("X")], exit_code=0)
    assert captured == [], "opted-out invocations must not call _send"


def test_first_run_notice_marker_persists(tmp_path, monkeypatch):
    """The notice prints once. Subsequent calls are silent because
    a marker file gets created in ~/.authgent/."""
    monkeypatch.setattr(telemetry, "DEFAULT_ENDPOINT", "https://collector.example/e")
    monkeypatch.setenv("HOME", str(tmp_path))
    # First call should write the marker.
    telemetry._show_first_run_notice()
    marker = tmp_path / ".authgent" / "telemetry_notice_shown"
    assert marker.exists()
    # Second call should not raise even with the marker present.
    telemetry._show_first_run_notice()
