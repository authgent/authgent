"""Tests for `lint --diff <baseline>` and `lint --save-baseline=...`.

The ``--diff`` mode is the single biggest CLI feature blocking CI
adoption: it lets a project gate on regressions only, ignoring the
findings that already exist in the baseline. The ``--save-baseline``
mode produces the JSON the diff path consumes.
"""

from __future__ import annotations

import json
from pathlib import Path

from authgent_server.scanner import (
    Finding,
    diff_findings,
    has_blocking,
    main_cli,
)


def _f(check_id: str, severity: str = "warning", title: str = "t") -> Finding:
    return Finding(
        check_id=check_id,
        severity=severity,  # type: ignore[arg-type]
        title=title,
        detail=f"detail for {check_id}",
        spec_link="https://example",
        remediation="r",
    )


def test_diff_finds_only_new_findings():
    baseline = [_f("MCP-PRM-001"), _f("MCP-AS-001")]
    current = [_f("MCP-PRM-001"), _f("MCP-PKCE-001")]
    new, resolved = diff_findings(current, baseline)
    assert [f.check_id for f in new] == ["MCP-PKCE-001"]
    assert [f.check_id for f in resolved] == ["MCP-AS-001"]


def test_diff_empty_baseline_returns_all_findings_as_new():
    current = [_f("MCP-PRM-001"), _f("MCP-AS-001")]
    new, resolved = diff_findings(current, [])
    assert {f.check_id for f in new} == {"MCP-PRM-001", "MCP-AS-001"}
    assert resolved == []


def test_diff_identical_findings_returns_empty():
    findings = [_f("MCP-PRM-001"), _f("MCP-AS-001")]
    new, resolved = diff_findings(findings, list(findings))
    assert new == []
    assert resolved == []


def test_diff_severity_change_is_treated_as_new_finding():
    """A check_id that escalated in severity (e.g. warning -> critical)
    counts as a new finding. CI gate should fire."""
    baseline = [_f("MCP-PKCE-001", severity="warning")]
    current = [_f("MCP-PKCE-001", severity="critical")]
    new, _ = diff_findings(current, baseline)
    assert len(new) == 1
    assert new[0].severity == "critical"


def test_main_cli_save_baseline_writes_json(tmp_path: Path, monkeypatch):
    """`--save-baseline` writes the current findings as JSON. The file
    must round-trip through json.loads + Finding(**kwargs)."""
    baseline_path = tmp_path / "baseline.json"

    async def _fake_scan(*args, **kwargs):
        return [_f("MCP-PRM-001", severity="critical")]

    import authgent_server.scanner as scanner_mod

    monkeypatch.setattr(scanner_mod, "scan", _fake_scan)
    rc = main_cli(
        "https://mcp.example.com",
        fmt="json",
        save_baseline=str(baseline_path),
    )
    assert rc == 1
    raw = json.loads(baseline_path.read_text())
    assert isinstance(raw, list)
    assert raw[0]["check_id"] == "MCP-PRM-001"


def test_main_cli_diff_zero_exit_when_no_new_findings(tmp_path: Path, monkeypatch, capsys):
    """When current findings match baseline, --diff exits 0 even if the
    baseline contained blocking findings. The CI gate is regression-only,
    not absolute."""
    baseline_path = tmp_path / "baseline.json"
    baseline_path.write_text(
        json.dumps(
            [
                {
                    "check_id": "MCP-PRM-001",
                    "severity": "critical",
                    "title": "t",
                    "detail": "d",
                    "spec_link": "https://e",
                    "remediation": "r",
                    "tier": "spec_required",
                    "extra": {},
                }
            ]
        )
    )

    async def _fake_scan(*args, **kwargs):
        return [_f("MCP-PRM-001", severity="critical")]

    import authgent_server.scanner as scanner_mod

    monkeypatch.setattr(scanner_mod, "scan", _fake_scan)
    rc = main_cli(
        "https://mcp.example.com",
        fmt="human",
        diff_baseline=str(baseline_path),
    )
    assert rc == 0


def test_main_cli_diff_nonzero_exit_when_new_blocking_finding(tmp_path: Path, monkeypatch):
    """A new error-or-critical finding in current that was not in the
    baseline must produce exit code 1. This is the regression gate."""
    baseline_path = tmp_path / "baseline.json"
    baseline_path.write_text("[]")

    async def _fake_scan(*args, **kwargs):
        return [_f("MCP-PKCE-001", severity="error")]

    import authgent_server.scanner as scanner_mod

    monkeypatch.setattr(scanner_mod, "scan", _fake_scan)
    rc = main_cli(
        "https://mcp.example.com",
        fmt="human",
        diff_baseline=str(baseline_path),
    )
    assert rc == 1


def test_main_cli_diff_missing_baseline_file_treated_as_empty(tmp_path: Path, monkeypatch):
    """First-time CI runs must work without a pre-seeded baseline file.
    A missing file is equivalent to an empty baseline."""

    async def _fake_scan(*args, **kwargs):
        return []  # clean scan

    import authgent_server.scanner as scanner_mod

    monkeypatch.setattr(scanner_mod, "scan", _fake_scan)
    rc = main_cli(
        "https://mcp.example.com",
        fmt="human",
        diff_baseline=str(tmp_path / "does-not-exist.json"),
    )
    assert rc == 0


def test_finding_signature_independent_of_detail_text():
    """Two findings with the same check_id+severity+title but different
    detail strings must be treated as the same finding for diff purposes.
    Detail text contains run-specific data (URLs, status codes) that
    would otherwise make every diff noisy."""
    f1 = Finding(
        check_id="X",
        severity="warning",
        title="T",
        detail="run 1 detail",
        spec_link="s",
        remediation="r",
    )
    f2 = Finding(
        check_id="X",
        severity="warning",
        title="T",
        detail="run 2 detail with different status code 502",
        spec_link="s",
        remediation="r",
    )
    new, resolved = diff_findings([f2], [f1])
    assert new == []
    assert resolved == []


def test_has_blocking_unchanged():
    """Sanity: has_blocking still works as before."""
    assert has_blocking([_f("X", severity="warning")]) is False
    assert has_blocking([_f("X", severity="error")]) is True
    assert has_blocking([_f("X", severity="critical")]) is True
