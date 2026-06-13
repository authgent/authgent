"""Tests for `lint --config <path>` support.

Real CI integrations need a declarative config file in source control.
The contract:

- ``url:`` from the file is the default target when no positional arg.
- A positional CLI argument overrides the file's ``url:``.
- ``suppressions:`` drop matching check IDs entirely.
- ``severity_overrides:`` mutate a check's severity (raise or lower).
- ``fail_on:`` sets the minimum severity that produces a non-zero exit.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from authgent_server.scanner import (
    Finding,
    LintConfig,
    _apply_config,
    _has_blocking_at,
    _load_lint_config,
    main_cli,
)


def _f(check_id: str, severity: str = "warning") -> Finding:
    return Finding(
        check_id=check_id,
        severity=severity,  # type: ignore[arg-type]
        title="t",
        detail="d",
        spec_link="s",
        remediation="r",
    )


def test_load_lint_config_parses_yaml(tmp_path: Path):
    cfg_path = tmp_path / ".authgent.yml"
    cfg_path.write_text(
        "url: https://mcp.example.com\n"
        "suppressions:\n"
        "  - MCP-PASSTHROUGH-001\n"
        "severity_overrides:\n"
        "  MCP-REFRESH-001: warning\n"
        "fail_on: warning\n"
    )
    cfg = _load_lint_config(str(cfg_path))
    assert cfg.url == "https://mcp.example.com"
    assert cfg.suppressions == ["MCP-PASSTHROUGH-001"]
    assert cfg.severity_overrides == {"MCP-REFRESH-001": "warning"}
    assert cfg.fail_on == "warning"


def test_load_lint_config_missing_file_raises(tmp_path: Path):
    """A typo in --config <path> must surface as a clear error, not
    silently fall back to defaults. Catches the most common CI bug."""
    with pytest.raises(FileNotFoundError):
        _load_lint_config(str(tmp_path / "no-such-file.yml"))


def test_load_lint_config_empty_yaml_returns_defaults(tmp_path: Path):
    """Empty file should parse as a valid no-op config."""
    cfg_path = tmp_path / ".authgent.yml"
    cfg_path.write_text("")
    cfg = _load_lint_config(str(cfg_path))
    assert cfg.url is None
    assert cfg.suppressions == []
    assert cfg.severity_overrides == {}
    assert cfg.fail_on == "error"


def test_apply_config_suppressions_drop_matching_check_ids():
    findings = [_f("MCP-PRM-001"), _f("MCP-PASSTHROUGH-001"), _f("MCP-AS-001")]
    cfg = LintConfig(suppressions=["MCP-PASSTHROUGH-001"])
    out = _apply_config(findings, cfg)
    assert {f.check_id for f in out} == {"MCP-PRM-001", "MCP-AS-001"}


def test_apply_config_severity_override_lowers_severity():
    findings = [_f("MCP-REFRESH-001", severity="error")]
    cfg = LintConfig(severity_overrides={"MCP-REFRESH-001": "warning"})
    out = _apply_config(findings, cfg)
    assert len(out) == 1
    assert out[0].severity == "warning"


def test_apply_config_severity_override_raises_severity():
    findings = [_f("MCP-PASSTHROUGH-001", severity="info")]
    cfg = LintConfig(severity_overrides={"MCP-PASSTHROUGH-001": "error"})
    out = _apply_config(findings, cfg)
    assert out[0].severity == "error"


def test_has_blocking_at_threshold_warning():
    findings = [_f("X", severity="warning")]
    assert _has_blocking_at(findings, "warning") is True
    assert _has_blocking_at(findings, "error") is False


def test_has_blocking_at_threshold_critical_only():
    findings = [_f("X", severity="error")]
    assert _has_blocking_at(findings, "critical") is False
    assert _has_blocking_at(findings, "error") is True


def test_main_cli_uses_url_from_config_when_no_cli_arg(tmp_path: Path, monkeypatch):
    cfg_path = tmp_path / ".authgent.yml"
    cfg_path.write_text("url: https://from-config.example.com\n")

    captured = {"url": None}

    async def _fake_scan(target, *args, **kwargs):
        captured["url"] = target
        return []

    import authgent_server.scanner as scanner_mod

    monkeypatch.setattr(scanner_mod, "scan", _fake_scan)
    rc = main_cli(None, config_path=str(cfg_path))
    assert rc == 0
    assert captured["url"] == "https://from-config.example.com"


def test_main_cli_cli_url_overrides_config(tmp_path: Path, monkeypatch):
    cfg_path = tmp_path / ".authgent.yml"
    cfg_path.write_text("url: https://from-config.example.com\n")

    captured = {"url": None}

    async def _fake_scan(target, *args, **kwargs):
        captured["url"] = target
        return []

    import authgent_server.scanner as scanner_mod

    monkeypatch.setattr(scanner_mod, "scan", _fake_scan)
    rc = main_cli("https://from-cli.example.com", config_path=str(cfg_path))
    assert rc == 0
    assert captured["url"] == "https://from-cli.example.com"


def test_main_cli_no_url_anywhere_returns_2(tmp_path: Path):
    cfg_path = tmp_path / ".authgent.yml"
    cfg_path.write_text("# empty config, no url\n")
    rc = main_cli(None, config_path=str(cfg_path))
    assert rc == 2


def test_main_cli_suppressions_remove_finding_from_output(tmp_path: Path, monkeypatch, capsys):
    cfg_path = tmp_path / ".authgent.yml"
    cfg_path.write_text("suppressions:\n  - MCP-PASSTHROUGH-001\n")

    async def _fake_scan(*args, **kwargs):
        return [_f("MCP-PASSTHROUGH-001"), _f("MCP-PRM-001", severity="critical")]

    import authgent_server.scanner as scanner_mod

    monkeypatch.setattr(scanner_mod, "scan", _fake_scan)
    rc = main_cli("https://x.example", fmt="human", config_path=str(cfg_path))
    assert rc == 1  # MCP-PRM-001 critical still blocks
    captured = capsys.readouterr()
    assert "MCP-PASSTHROUGH-001" not in captured.out
    assert "MCP-PRM-001" in captured.out


def test_main_cli_fail_on_critical_lets_errors_pass(tmp_path: Path, monkeypatch):
    """fail_on: critical means an `error` severity does NOT exit 1."""
    cfg_path = tmp_path / ".authgent.yml"
    cfg_path.write_text("fail_on: critical\n")

    async def _fake_scan(*args, **kwargs):
        return [_f("X", severity="error")]

    import authgent_server.scanner as scanner_mod

    monkeypatch.setattr(scanner_mod, "scan", _fake_scan)
    rc = main_cli("https://x.example", config_path=str(cfg_path))
    assert rc == 0
