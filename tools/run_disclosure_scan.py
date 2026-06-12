#!/usr/bin/env python3
"""Run the MCP-OAuth scanner against the disclosure target list.

This is the harness for assembling the prevalence numbers that appear in
``docs/attacks/*.md``. It is deliberately kept separate from the
public-facing scanner endpoints because:

- The target list is sensitive during an active disclosure window — we
  do not want it on GitHub Pages.
- Per-vendor scan outputs land in ``tools/scan-results/`` (gitignored)
  so a maintainer can prepare individual disclosure emails before the
  embargo lifts.
- Only the *aggregate, anonymised* count is published — and only after
  the embargo closes, by hand-editing the relevant docs/attacks page.

Usage::

    cp tools/disclosure-targets.example.json tools/disclosure-targets.json
    # Populate tools/disclosure-targets.json from public sources
    python tools/run_disclosure_scan.py
    # Inspect tools/scan-results/<vendor-slug>.json for each affected vendor

The scanner runs with ``probe_registrations=False``; the DCR-mirror
probe is gated to one-per-hour by an in-process cache anyway, but for
prevalence work we don't need to litter every vendor's registration
table. Disclosure emails that need DCR-mirror confirmation should
re-run with ``--probe-registrations`` against the single target.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import re
import sys
from collections import Counter
from dataclasses import asdict
from pathlib import Path
from typing import Any

# Make the in-tree scanner importable when run from the repo root.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "server"))

from authgent_server.scanner import Finding, scan  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parent.parent
TARGETS_PATH = REPO_ROOT / "tools" / "disclosure-targets.json"
RESULTS_DIR = REPO_ROOT / "tools" / "scan-results"


def _slug(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")


async def _scan_target(target: dict[str, Any], probe_registrations: bool) -> dict[str, Any]:
    url = target["url"]
    try:
        findings = await scan(url, probe_registrations=probe_registrations)
    except Exception as exc:  # noqa: BLE001
        return {"target": target, "error": str(exc), "findings": []}
    return {"target": target, "findings": [asdict(f) for f in findings]}


def _summarise(results: list[dict[str, Any]]) -> dict[str, Any]:
    """Anonymised aggregate suitable for publishing post-embargo."""
    total = len(results)
    errored = sum(1 for r in results if r.get("error"))
    scanned = total - errored
    counter: Counter[str] = Counter()
    affected_count: dict[str, int] = {}
    for r in results:
        for f in r["findings"]:
            counter[f["check_id"]] += 1
        # Count distinct vendors affected by each check_id (one per vendor)
        seen_in_target: set[str] = set()
        for f in r["findings"]:
            seen_in_target.add(f["check_id"])
        for cid in seen_in_target:
            affected_count[cid] = affected_count.get(cid, 0) + 1

    severities: Counter[str] = Counter()
    for r in results:
        for f in r["findings"]:
            severities[f["severity"]] += 1
    return {
        "total_targets": total,
        "scanned_ok": scanned,
        "errored": errored,
        "vendors_with_finding": affected_count,  # vendor count per check_id
        "total_findings": dict(counter),  # raw count per check_id (some targets have >1)
        "severity_distribution": dict(severities),
    }


async def _amain(probe_registrations: bool) -> int:
    if not TARGETS_PATH.exists():
        print(
            f"ERROR: {TARGETS_PATH.relative_to(REPO_ROOT)} not found.\n"
            "Copy tools/disclosure-targets.example.json and populate it from public sources.",
            file=sys.stderr,
        )
        return 2

    targets_doc = json.loads(TARGETS_PATH.read_text())
    targets = targets_doc.get("targets", [])
    if not targets:
        print("ERROR: targets list is empty.", file=sys.stderr)
        return 2

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)

    print(f"Scanning {len(targets)} target(s)...", file=sys.stderr)
    results = await asyncio.gather(
        *(_scan_target(t, probe_registrations) for t in targets), return_exceptions=False
    )

    for r in results:
        slug = _slug(str(r["target"].get("vendor") or r["target"].get("name") or "unknown"))
        out = RESULTS_DIR / f"{slug}.json"
        out.write_text(json.dumps(r, indent=2, default=str) + "\n")
        finding_count = len(r["findings"])
        marker = "ERR" if r.get("error") else f"{finding_count} finding(s)"
        print(f"  {r['target']['vendor']:30s} → {marker}  ({out.relative_to(REPO_ROOT)})")

    summary = _summarise(results)
    print()
    print(json.dumps(summary, indent=2))
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--probe-registrations",
        action="store_true",
        help="Run the DCR-mirror probe (two POSTs to /register per target). "
        "Off by default to avoid littering vendor registration tables during a "
        "broad sweep; enable for single-target follow-up confirmations.",
    )
    args = parser.parse_args()
    return asyncio.run(_amain(args.probe_registrations))


if __name__ == "__main__":
    sys.exit(main())
