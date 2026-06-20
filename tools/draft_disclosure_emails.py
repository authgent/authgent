#!/usr/bin/env python3
"""Generate per-vendor disclosure email drafts from the scan results.

For each vendor in tools/scan-results/*.json, produce a personalised
email at tools/disclosure-emails/<vendor-slug>.md. The drafts are
NOT sent automatically; the maintainer reviews and sends. Output
files are gitignored.

Convention:

- One file per vendor, even if no actionable findings (clean vendors
  get a "we didn't find anything blocking" record so the maintainer
  has a complete audit log).
- Subject line + recipient address taken from the targets file.
- Body composed from the scanner's ``remediation`` strings so we
  never hand-write spec advice that drifts from the source of truth.
- Embargo date pre-computed at ``send_date + 14 days`` per
  docs/disclosure-policy.md.
"""

from __future__ import annotations

import json
import re
from datetime import UTC, datetime, timedelta
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
RESULTS_DIR = REPO_ROOT / "tools" / "scan-results"
TARGETS_PATH = REPO_ROOT / "tools" / "disclosure-targets.json"
EMAILS_DIR = REPO_ROOT / "tools" / "disclosure-emails"


def _slug(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")


def _format_finding(finding: dict) -> str:
    return (
        f"### {finding['check_id']} ({finding['severity']}): {finding['title']}\n\n"
        f"{finding['detail']}\n\n"
        f"**Spec reference:** {finding['spec_link']}\n\n"
        f"**Remediation:** {finding['remediation']}\n"
    )


EMA_LAUNCH_PARTNERS = {
    "Asana",
    "Atlassian",
    "Canva",
    "Figma",
    "Granola",
    "Linear",
    "Supabase",
}


def _draft_email(target: dict, findings: list[dict], embargo_date: str) -> str:
    blocking = [f for f in findings if f["severity"] in ("error", "critical")]
    advisory = [f for f in findings if f["severity"] in ("info", "warning")]

    contact = target.get("security_contact") or "<security@vendor>"
    vendor = target["vendor"]
    url = target["url"]
    vendor_short = vendor.split(" (")[0]
    is_ema_partner = vendor_short in EMA_LAUNCH_PARTNERS

    if not blocking:
        return _draft_clean_email(target, advisory)

    # News-cycle framing. The 2026-06-18 Enterprise-Managed Authorization
    # launch put OAuth on every MCP vendor's security inbox the same week
    # we send these emails. Riding that context lifts open + reply rates
    # materially. Two variants: launch partners get the direct
    # "congratulations + we re-scanned in light of EMA" hook; everyone
    # else gets the "following the EMA announcement" framing.
    if is_ema_partner:
        opener = [
            f"Hi {vendor_short} security team,",
            "",
            f"Congratulations on being a launch partner for the Model",
            "Context Protocol's Enterprise-Managed Authorization (EMA)",
            "extension on 2026-06-18. While reviewing the published OAuth",
            f"metadata for {url} in light of the EMA announcement, the",
            "open-source authgent MCP-OAuth conformance scanner (Apache",
            "2.0; IETF Internet-Draft on datatracker) flagged the items",
            "below.",
            "",
            "These findings are independent of EMA. EMA / ID-JAG",
            "(draft-ietf-oauth-identity-assertion-authz-grant) replaces",
            "the per-app consent screen but does not touch PKCE methods",
            "or RFC 8707 resource-indicator handling, so the items below",
            "remain actionable regardless of EMA rollout state.",
            "",
            "  https://github.com/authgent/authgent",
            "  https://datatracker.ietf.org/doc/draft-agnihotri-oauth-agent-impl-status/",
            "  https://thenewstack.io/mcp-gets-its-missing-enterprise-authorization-layer/",
            "",
        ]
    else:
        opener = [
            f"Hi {vendor_short} security team,",
            "",
            "Following the 2026-06-18 announcement of MCP",
            "Enterprise-Managed Authorization (EMA) by Anthropic /",
            "Microsoft / Okta, the open-source authgent MCP-OAuth",
            "conformance scanner (Apache 2.0; IETF Internet-Draft on",
            f"datatracker) re-scanned a set of public MCP servers. {url}",
            "surfaced the items below. EMA replaces the consent screen",
            "but does not touch PKCE methods or RFC 8707 resource",
            "indicators, so these findings remain actionable",
            "independently of any EMA rollout you may be planning.",
            "",
            "  https://github.com/authgent/authgent",
            "  https://datatracker.ietf.org/doc/draft-agnihotri-oauth-agent-impl-status/",
            "  https://thenewstack.io/mcp-gets-its-missing-enterprise-authorization-layer/",
            "",
        ]

    parts = [
        f"To: {contact}",
        f"Subject: Responsible disclosure: MCP-OAuth conformance findings on {url}",
        "",
        *opener,
        f"A scan on {datetime.now(UTC).strftime('%Y-%m-%d')} surfaced",
        "the following blocking finding(s) you may want to review:",
        "",
    ]
    for f in blocking:
        parts.append(_format_finding(f))

    if advisory:
        parts.append("Advisory (informational; non-blocking):")
        parts.append("")
        for f in advisory:
            parts.append(f"- **{f['check_id']}** ({f['severity']}): {f['title']}")
        parts.append("")

    parts.extend(
        [
            "The full structured output (JSON) and a reproduction command",
            "are at the end of this message.",
            "",
            "## Disclosure window",
            "",
            f"This email starts a 14-day responsible-disclosure window per",
            "authgent's policy:",
            "",
            "  https://github.com/authgent/authgent/blob/main/docs/disclosure-policy.md",
            "",
            f"Until **{embargo_date}**, your {url} entry on the public",
            "registry will display 'Vendor notified — grade publishes",
            f"{embargo_date}' without the grade. If a fix lands before that",
            "date, the relevant finding is removed and the entry refreshes",
            "to whatever the live state is.",
            "",
            "## Opt out",
            "",
            "If you would prefer to opt out of the public registry",
            "entirely, reply with 'opt out' and I will set",
            "`opted_out: true` on your entry within 24 hours; the",
            "registry never lists targets that ask to be excluded.",
            "",
            "## Corrections",
            "",
            "If anything in this disclosure is incorrect, please reply",
            "with the correction. False findings are removed before",
            "publication and the corresponding scanner check is fixed.",
            "",
            "## Reproduction",
            "",
            "```bash",
            "pip install authgent-server",
            f"authgent-server lint {url}",
            "```",
            "",
            "## Full JSON",
            "",
            "```json",
            json.dumps(findings, indent=2),
            "```",
            "",
            "Thanks,",
            "Dhruv Agnihotri",
            "security@authgent.dev",
            "https://github.com/authgent/authgent",
        ]
    )
    return "\n".join(parts)


def _draft_clean_email(target: dict, advisory: list[dict]) -> str:
    """For vendors with only advisory findings or none at all -- no
    embargo, no public registry penalty, just a courtesy heads-up."""
    contact = target.get("security_contact") or "<security@vendor>"
    vendor = target["vendor"]
    url = target["url"]
    parts = [
        f"To: {contact}",
        f"Subject: MCP-OAuth scan: {url} passes all blocking checks",
        "",
        f"Hi {vendor} security team,",
        "",
        f"I scanned {url} with the open-source authgent MCP-OAuth",
        "conformance scanner today. Your server passes all the blocking",
        "(error/critical) checks. This is unusual; congratulations.",
        "",
    ]
    if advisory:
        parts.extend(
            [
                "Advisory items you may want to consider for a future",
                "release:",
                "",
            ]
        )
        for f in advisory:
            parts.append(f"- **{f['check_id']}** ({f['severity']}): {f['title']}")
            parts.append(f"  Spec: {f['spec_link']}")
            parts.append(f"  Fix: {f['remediation']}")
            parts.append("")
    parts.extend(
        [
            "No disclosure embargo applies (no blocking findings). Your",
            f"entry on the public registry will reflect the current grade.",
            "",
            "Thanks,",
            "Dhruv Agnihotri",
            "security@authgent.dev",
            "https://github.com/authgent/authgent",
        ]
    )
    return "\n".join(parts)


def main() -> int:
    targets_doc = json.loads(TARGETS_PATH.read_text())
    targets = {t["url"]: t for t in targets_doc["targets"]}
    EMAILS_DIR.mkdir(exist_ok=True)
    embargo_date = (datetime.now(UTC) + timedelta(days=14)).strftime("%Y-%m-%d")

    counts = {"with_blocking": 0, "advisory_only": 0, "clean": 0}
    for result_file in sorted(RESULTS_DIR.glob("*.json")):
        result = json.loads(result_file.read_text())
        target_url = result["target"]["url"]
        target = targets.get(target_url) or result["target"]
        findings = result.get("findings") or []
        slug = _slug(target.get("vendor") or target.get("name") or "unknown")

        if any(f["severity"] in ("error", "critical") for f in findings):
            counts["with_blocking"] += 1
        elif any(f["severity"] in ("info", "warning") for f in findings):
            counts["advisory_only"] += 1
        else:
            counts["clean"] += 1

        body = _draft_email(target, findings, embargo_date)
        out = EMAILS_DIR / f"{slug}.md"
        out.write_text(body + "\n")

    print(
        f"drafts written: {counts['with_blocking']} blocking, "
        f"{counts['advisory_only']} advisory-only, {counts['clean']} clean."
    )
    print(f"output dir: {EMAILS_DIR}")
    return 0


if __name__ == "__main__":
    main()
