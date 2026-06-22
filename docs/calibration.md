# Scanner Calibration

This page is the public-facing twin of
[`server/tests/test_calibration.py`](../server/tests/test_calibration.py).
The pytest file is the executable contract; this page is the written
explanation.

If a scoring weight ever changes, both files update together. CI fails
if the test rows no longer produce the documented grades — so the table
below cannot drift.

## Why calibration matters

Letter grades have to be *interpretable*. If every server in the wild
grades D, the conclusion the reader draws is "this scanner is broken,"
not "these vendors are broken." The calibration set is a small group of
synthetic targets whose expected grade we publish ahead of time. If
those synthetic targets ever produce the wrong grade, the scanner gets
fixed before any production traffic is affected.

## The calibration set

| Case | Class | Expected grade | Why |
|---|---|---|---|
| Perfect MCP-2026 conformant | known-good | **A / 100** | All 10 spec checks pass; advisory checks (DPoP, iss) also pass. The reference shape every MCP server should look like. |
| Legacy IdP, no MCP-only fields | known-good | **A** | Same as above except no `authorization_response_iss_parameter_supported` and no DPoP advertised. Both are *advisory* — they don't drive the grade. This is the case Auth0 / Okta / Keycloak fit before they ship MCP-2026 support. |
| PKCE `plain` advertised | known-bad | **B–C** | Single OAuth 2.1 violation. Severity `error` = −15 → score 85 → grade B. |
| No `/.well-known/oauth-protected-resource` | known-bad | **D–F** | MCP clients can't discover the AS. Severity `critical` = −50 → score 50 → grade D at best. |
| Implicit grant advertised (`response_type=token`) | known-bad | **D–F** | OAuth 2.1 forbids this. Stacks with DCR-mirror in this fixture for an F. |
| DCR mirror (Obsidian Jan 2026 pattern) | known-bad | **D–F** | Same `client_id` for distinct registrations enables consent-cache-bypass. Severity `critical` = −50. |

## How to interpret a real score

A real-world MCP server's findings often combine multiple checks. The
score subtracts each penalty in sequence; the grade boundaries are
fixed at 95/85/70/50.

Example walkthroughs of the registry rows produced from real public
metadata:

- **Stripe MCP — D / 50.** PRM is missing entirely (one critical
  spec_required finding). 100 − 50 = 50 = D.
- **Notion MCP — D / 55.** PKCE advertises `plain` (error, −15) +
  no RFC 8707 (error, −15) + PKCE-002 drift (error, −15) →
  100 − 15 − 15 − 15 = 55 → D. The scanner also reports "no DCR
  endpoint" (`MCP-DCR-001`, warning) but that finding is **advisory**
  and is **not** subtracted: DCR was demoted from SHOULD to MAY in MCP
  2025-11-25, so missing DCR is informational, never grade-affecting.
- **authgent demo — A / 100.** Implements every spec_required check.
  No advisory failures either, but those don't affect the grade.

The `/api/scan?url=...` response carries each finding so you can
reproduce the math yourself.

## Why advisory ≠ graded

The reviewer who flagged this caught a real footgun:
RFC 9207 `iss` and RFC 9449 DPoP **were not** mandatory until the MCP
2026-07-28 spec. Penalising every Auth0 / Okta / Keycloak instance
that hasn't shipped MCP support yet would have made the registry's
grades "everyone fails," and the conclusion wouldn't be "vendors are
behind"; it would be "the scanner is broken."

So those checks are now `tier="advisory"` — they show up in the report
("here's something to fix when you adopt MCP-2026") but they do not
move the letter grade.

## Reproducing the calibration locally

```bash
git clone https://github.com/authgent/authgent.git
cd authgent/server
pip install -e ".[dev]"
pytest tests/test_calibration.py -v
```

If you change a weight and a calibration row no longer matches, the
test fails before the scanner ships. Adding a new check requires
adding a calibration row that pins its expected grade impact.

## Reporting drift

If a real-world server's grade looks wrong:

1. Run `authgent-server lint <url> -f json` and capture the output.
2. Open an issue at <https://github.com/authgent/authgent/issues>.
3. We add the finding profile as a new calibration row, decide whether
   the weight is right, and either the scanner gets fixed or the test
   gets updated to pin the new behavior.

The disclosure window in
[`disclosure-policy.md`](disclosure-policy.md) gives vendors 14 days
to flag a calibration error before the grade publishes.
