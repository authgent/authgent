# Scanner Methodology

How the authgent MCP-OAuth scanner produces a grade.

The scanner is open-source ([scanner.py](../server/authgent_server/scanner.py))
so every claim here is verifiable against the source. This page is the
human-readable companion linked from every grade.

## Grading

The scanner runs ten checks. Each check returns zero or more findings,
and each finding has two fields that determine its weight:

- **severity** — `info`, `warning`, `error`, or `critical`. Reflects how
  bad the failure is in absolute terms.
- **tier** — `spec_required` or `advisory`. **Only `spec_required`
  findings affect the letter grade.** `advisory` findings appear in the
  report but don't move the score; they exist so a legacy IdP that
  predates a 2026-spec requirement is not penalised before its operator
  ships MCP support.

Per-finding penalty:

| severity | penalty |
|---|---|
| `info` | −1 |
| `warning` | −5 |
| `error` | −15 |
| `critical` | −50 |

Score is `max(0, 100 − Σ penalties)` summed over `spec_required`
findings only. Letter grades:

| score | grade |
|---|---|
| 95–100 | A |
| 85–94 | B |
| 70–84 | C |
| 50–69 | D |
| 0–49 | F |

A single `critical` spec_required finding (e.g. PRM missing entirely)
drops the server from A to D. That's intentional: a server with no
RFC 9728 metadata can't be discovered by an MCP client at all, so the
rest of the spec doesn't matter.

## The checks

| ID | Tier | Sev | Spec | What it tests |
|---|---|---|---|---|
| **MCP-PRM-001** | spec_required | critical / error | [RFC 9728](https://datatracker.ietf.org/doc/html/rfc9728) | `/.well-known/oauth-protected-resource` exists, returns JSON with `resource` + `authorization_servers`. |
| **MCP-AS-001** | spec_required | error | [RFC 8414](https://datatracker.ietf.org/doc/html/rfc8414) | `/.well-known/oauth-authorization-server` reachable on the AS PRM points at. |
| **MCP-PKCE-001** | spec_required | critical / error | [RFC 7636](https://datatracker.ietf.org/doc/html/rfc7636), OAuth 2.1 | AS metadata advertises `S256`; does not advertise `plain`. |
| **MCP-PKCE-002** | spec_required | error | OAuth 2.1, [Obsidian Jan 2026](https://www.obsidiansecurity.com/blog/when-mcp-meets-oauth-common-pitfalls-leading-to-one-click-account-takeover) | Drift probe: `code_challenge_method=plain` at `/authorize` is rejected with the method named in the error response. |
| **MCP-AUD-001** | spec_required | error | [RFC 8707](https://datatracker.ietf.org/doc/html/rfc8707) | `resource_indicators_supported: true` advertised. |
| **MCP-DCR-001** | **advisory** | warning | [RFC 7591](https://datatracker.ietf.org/doc/html/rfc7591) | `registration_endpoint` advertised. *DCR was demoted from SHOULD to MAY in MCP 2025-11-25 — it is now OPTIONAL, so missing DCR is informational and does not affect the letter grade.* |
| **MCP-CSRF-001** | spec_required | critical | OAuth 2.1 | `response_types_supported` does **not** include `token` (implicit grant forbidden). |
| **MCP-DCR-MIRROR-001** | spec_required | critical | [RFC 7591](https://datatracker.ietf.org/doc/html/rfc7591), Obsidian Jan 2026 | Two consecutive registrations with the same payload return distinct `client_id`s. |
| **MCP-ISS-001** | **advisory** | warning | [RFC 9207](https://datatracker.ietf.org/doc/html/rfc9207) / MCP SEP-2468 | `authorization_response_iss_parameter_supported: true` advertised. *Mandatory only in MCP 2026-07-28; pre-spec IdPs get a pass.* |
| **MCP-REFRESH-001** | **advisory** | warning | [RFC 9449](https://datatracker.ietf.org/doc/html/rfc9449) | DPoP advertised when refresh tokens are issued to public clients. *Best practice; not currently MCP-mandatory.* |
| **MCP-PASSTHROUGH-001** | **advisory** | info | MCP authorization spec | Heuristic: GET / returns 200 unauthenticated. *May be a legitimate landing page; surfaced for review.* |

## What drives the grade vs. what doesn't

The rubric's authority rests on grading only against what the MCP
authorization spec (and the RFCs it normatively cites) actually
**mandates**. Everything else is surfaced as advice, never as a grade
penalty. The two buckets are explicit:

**MCP-spec-mandated — `spec_required`, drives the letter grade:**

- `MCP-PRM-001` (RFC 9728 PRM)
- `MCP-AS-001` (RFC 8414 AS metadata)
- `MCP-PKCE-001` (RFC 7636 / OAuth 2.1 — S256, no `plain`)
- `MCP-PKCE-002` (OAuth 2.1 — advertise-vs-enforce drift)
- `MCP-AUD-001` (RFC 8707 resource indicators)
- `MCP-CSRF-001` (OAuth 2.1 — implicit grant forbidden)
- `MCP-DCR-MIRROR-001` (RFC 7591 — *if* a server ships DCR, distinct
  registrations must yield distinct `client_id`s; a static `client_id`
  is the Obsidian consent-cache-bypass flaw). Note this is *conditional*:
  it only fires against servers that actually expose DCR, and it grades
  "DCR shipped broken," not "DCR not shipped."

**OAuth best-practice / beyond-spec — `advisory`, informational only:**

- `MCP-DCR-001` (RFC 7591 — DCR was demoted from SHOULD to MAY in MCP
  2025-11-25; DCR is now OPTIONAL, so missing DCR never moves the grade)
- `MCP-ISS-001` (RFC 9207 — mandatory only in MCP 2026-07-28)
- `MCP-REFRESH-001` (RFC 9449 DPoP — best practice, not MCP-mandatory)
- `MCP-PASSTHROUGH-001` (heuristic; may be a legitimate landing page)
- `MCP-EMA-001` … `MCP-EMA-004` (Enterprise-Managed Authorization /
  ID-JAG — an opt-in MCP extension built on a WG draft, not the spec)

The distinction that matters most for DCR: **"you must ship DCR"** is
not a spec requirement (advisory), but **"if you ship DCR it must not
be broken"** still is (spec_required). That is why `MCP-DCR-001` is
advisory while `MCP-DCR-MIRROR-001` remains spec_required.

## What "passing" looks like

A spec-conformant MCP server response on the AS metadata endpoint:

```json
{
  "issuer": "https://your-as.example.com",
  "authorization_endpoint": "https://your-as.example.com/authorize",
  "token_endpoint": "https://your-as.example.com/token",
  "jwks_uri": "https://your-as.example.com/.well-known/jwks.json",
  "registration_endpoint": "https://your-as.example.com/register",
  "response_types_supported": ["code"],
  "grant_types_supported": [
    "authorization_code",
    "client_credentials",
    "refresh_token",
    "urn:ietf:params:oauth:grant-type:token-exchange"
  ],
  "code_challenge_methods_supported": ["S256"],
  "resource_indicators_supported": true,
  "authorization_response_iss_parameter_supported": true,
  "dpop_signing_alg_values_supported": ["ES256"]
}
```

A spec-conformant PRM response:

```json
{
  "resource": "https://your-mcp-server.example.com",
  "authorization_servers": ["https://your-as.example.com"],
  "scopes_supported": ["read", "write"],
  "bearer_methods_supported": ["header"]
}
```

## False positives

- **DCR-MIRROR**: vendors that aggressively de-duplicate registrations
  by `client_name` or other heuristics will trigger this check. The
  scanner uses the literal probe name `authgent-lint-probe`. If your
  server normally returns distinct `client_id`s but de-dupes on this
  specific probe, please open an issue with the reproduction.
- **PKCE-002 (drift)**: this is a heuristic. Servers that respond with a
  generic 4xx that doesn't name the method *might* be enforcing the
  method server-side at the token endpoint instead of the authorize
  endpoint. The check errs toward signal — re-run with the CLI's
  verbose mode to see the raw response and rule the finding out.

## Reproducing a result

Anyone can re-run any registry result locally:

```bash
pip install authgent-server
authgent-server lint <url>          # human output
authgent-server lint <url> -f json  # the same data structure the API returns
authgent-server lint <url> -f github  # GitHub Actions annotations
```

Or in CI:

```yaml
- uses: authgent/authgent/.github/actions/mcp-lint@v0.3.2
  with:
    url: https://your-mcp-server.example.com
    fail-on: error
```

The hosted endpoint is `https://authgent-demo.dhruvagnihotri.com/api/scan?url=…`.
The same scanner powers the registry, the CLI, and the Action — there
is no second implementation that could disagree.

## Disclosure

Vendor disclosure timeline, opt-out, and correction process are in
[`disclosure-policy.md`](disclosure-policy.md).
