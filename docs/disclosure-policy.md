# Disclosure Policy — authgent MCP-OAuth Registry

The MCP-OAuth Registry at <https://authgent.github.io/authgent/registry/>
publishes scan results for public MCP servers. This page documents the
ground rules so vendors, security teams, and the project itself can
operate from the same playbook.

## What we publish

- The **public** OAuth metadata at `/.well-known/oauth-protected-resource`
  and `/.well-known/oauth-authorization-server` of each listed server.
- A grade (A–F) computed only from **`tier="spec_required"` findings** —
  normative requirements of the MCP 2025-11-25 / 2026-07-28 authorization
  spec, OAuth 2.1, or a cited RFC.
- Best-practice / advisory findings (e.g. RFC 9449 DPoP, RFC 9207 `iss`
  advertisement) are surfaced in the report but **do not affect the
  letter grade**, so a legacy IdP that predates the MCP spec is not
  penalised before its operator has had a chance to ship MCP support.

We never publish:

- Anything that requires authentication to retrieve.
- Anything observed in a flow we drove past the consent step.
- A vendor's customer data, traffic, or tokens.

## Probing

The scanner makes a small number of unauthenticated HTTP requests:

1. `GET /.well-known/oauth-protected-resource`
2. `GET /.well-known/oauth-authorization-server` (resolved from the PRM)
3. `POST {registration_endpoint}` twice with a deliberately benign client
   payload to detect the [Obsidian Jan 2026][obsidian] DCR mirror pattern.
   The probe registers a client named `authgent-lint-probe` with no
   scopes; vendors who wish to drop these registrations can match on
   that client_name.
4. `GET {authorization_endpoint}?...code_challenge_method=plain` to detect
   advertise-vs-enforce drift on PKCE.

Each request runs once, with a tight per-target timeout. Total bytes per
scan are small (kilobytes). All requests are issued from
`authgent-demo.dhruvagnihotri.com` so vendor security teams can identify
and allow / deny the source.

[obsidian]: https://www.obsidiansecurity.com/blog/when-mcp-meets-oauth-common-pitfalls-leading-to-one-click-account-takeover

## Pre-publication notice (14-day window)

When the registry is *seeded* with a new target (or when a new check is
added that materially changes a target's grade), we mark the entry with
``embargo_until = now + 14 days`` before publishing the grade. During
the window:

- The registry shows the entry as "Vendor notified · grade publishes
  YYYY-MM-DD" — visible, but no grade.
- We email the vendor's `security@` mailbox (or, if absent, the
  designated contact in their `.well-known/security.txt` or PRM
  metadata) with the full finding list and the disclosure date.
- Any fix that lands during the window before the deadline removes
  the relevant finding. The grade publishes whatever the live state is
  on the deadline date.

After the disclosure date the grade is published and refreshes hourly.

## Opt-out

Vendors who do not wish to be listed publicly can email
`security@authgent.dev` (subject: "registry opt-out: <hostname>") and we
will set `opted_out: true` on the next deploy. Opted-out targets are
hidden from the registry response entirely. We never list a target that
has asked to be excluded.

## Correction process

If you believe a finding is in error:

1. Open a GitHub issue at <https://github.com/authgent/authgent/issues>
   with the URL, the check ID, and the reproduction steps that show the
   finding is false.
2. We respond within 3 business days.
3. If the finding is wrong, the check is fixed and the registry refreshes
   automatically. Where appropriate, the test fixture is added to
   `docs/calibration.md` so the regression cannot recur silently.

## What this is not

The registry is **not a vulnerability disclosure**. It does not publish
exploits, working PoCs, or vulnerability details that would not be
discoverable from public metadata.

If you find a real vulnerability in a listed MCP server (not a metadata
finding), please report it directly to the vendor under their disclosure
policy — not via this registry.

## Who runs this

The registry is a side project of Dhruv Agnihotri, maintainer of
[authgent](https://github.com/authgent/authgent). The scanner is
Apache 2.0; you can re-run any finding yourself with
`authgent-server lint <url>`.
