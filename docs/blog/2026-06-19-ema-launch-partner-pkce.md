---
title: "EMA-readiness: a conformance baseline for the Enterprise-Managed Authorization era"
description: A snapshot of the Model Context Protocol's Enterprise-Managed Authorization launch, and a checklist for verifying your MCP server is EMA-ready — with open-source scanner data on the current ecosystem state.
target_query: "MCP Enterprise Managed Authorization conformance"
publish_targets: ["dev.to", "lobste.rs", "medium"]
canonical: https://authgent.dev/blog/2026-06-19-ema-launch-partner-pkce/
date: 2026-06-19
draft: false
---

# EMA-readiness: a conformance baseline for the Enterprise-Managed Authorization era

On 2026-06-18 the Model Context Protocol's Enterprise-Managed Authorization (EMA) extension went **Stable** — [announced](https://modelcontextprotocol.io/extensions/auth/enterprise-managed-authorization) by MCP maintainer Paul Carleton on the MCP blog, and covered the same day by Frederic Lardinois in [The New Stack](https://thenewstack.io/mcp-gets-its-missing-enterprise-authorization-layer/). EMA replaces the per-app OAuth consent screen for enterprise users. It builds on a WG-adopted IETF draft, [Identity Assertion JWT Authorization Grant](https://datatracker.ietf.org/doc/draft-ietf-oauth-identity-assertion-authz-grant/) ("ID-JAG"), which lets an enterprise IdP vouch for a user once and have that assertion accepted across every MCP server an admin has pre-approved.

The launch had a clear cast. **Okta** is the launch IdP (its branded version is "Cross App Access"). **Anthropic** and **Microsoft** are launch clients (Claude and VS Code). And seven connectors / MCP servers shipped support on day one: **Asana, Atlassian, Canva, Figma, Granola, Linear, Supabase**. Getting a brand-new authorization extension integrated end-to-end across an IdP, two clients, and seven servers inside a single launch window is genuinely impressive work, done in good faith on a spec that only just stabilized.

EMA is real progress. It solves a friction point that has held enterprise MCP adoption back for months. It is also, per Aaron Parecki (Okta), explicitly a governance layer rather than a policy layer. Parecki calls it a "centralized governance plane"; The New Stack's coverage frames the boundary this way — the plane decides *who connects to what*, but not *whether a given action is allowed*. The decision about whether a particular agent may run a specific action on a specific resource still sits with the policy engines and gateways between an agent and the tools it calls.

That boundary is exactly why a conformance baseline is useful right now. EMA layers enterprise-grade *authentication* on top of an MCP server's *authorization* posture — it assumes that posture is already sound. So this post is a checklist: here's how to verify your MCP server is EMA-ready, and here's an open snapshot of where the ecosystem sits a day after launch, so everyone (the launch partners included) has a shared reference to tighten against.

## Ecosystem snapshot, 2026-06-19

Within 24 hours of the announcement, several launch connectors had updated their MCP authorization-server metadata, and three added the new `urn:ietf:params:oauth:grant-profile:id-jag` value to `authorization_grant_profiles_supported` — note this is a grant *profile* identifier, not a grant_type. (The actual OAuth grant_types in the EMA flow are `urn:ietf:params:oauth:grant-type:token-exchange`, used with `requested_token_type=urn:ietf:params:oauth:token-type:id-jag` to mint the ID-JAG, and `urn:ietf:params:oauth:grant-type:jwt-bearer` to redeem it.)

I then scanned the same metadata with the open-source [authgent](https://github.com/authgent/authgent) MCP-OAuth conformance scanner, which checks authorization-server metadata against the RFCs the MCP 2025-11-25 authorization spec requires (RFC 7591, 7636, 8414, 8707, 9728). Here's the snapshot:

| Vendor | EMA / ID-JAG profile advertised? | PKCE methods | RFC 8707 resource indicators |
|---|---|---|---|
| Asana | — | `["plain", "S256"]` | not advertised |
| Canva | Yes (`id-jag` profile in metadata) | `["plain", "S256"]` | not advertised |
| Figma | Yes | `["S256"]` | not advertised |
| Linear | Yes | `["S256"]` | not advertised |
| Granola | Yes | `["S256"]` | not advertised |
| Atlassian, Supabase | AS metadata not reachable at scan time | n/a | n/a |

Two patterns are worth surfacing, both as one-line config fixes rather than as anything to be alarmed about.

**Two connectors (Asana, Canva) still advertise `plain` PKCE alongside `S256`.** OAuth 2.1 ([draft-ietf-oauth-v2-1, §4.1.2.3](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1)) discourages `plain`; RFC 7636 §4.4.1 keeps it only as a transitional fallback that new servers shouldn't use. The MCP 2025-11-25 auth spec mandates PKCE with S256. The PKCE-downgrade family (catalogued by [OAuch](https://oauch.io/Threats/Info/BCP_4_8) as `BCP_4_8`, with CVE / GHSA entries against Authentik in 2024 and Better-Auth on 2026-05-31) is why OAuth 2.1 hardened the requirement. Dropping `plain` from `code_challenge_methods_supported` closes it.

**None of the reachable connectors *advertise* RFC 8707 resource indicators.** A caveat first: the scanner reads advertised AS metadata, not runtime behavior — a server can enforce the `resource` parameter at `/token` without setting `resource_indicators_supported: true`, and that distinction matters, so read this as "not advertised," not "not supported." That said, [RFC 8707](https://datatracker.ietf.org/doc/html/rfc8707) — also MCP-mandated — binds a token to a specific resource, which defeats the [confused-deputy pattern](https://www.obsidiansecurity.com/blog/when-mcp-meets-oauth-common-pitfalls-leading-to-one-click-account-takeover) Obsidian Security disclosed against several production MCP servers in January 2026. This matters a little more in the EMA era, because EMA's whole value is one IdP assertion accepted across many MCP servers: if the access tokens those servers mint aren't resource-bound, a token minted for one is more easily replayed against another. RFC 8707 is what keeps the blast radius narrow — and advertising it is a metadata flag plus a `resource`-parameter check at the token endpoint.

Neither of these is something EMA introduces, and neither is surprising. It's the well-known "new feature absorbs the engineering attention, the basics get a follow-up pass" pattern — and these are precisely the kind of follow-up that a stabilized spec plus a shared checklist make easy.

## What EMA fixes (and what it leaves to you)

EMA / ID-JAG solves a real problem. Pre-EMA, an enterprise user clicked "Allow" once per MCP-server-plus-app combination per quarter. For a 50,000-employee company with 30 MCP integrations, that was on the order of a million consent clicks a year. EMA collapses those into a single SSO at the IdP, and the IdP's governance plane decides which MCP servers a user may even attempt to connect to.

But EMA is not a substitute for OAuth conformance underneath it. The ID-JAG draft (`draft-ietf-oauth-identity-assertion-authz-grant`, rev -04, 2026-05-21; authored by Aaron Parecki, Karl McGuinness, and Brian Campbell; not yet an RFC) profiles RFC 8693 (token exchange) for the IdP-to-resource step and RFC 7521/7523 (JWT bearer) for the resource AS step. It assumes the underlying OAuth posture is sound. So the baseline below is the natural companion to turning EMA on.

## What to check on your own MCP server

If you operate an MCP server, three things to verify:

```bash
pip install authgent-server
authgent-server lint https://your-mcp.example.com
```

The relevant scanner check IDs:

- **MCP-PKCE-001** (MCP-mandated): PKCE methods. Should advertise `["S256"]` exactly. Removing `plain` from `code_challenge_methods_supported` is a one-line config change.
- **MCP-AUD-001** (MCP-mandated): RFC 8707. The AS metadata should set `resource_indicators_supported: true` and the `/token` handler should enforce the `resource` parameter.
- **MCP-EMA-001..004** (new this week, **advisory tier**): four readiness checks for EMA / ID-JAG. They surface whether your AS advertises the `id-jag` grant profile, whether `jwt-bearer` is in `grant_types_supported`, whether `jwks_uri` is reachable for assertion verification, and whether the same metadata also advertises `plain` PKCE. Being advisory-tier, **these checks never affect a server's letter grade** — we surface EMA-readiness without penalizing anyone for being early on a brand-new extension.

The full methodology, severity tiers, and remediation guidance are in [`docs/methodology.md`](https://github.com/authgent/authgent/blob/main/docs/methodology.md). The same code path runs as a CLI, a [GitHub Action](https://github.com/authgent/authgent/blob/main/.github/actions/mcp-lint/README.md), and a hosted scanner UI. The scanner is also documented as IETF Internet-Draft [`draft-agnihotri-oauth-agent-impl-status-00`](https://datatracker.ietf.org/doc/draft-agnihotri-oauth-agent-impl-status/) on datatracker.

## Coordinating with vendors

This snapshot is meant as a shared reference, not a scoreboard. Each connector named above gets a per-vendor email this week with its specific findings, the scanner's remediation hint, and a 14-day window before any grade publishes, per [`docs/disclosure-policy.md`](https://github.com/authgent/authgent/blob/main/docs/disclosure-policy.md). The public registry at <https://authgent.dev/registry/> shows each as "Vendor notified — grade publishes" with the per-vendor date, until the window lifts, and any fix that lands first refreshes the entry to the live state. Because the EMA checks are advisory, none of the EMA-readiness findings move a grade regardless.

## For enterprise security teams

If you're considering turning EMA on for your tenant: turn it on. It's better than what you had yesterday. Then run the scan above against the MCP servers in your inventory as part of onboarding — EMA governs *who connects*, not what each server does with the tokens the IdP just helped it mint, so a quick S256-and-8707 check rounds out the picture.

## Read more

- [The New Stack — MCP gets its missing enterprise authorization layer](https://thenewstack.io/mcp-gets-its-missing-enterprise-authorization-layer/) (Frederic Lardinois, 2026-06-18)
- [MCP Enterprise-Managed Authorization spec](https://modelcontextprotocol.io/extensions/auth/enterprise-managed-authorization)
- [draft-ietf-oauth-identity-assertion-authz-grant](https://datatracker.ietf.org/doc/draft-ietf-oauth-identity-assertion-authz-grant/) (ID-JAG, IETF OAuth WG)
- [authgent on GitHub](https://github.com/authgent/authgent) (the scanner used here, Apache 2.0)
- [authgent IETF Internet-Draft](https://datatracker.ietf.org/doc/draft-agnihotri-oauth-agent-impl-status/) (draft-agnihotri-oauth-agent-impl-status-00)
- [authgent disclosure policy](https://github.com/authgent/authgent/blob/main/docs/disclosure-policy.md)

Comments, corrections, and counter-readings welcome — the repo's [issue tracker](https://github.com/authgent/authgent/issues) is the right venue.
