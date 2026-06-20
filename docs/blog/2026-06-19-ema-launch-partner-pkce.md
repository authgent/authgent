---
title: "EMA launch partners shipped ID-JAG and `plain` PKCE in the same metadata document"
description: A 24-hour postmortem of the Model Context Protocol's Enterprise-Managed Authorization launch. Three of four reachable launch partners advertise the new ID-JAG grant profile in metadata that still fails OAuth-2.1 basics.
target_query: "MCP Enterprise Managed Authorization conformance"
publish_targets: ["dev.to", "lobste.rs", "medium"]
canonical: https://authgent.dev/blog/2026-06-19-ema-launch-partner-pkce/
date: 2026-06-19
draft: true
---

# EMA launch partners shipped ID-JAG and `plain` PKCE in the same metadata document

On 2026-06-18 The New Stack [announced](https://thenewstack.io/mcp-gets-its-missing-enterprise-authorization-layer/) the Model Context Protocol's Enterprise-Managed Authorization (EMA) extension. Same day, Anthropic enabled it in a Claude beta. The extension, sponsored by Okta and Microsoft, replaces the per-app OAuth consent screen for enterprise users. It uses a new IETF draft, [Identity Assertion JWT Authorization Grant](https://datatracker.ietf.org/doc/draft-ietf-oauth-identity-assertion-authz-grant/) ("ID-JAG"), to let an enterprise IdP vouch for a user once and have that vouching accepted across every MCP server an admin pre-approves.

EMA is real progress. It solves a friction point that has held enterprise MCP adoption back for nine months. It is also, per Aaron Parecki (Okta), explicitly *not* the layer that decides what actions an agent is allowed to take. From the New Stack article:

> "That governance plane decides who connects to what. It does not decide whether a given action is allowed, though." [...] Whether a particular agent should be allowed to run a specific action on a specific resource at a given moment is a decision that is managed by the policy engines and gateways that now typically sit between an agent and the tools it calls.

Within 24 hours of the announcement, four of the named launch partners (Anthropic, Microsoft, Okta, plus Asana, Atlassian, Canva, Figma, Granola, Linear, Supabase) had updated their MCP authorization-server metadata. Three of them (Linear, Canva, Figma) added the new `urn:ietf:params:oauth:grant-profile:id-jag` value to `authorization_grant_profiles_supported`. So far, so good.

Then I re-scanned them with the open-source [authgent](https://github.com/authgent/authgent) MCP-OAuth conformance scanner, which checks the same authorization-server metadata against the RFCs the MCP authorization spec requires (RFC 7591, 7636, 8414, 8707, 9207, 9728). The launch-day metadata has a problem.

## The result

| Vendor | EMA / ID-JAG advertised? | PKCE methods | RFC 8707 resource indicators |
|---|---|---|---|
| **Asana** | Launch partner | `["plain", "S256"]` | not supported |
| **Canva** | **Yes** (`id-jag` profile in metadata) | `["plain", "S256"]` | not supported |
| **Figma** | **Yes** | `["S256"]` (clean) | not supported |
| **Linear** | **Yes** | `["S256"]` (clean) | not supported |
| Atlassian | Launch partner | `["plain", "S256"]` | not supported |
| Granola, Supabase | endpoint not yet reachable | n/a | n/a |

Three observations.

**One: Canva and Asana ship `plain` PKCE in the same metadata document that advertises EMA.** OAuth 2.1 ([draft-ietf-oauth-v2-1, §4.1.2.3](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1)) forbids `plain`. RFC 7636 §4.4.1 reserves it as a transitional fallback that should not be used by any new server. Atlassian, also a launch partner, advertises the same. The PKCE-downgrade family (catalogued by [OAuch](https://oauch.io/Threats/Info/BCP_4_8) as `BCP_4_8`, with named CVE / GHSA entries against Authentik in 2024 and Better-Auth on 2026-05-31) was specifically the reason OAuth 2.1 hardened the requirement. EMA does not change that.

**Two: zero of the reachable launch partners advertise [RFC 8707](https://datatracker.ietf.org/doc/html/rfc8707) resource indicators.** RFC 8707 is the mechanism that binds a token to a specific resource, defeating the [confused-deputy pattern](https://www.obsidiansecurity.com/blog/when-mcp-meets-oauth-common-pitfalls-leading-to-one-click-account-takeover) Obsidian Security disclosed against multiple production MCP servers in January 2026. The MCP authorization spec at [`specification/2025-11-25/basic/authorization`](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization) lists RFC 8707 as a normative requirement. The launch-partner metadata makes it impossible for an MCP client to tell the AS *which* MCP server it intends to use the token at, which means a token minted for Linear is replayable against Asana.

**Three: ID-JAG support without RFC 8707 is worse than ID-JAG support with RFC 8707.** EMA's whole pitch is that an enterprise IdP issues a single assertion that is accepted across many MCP servers. If the access tokens those MCP servers mint from that assertion are not bound to a specific resource, the EMA assertion has effectively widened the blast radius of any token leak from one MCP server to all of them. That is not a vulnerability EMA introduces; it is a vulnerability the absence of RFC 8707 introduces. EMA just makes it more consequential because it ships those tokens in higher volume.

## What EMA actually fixes

To be clear about scope: EMA / ID-JAG is solving a real, important problem. Pre-EMA, an enterprise user had to click "Allow" once per MCP-server-plus-app combination per quarter. For a 50,000-employee company with 30 MCP integrations, that was 1.5M consent clicks a year. EMA collapses those to a single SSO at the IdP, and the IdP's policy engine decides which MCP servers the user is authorized to even attempt to connect to. That is genuinely better than the alternative.

But EMA is not OAuth-conformance. The ID-JAG draft itself profiles RFC 8693 (token exchange) for the IdP-to-resource step, and RFC 7521/7523 (JWT bearer) for the resource AS step. It assumes the underlying OAuth posture is sound. When the underlying posture advertises `plain` PKCE and skips RFC 8707, EMA is layering corporate-grade authentication on top of OAuth-2.1-noncompliant authorization.

## What to check on your own MCP server

If you operate an MCP server, three questions:

```bash
pip install authgent-server
authgent-server lint https://your-mcp.example.com
```

The relevant scanner check IDs:

- **MCP-PKCE-001**: PKCE methods. Should advertise `["S256"]` exactly. Removing `plain` from `code_challenge_methods_supported` is a one-line config change.
- **MCP-AUD-001**: RFC 8707. The AS metadata should set `resource_indicators_supported: true` and the `/token` handler should enforce the `resource` parameter.
- **MCP-EMA-001..004** (new this week): four advisory-tier checks for EMA / ID-JAG readiness. They surface whether your AS advertises the `id-jag` profile, whether `jwt-bearer` is in `grant_types_supported`, whether `jwks_uri` is reachable for assertion verification, and whether the same metadata also advertises the OAuth-2.1-forbidden `plain` PKCE method.

The full methodology, severity tiers, and remediation guidance are in [`docs/methodology.md`](https://github.com/authgent/authgent/blob/main/docs/methodology.md). The same code path runs as a CLI, a [GitHub Action](https://github.com/authgent/authgent/blob/main/.github/actions/mcp-lint/README.md), and a hosted scanner UI. The scanner is also documented as IETF Internet-Draft [`draft-agnihotri-oauth-agent-impl-status-00`](https://datatracker.ietf.org/doc/draft-agnihotri-oauth-agent-impl-status/) on datatracker.

## Disclosure

Each affected vendor will receive a per-vendor disclosure email this week with the same EMA-cycle context, their specific findings, the scanner's remediation hint, and a 14-day embargo per [`docs/disclosure-policy.md`](https://github.com/authgent/authgent/blob/main/docs/disclosure-policy.md). The public registry at <https://authgent.github.io/authgent/registry/> displays each vendor as "Vendor notified — grade publishes <date>" without the grade until the embargo lifts. Vendors who fix the issue before the deadline see the registry refresh to whatever the live state is.

## What this is not

This is not a vulnerability disclosure of EMA itself. EMA is fine; the spec is well-written and the launch partners did the integration work in good faith. The story is that *the OAuth basics underneath the new shiny extension are still broken at the same vendors that integrated the shiny new extension first.* That is interesting because it tells you something true about how rollouts of enterprise extensions interact with the underlying spec compliance: the new feature absorbs all the engineering attention and the basics quietly go unrevisited.

If you are an enterprise security team thinking about turning EMA on for your tenant: turn it on. It is better than what you had yesterday. But also have someone run the scan above against the MCP servers in your inventory before you let agents through. EMA does not change what those servers do with the tokens the IdP just helped them mint.

## Read more

- [The New Stack — MCP gets its missing enterprise authorization layer](https://thenewstack.io/mcp-gets-its-missing-enterprise-authorization-layer/) (Frederic Lardinois, 2026-06-18)
- [MCP Enterprise-Managed Authorization spec](https://modelcontextprotocol.io/extensions/auth/enterprise-managed-authorization)
- [draft-ietf-oauth-identity-assertion-authz-grant](https://datatracker.ietf.org/doc/draft-ietf-oauth-identity-assertion-authz-grant/) (ID-JAG, IETF OAuth WG)
- [authgent on GitHub](https://github.com/authgent/authgent) (the scanner used here, Apache 2.0)
- [authgent IETF Internet-Draft](https://datatracker.ietf.org/doc/draft-agnihotri-oauth-agent-impl-status/) (draft-agnihotri-oauth-agent-impl-status-00)
- [authgent disclosure policy](https://github.com/authgent/authgent/blob/main/docs/disclosure-policy.md)

Comments / corrections / counter-readings welcome. The repo's [issue tracker](https://github.com/authgent/authgent/issues) is the right venue.
