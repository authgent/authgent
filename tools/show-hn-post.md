# Show HN Post

## Title
```
Show HN: I scanned 30 production MCP servers' OAuth – only 1 earned an A
```

## Body

```
I built authgent (https://github.com/authgent/authgent), an open-source scanner that audits MCP servers' OAuth implementation against 15 RFC-mapped checks. Then I ran it against 30 production MCP servers.

**The results:**
- Only 1 server earned an A grade
- 29/30 don't advertise RFC 8707 resource indicators (confused deputy vulnerability)
- 3 of the 7 Enterprise-Managed Authorization (EMA) launch partners shipped broken PKCE (advertise S256-only in discovery, accept `plain` at /authorize)
- 80% missing RFC 9728 Protected Resource Metadata (MCP clients can't discover the auth server)

**What it checks:**
- RFC 9728: Protected Resource Metadata (MUST for MCP)
- RFC 8414: Authorization Server Metadata
- RFC 7636: PKCE enforcement (detects advertise-drift heuristic)
- RFC 8707: Resource Indicators (prevents confused deputy attacks)
- RFC 9207: Authorization Server Issuer ID
- RFC 9449: DPoP sender-constrained tokens
- MCP 2025-11-25 authorization spec compliance
- EMA (ID-JAG) readiness

**Try it yourself:**
```bash
pip install authgent-server
authgent-server lint https://your-mcp-server.example.com
```

Or use the hosted scanner: https://authgent.dev/scan

**Public registry with grades:** https://authgent.dev/registry

**Responsible disclosure:** I notified all failing vendors 14 days before publishing. Several have already fixed the issues.

**Why this matters:**
MCP grew from 0 to 51,311 servers in 18 months. OAuth for AI agents is the new "HTTPS everywhere" problem. EMA shipped June 18, 2026 to standardize it — but even the launch partners (Asana, Atlassian, Canva, Figma, Granola, Linear, Supabase) shipped it broken.

**IETF angle:**
authgent is the reference implementation for `draft-ietf-oauth-identity-chaining-14` (agent delegation chains, now in RFC Editor Queue) and `draft-ietf-oauth-transaction-tokens-08` (in WG Last Call). The implementation is cited in `draft-agnihotri-oauth-agent-impl-status` on IETF datatracker.

**How it works:**
- Fetches `/.well-known/oauth-protected-resource` (RFC 9728)
- Probes authorization server metadata (RFC 8414)
- Tests PKCE enforcement heuristically (no client registration required)
- Checks for confused deputy vulnerabilities (RFC 8707)
- Grades A-F, outputs human/JSON/GitHub-workflow-annotations

**GitHub Action for CI:**
```yaml
- uses: authgent/authgent/.github/actions/mcp-lint@v0.3.4
  with:
    url: https://your-mcp-server.example.com
```

**Embeddable badge:**
```markdown
[![MCP OAuth Grade](https://authgent.dev/api/badge?url=https://your-server.com)](https://authgent.dev/scan/?url=https://your-server.com)
```

**The PKCE-drift heuristic:**
Most interesting finding: several servers advertise "PKCE S256 required" in their discovery metadata, but silently accept `code_challenge_method=plain` at the actual `/authorize` endpoint. This is a known vulnerability class (CWE-757), but hard to detect without registering a client. authgent uses an unauthenticated probe that triggers pre-PKCE rejection signals to detect this without littering vendor registration tables.

Full writeup: https://github.com/authgent/authgent/blob/main/docs/attacks/pkce-drift.md

**Open source, Apache 2.0:** https://github.com/authgent/authgent

Happy to answer questions about the methodology, findings, or IETF standards work.
```

## Timing
- **Best day:** Tuesday or Wednesday
- **Best time:** 8-10am Pacific (HN peak traffic)
- **Coordinate with:** Simon Willison blog post (if he publishes, post Show HN 24 hours later to ride the amplification wave)

## Prep Before Posting
1. ✅ Make sure authgent.dev/scan is responding quickly (test load)
2. ✅ Make sure GitHub repo README is polished (first-time visitors will judge in 10 seconds)
3. ✅ Have 2-3 "seed" comments ready from real users (NOT sockpuppets — people you've told about the launch)
4. ✅ Clear your calendar for 6 hours to respond to every comment within 30 minutes

## Comment Response Strategy
**If someone asks about a specific RFC:**
> Great question. [RFC citation] requires [specific behavior]. In the scan, authgent checks [how]. The most common failure mode is [example]. Here's the exact code that implements the check: [GitHub link to scanner.py line].

**If someone says "just use Auth0/Okta":**
> Totally fair for many use cases. authgent is specifically for:
> 1. Self-hosted (no vendor lock-in)
> 2. IETF reference implementation (if you're implementing the spec yourself)
> 3. Scanner (audit existing servers, including Auth0/Okta)
>
> If Auth0/Okta work for you, use them. The scanner still applies — it checks any OAuth server's compliance.

**If someone questions the methodology:**
> Valid concern. The scanner runs 4 unauthenticated HTTP requests (documented here: [disclosure policy link]). The PKCE-drift check is a heuristic (may have false positives), so it's `advisory` tier, not graded. Every check maps to a specific RFC clause: [methodology doc link].

**If someone found a bug:**
> Thanks for catching that! Could you file an issue with reproduction steps? [GitHub issues link]. I'll fix it today.

**If someone asks "why not just read the docs":**
> Great point. The scanner exists because:
> 1. OAuth 2.1 + MCP pulls in 13 RFCs — easy to miss one
> 2. Discovery metadata often lies (advertises S256, accepts plain)
> 3. Running code tests the actual behavior, not the docs
> 4. CI integration (fails PRs that break OAuth)

## Post-Launch Amplification
After posting Show HN:
1. **Tweet the HN link** with context: "Posted authgent (MCP-OAuth scanner) to Show HN. Scanned 30 production servers, only 1 passed. Thread on findings..."
2. **Cross-post to Reddit** (r/ClaudeAI, r/programming, r/netsec) — wait 6 hours after HN to avoid looking spammy
3. **Email IETF OAuth WG list** (use OUTREACH.md template) — cite Show HN discussion as evidence of community interest
4. **LinkedIn post** (professional angle): "Released authgent, an open-source MCP-OAuth scanner cited in IETF draft..."

## If Show HN Doesn't Hit Front Page
Don't panic. Even 50-100 points = 500-1000 views, several GitHub stars, useful feedback. The goal isn't HN front page — it's planting the seed in the right communities.

Backup amplification:
- InfoQ (submit article based on scan findings)
- The New Stack (pitch story: "Why MCP-OAuth is broken and how to fix it")
- Changelog podcast (email changelog.com/news with pitch)

## What Success Looks Like
**Within 6 hours:**
- 100+ HN points (front page)
- 50+ GitHub stars
- 10+ comments with technical questions/feedback
- 1-2 maintainers from MCP ecosystem commenting positively

**Within 48 hours:**
- 200+ GitHub stars
- 5+ badge embeds in other MCP servers' READMEs
- 1-2 framework maintainers responding positively to integration issues
- Blog/podcast coverage from 1-2 outlets

**Within 2 weeks:**
- 500+ GitHub stars
- awesome-mcp-servers PR merged
- 1+ framework integration (even if just a doc link)
- Cited in MCP official docs or Discord

## Emergency Contacts
If the site goes down or scanner breaks during launch:
- Have your phone handy to SSH into server
- Pre-deploy a static "scanner is overloaded, check back in 30min" page
- Post update in HN comments immediately: "Traffic spike broke the hosted scanner (good problem!). CLI still works: `pip install authgent-server`. Fixing now."
