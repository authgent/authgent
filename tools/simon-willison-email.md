# Simon Willison Email Pitch

## Recipient
Simon Willison  
Contact form: https://simonwillison.net/contact/

## Subject Line
```
MCP-OAuth scanner story: 30 production servers, only 1 earned an A
```

## Email Body

```
Hi Simon,

I've been following your MCP security coverage (especially your recent posts on LLM security and the datasette-llm work). I built something you might find interesting.

**The project:** authgent — an open-source scanner that audits MCP servers' OAuth implementation against 15 RFC-mapped checks (RFC 9728, 8414, 7636, 8707, etc.). Think "hadolint for MCP-OAuth."

**The data:** I scanned 30 production MCP servers (Notion, Cloudflare, Linear, Stripe, Figma, HubSpot, Slack, etc.). Results:
- **Only 1 server earned an A grade**
- 29/30 don't advertise RFC 8707 resource indicators (confused deputy risk)
- 3/7 EMA launch partners (Asana, Atlassian, Canva, Figma, Granola, Linear, Supabase) shipped broken PKCE (advertise S256-only, accept plain at /authorize)

**The methodology:** Fully reproducible. Every check maps to a specific RFC clause. Public registry at authgent.dev/registry shows per-vendor grades with finding details. CLI: `pip install authgent-server && authgent-server lint <url>`.

**Why this matters:** MCP grew from 0 to 51,311 servers in 18 months (per Glama). Enterprise-Managed Authorization (EMA) launched June 18, 2026 to fix this — but even the launch partners shipped it wrong. OAuth for agents is the new "HTTPS everywhere" problem.

**IETF angle:** authgent is the reference implementation cited in `draft-agnihotri-oauth-agent-impl-status` on datatracker. I'm implementing `draft-ietf-oauth-identity-chaining-14` (agent delegation chains, now in RFC Editor Queue) and `draft-ietf-oauth-transaction-tokens-08` (in WG Last Call).

**Would this make a blog post?** 

I can provide:
- Full scan data (CSV/JSON)
- Per-vendor findings breakdown
- Responsible disclosure timeline (14-day window, already notified failing vendors)
- Live reproduction steps (readers can scan their own servers)
- Attack vectors for each check (PKCE-drift, confused deputy, etc.)

I've documented everything at:
- Scanner + registry: https://authgent.dev/scan
- GitHub repo: https://github.com/authgent/authgent
- PKCE-drift attack writeup: https://github.com/authgent/authgent/blob/main/docs/attacks/pkce-drift.md
- IETF draft: https://datatracker.ietf.org/doc/draft-agnihotri-oauth-agent-impl-status/

The parallel I keep thinking about: in 2015, Let's Encrypt + EFF made "HTTPS everywhere" real by making it easy + free. In 2026, MCP needs the same thing for OAuth. The tooling exists (authgent scanner), the standard is stabilizing (identity-chaining-14 in RFC Ed queue), but adoption is a mess.

If this fits your editorial direction, I'd love to provide whatever data/context would be most useful. If not, no worries — I know your blog has a high bar.

Thanks for considering it,  
Dhruv Agnihotri

---

**Quick links:**
- Live scanner: https://authgent.dev/scan
- GitHub: https://github.com/authgent/authgent  
- Public registry: https://authgent.dev/registry
- EMA audit blog: https://authgent.dev/blog/2026-06-19-ema-launch-partner-pkce/
```

## Timing
Send Tuesday or Wednesday morning Pacific (best response rates per Simon's posting patterns)

## Follow-up Strategy
- If no response within 7 days: Send one gentle follow-up via Twitter DM: "Hey Simon — sent an email about MCP-OAuth scanner data. No pressure if it doesn't fit your blog, but wanted to make sure it didn't land in spam. Thanks!"
- If Simon publishes: Amplify on Twitter, HN (comment), Reddit. Coordinate Show HN launch for 24 hours after his post goes live (ride the amplification wave).

## Alternative Channel: Twitter DM
If email bounces or you want a faster response:

```
Hey Simon — built an open-source MCP-OAuth scanner (authgent). Scanned 30 production servers; only 1 earned an A. 29/30 fail RFC 8707, 3 EMA launch partners shipped broken PKCE.

Full methodology + public registry: authgent.dev/registry

Would this be interesting for a blog post? Happy to provide scan data, reproducibility steps, and disclosure timeline.

Repo: github.com/authgent/authgent
IETF draft: datatracker.ietf.org/doc/draft-agnihotri-oauth-agent-impl-status/
```

## Why Simon Specifically
- **50k+ blog readers** (per his own analytics posts)
- **HN front-page magnet** — his posts routinely hit #1
- **MCP security coverage** — already writing about LLM security, datasette, agent tooling
- **Standards-literate** — cites RFCs, appreciates IETF work
- **Independent voice** — not a vendor, high trust signal

## Backup Influencers (If Simon Passes)
1. **swyx (Latent Space podcast)** — 100k+ listeners, AI engineering focus
2. **Kelsey Hightower** — Cloud security, high Twitter reach
3. **Troy Hunt** — Security researcher, Have I Been Pwned creator
4. **Bruce Schneier** — Security blog, 200k+ readers
5. **Dan Lorenc (Chainguard)** — Supply chain security, OSS focus
