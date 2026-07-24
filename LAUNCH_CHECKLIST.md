# 🚀 authgent Launch Checklist — Your Minimal Actions

## The Truth: You Already Built 90% of What ESLint Has

You have:
- ✅ Scanner (15 RFC checks, A-F grading)
- ✅ Badge API (embeddable shields)
- ✅ Registry (8 vendors, embargo system)
- ✅ GitHub Action (baseline mode, annotations)
- ✅ Hosted UI (authgent.dev/scan, authgent.dev/registry)
- ✅ 4 blog posts (1 published, 3 ready to publish)
- ✅ Disclosure machinery (30 vendors scanned June 21)
- ✅ IETF draft on datatracker

**What ESLint had that you don't:** Distribution channels.

ESLint didn't win by being better — it won by being in:
- npm search results
- Framework docs (React, Babel, Create React App)
- awesome-lists (awesome-javascript)

You're in **none** of those for MCP.

---

## Your 5 Human Actions This Week

I've already done the programmatic work (flipped blog drafts to published, added badge to README, drafted all the outreach content). You just need to execute these 5 distribution actions:

### ✅ ACTION 1: Submit awesome-mcp-servers PR (30 minutes)

**Why this first:** 90,300 stars = instant discoverability. ESLint's inflection point was getting into awesome-javascript.

**What to do:**
1. Go to https://github.com/punkpeye/awesome-mcp-servers
2. Fork the repo
3. Add this line to the "Security & Compliance" section (create if doesn't exist):
   ```markdown
   - [authgent](https://github.com/authgent/authgent) - Open-source MCP-OAuth compliance scanner. Grades servers A-F against 15 RFC checks (9728, 8414, 7636, 8707, etc.). CLI + hosted scanner + GitHub Action + embeddable badge. Catches PKCE advertise-drift and missing protected resource metadata.
   ```
4. Submit PR with title: "Add authgent - MCP-OAuth compliance scanner"
5. Use PR body from `tools/awesome-mcp-pr.md`

**Expected outcome:** PR merged within 7 days. Instant SEO + discoverability boost.

---

### ✅ ACTION 2: Post 4 GitHub issues on frameworks (2 hours total)

**Why:** LangChain (141k stars), FastMCP (26k stars), CrewAI (54.9k stars), LlamaIndex (36k stars) control distribution to 300k+ developers. ESLint won when babel-eslint shipped.

**What to do:**
1. Open `tools/framework-outreach-templates.md`
2. Copy template #1 (LangChain)
3. Go to https://github.com/langchain-ai/langchain/issues/new
4. Paste title + body
5. Submit
6. Repeat for FastMCP, CrewAI, LlamaIndex (templates 2-4)

**Expected outcome:** 2-3 maintainers respond positively within 14 days. At least 1 accepts some form of integration (even just a doc link).

---

### ✅ ACTION 3: Email Simon Willison (15 minutes)

**Why:** Simon's blog gets 50k+ readers. His posts hit HN front page. He writes about MCP security. One blog post from him = 6 months of organic growth.

**What to do:**
1. Open `tools/simon-willison-email.md`
2. Go to https://simonwillison.net/contact/
3. Copy subject + body
4. Send
5. If no response in 7 days, send one gentle Twitter DM follow-up

**Expected outcome:** 50% chance he publishes a blog post within 2-3 weeks. If he does, coordinate Show HN launch for 24 hours after.

---

### ✅ ACTION 4: Post Show HN (30 minutes + 6-hour monitoring)

**Why:** HN is where technical products get discovered. ESLint's Feb 27, 2015 launch hit front page. 100+ points = 1000+ views.

**What to do:**
1. Open `tools/show-hn-post.md`
2. Pick a Tuesday or Wednesday, 8-10am Pacific
3. Go to https://news.ycombinator.com/submit
4. Title: "Show HN: I scanned 30 production MCP servers' OAuth – only 1 earned an A"
5. URL: https://github.com/authgent/authgent
6. Text: (copy from show-hn-post.md)
7. Monitor for 6 hours, respond to every comment within 30 minutes

**Expected outcome:** 50-200 points, 10-50 comments, 50-200 GitHub stars in 48 hours.

---

### ✅ ACTION 5: Cross-post blogs to dev.to + Medium (1 hour)

**Why:** Your blog posts are published in the repo but not distributed. dev.to + Medium = different audiences + SEO.

**What to do:**
1. Go to https://dev.to/new
2. Copy content from `docs/blog/2026-06-19-ema-launch-partner-pkce.md`
3. Add canonical URL: `https://github.com/authgent/authgent/blob/main/docs/blog/2026-06-19-ema-launch-partner-pkce.md`
4. Publish
5. Repeat for the 3 other blog posts (MCP checklist, Claude Desktop debug, RFC 9728)
6. Same process on Medium

**Expected outcome:** 500-2000 views per post, backlinks, SEO juice.

---

## Timing Strategy (Week-by-Week)

### Week 1: Plant Seeds
- **Monday:** ACTION 1 (awesome-mcp PR)
- **Tuesday:** ACTION 2 (framework issues - LangChain, FastMCP)
- **Wednesday:** ACTION 3 (email Simon)
- **Thursday:** ACTION 2 cont. (CrewAI, LlamaIndex)
- **Friday:** ACTION 5 (cross-post blogs)

### Week 2: Coordinated Launch
- **Monday:** Wait for framework responses, prepare Show HN
- **Tuesday:** ACTION 4 (Show HN launch) — if Simon published, do it 24 hours after his post
- **Wednesday-Thursday:** Monitor HN, respond to comments, tweet amplification
- **Friday:** Retrospective, plan follow-ups

---

## What I Already Did For You

✅ **Flipped 3 blog drafts to published** (set `draft: false`)
- `docs/blog/2026-06-13-mcp-server-oauth-checklist.md`
- `docs/blog/2026-06-13-claude-desktop-oauth-not-working.md`
- `docs/blog/2026-06-13-rfc-9728-protected-resource-metadata.md`

✅ **Added authgent badge to your own README** (dogfooding it)

✅ **Drafted all outreach content:**
- `tools/awesome-mcp-pr.md` — PR title, body, entry text
- `tools/framework-outreach-templates.md` — 4 GitHub issue templates (LangChain, FastMCP, CrewAI, LlamaIndex)
- `tools/simon-willison-email.md` — Subject + body + timing strategy
- `tools/show-hn-post.md` — Title + body + response strategy

All you have to do is **copy-paste and send**.

---

## Why This Will Work (The ESLint Parallel)

| ESLint's Playbook | Your Execution |
|---|---|
| **Technical wedge** (parser pluggability) | MCP OAuth broken = forced audit |
| **Influencer coordination** (Sebastian McKenzie + Dan Abramov, Feb 27 2015) | Simon Willison blog + Show HN same week |
| **Framework integration** (babel-eslint) | LangChain + FastMCP issues |
| **Network effects** (Airbnb config, badges) | Badge API + registry |
| **Discovery** (awesome-javascript) | awesome-mcp-servers PR |
| **Default bundling** (Create React App) | FastMCP `init` template (if accepted) |

You have the same distribution machinery ESLint had. You just need to **activate it**.

---

## Success Metrics (30 Days Post-Launch)

**Leading Indicators (Week 1-2):**
- [ ] awesome-mcp-servers PR merged
- [ ] 2+ framework maintainers respond positively
- [ ] Show HN reaches 100+ points
- [ ] Simon Willison publishes blog post (50% chance)

**Lagging Indicators (Week 3-4):**
- [ ] 500+ GitHub stars (from current ~3)
- [ ] 10k+ PyPI downloads/month (from current ~200)
- [ ] 10+ MCP servers display authgent badge
- [ ] 1,000+ unique URLs scanned via registry
- [ ] 1+ framework integration merged

**North Star (6 Months):**
- [ ] Cited in MCP official docs
- [ ] 5,000+ GitHub stars
- [ ] 3+ framework integrations (LangChain, FastMCP, CrewAI)
- [ ] 100+ badge embeds
- [ ] IETF draft cited in OWASP AISVS

---

## The One Thing To Do First

If you can **only do ONE thing this week:**

🎯 **Submit the awesome-mcp-servers PR** (Action 1)

Why?
- 30 minutes of work
- 90,300 stars = instant discoverability
- Zero dependencies (no approval needed, just merge)
- Unlocks everything else (framework maintainers search awesome-lists first)

ESLint didn't win by being 10x better. It won by being 10x better **distributed**.

You have the product. Now execute the distribution playbook.

---

## Questions? Blockers?

If you hit any issues:
- Can't access Simon's contact form → Use Twitter DM backup in `tools/simon-willison-email.md`
- PR gets rejected → Submit to alternative awesome-lists (awesome-ai-agents, awesome-llm)
- Show HN gets flagged → Wait 24 hours, repost with different title
- Framework issues get ignored → Ping once after 7 days, then move to next framework

The system is fault-tolerant. Even if 50% of the actions fail, the remaining 50% still gets you farther than doing nothing.

**Your move.**
