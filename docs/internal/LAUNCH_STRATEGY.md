# authgent Launch Strategy — Platform Sequencing & Timing

## The Core Question: Stars First or Content First?

**Answer: Content first, then stars, then authority publication. Here's why.**

The research is clear (arxiv study of 138 launches, daily.dev 30-day guide, multiple HN post-mortems):

1. **Dev.to/blog post 1–2 days BEFORE Hacker News** — Gets indexed by Google/daily.dev so when HN traffic spikes, people who Google your project find a real article, not just a bare repo. This is the single most actionable finding.
2. **Hacker News is the star engine** — Average of 121 stars in 24 hours, 289 in a week from a front-page Show HN (arxiv study, 2024–2025 data). You don't get stars first and then post — you post and that's how you get stars.
3. **InfoQ requires original, unpublished content** — Their guidelines are explicit: "We do not publish posts that have already been published somewhere else on the internet." So the InfoQ piece MUST be a different article than what you post on Dev.to. This means you need TWO articles, not one.

---

## The Two-Article Strategy

### Article 1: "The Builder Story" (Dev.to / personal blog)
- **Tone:** Practitioner, first-person, "how I built this"
- **Content:** Why you built authgent, the MCP auth gap, technical decisions, code snippets, how to use it
- **Purpose:** SEO landing page, HN anchor, community engagement
- **Where:** Dev.to + cross-post to Hashnode + your blog
- **When:** 1–2 days before Hacker News launch

### Article 2: "The Architecture Deep-Dive" (InfoQ)
- **Tone:** Third-person technical, industry analysis, RFC-focused
- **Content:** Delegation chain architecture, chain splicing attack, DPoP for agents, two schools of thought (OAuth vs. custom protocols)
- **Purpose:** Credibility, thought leadership, industry positioning
- **Where:** InfoQ (exclusive, never published elsewhere)
- **When:** 4–6 weeks after launch (once you have stars, users, and credibility)

**These two articles serve completely different purposes and audiences. They do NOT cannibalize each other.**

---

## The Sequencing — 5 Phases

```
PRE-LAUNCH          LAUNCH DAY         WEEK 1              WEEKS 2-4           WEEKS 5-8
(7 days before)     (THE day)          (momentum)          (sustained growth)   (authority)

Polish repo         Show HN 9AM ET     Answer every issue   Reddit deep-dives   Submit InfoQ
README + badges     Reddit 30min later  Dev.to follow-up     LangChain/CrewAI     proposal
Publish Dev.to      LinkedIn + X same   LinkedIn articles    integration PRs     Speak at meetups
Seed 5-10 stars     day                 Fix bugs from        Comparison guides   IETF reference
from network        Engage ALL          feedback             YouTube demo         (if accepted)
                    comments <2hr       GitHub Discussions
```

---

## Phase 0: Pre-Launch Prep (Days -7 to -1)

### GitHub Repo Polish
- [ ] **README** — Must be exceptional. Clear problem statement, architecture diagram, quickstart in <30 seconds, comparison table, badges (tests passing, PyPI version, npm version, license)
- [ ] **Contributing guide** — CONTRIBUTING.md exists, make sure it's welcoming
- [ ] **Issue templates** — Bug report, feature request, question
- [ ] **GitHub Discussions** — Enable and seed with a "Welcome" thread and an "Architecture Decisions" thread
- [ ] **Social preview image** — GitHub renders this in link previews. Make it clean: logo + tagline + architecture diagram. 1280×640px.
- [ ] **Pinned issues** — "Good first issues" for contributors
- [ ] **CI badge green** — All 320 tests passing in GitHub Actions

### Seed Stars (5–15)
- Ask personal network, colleagues, friends who are developers
- NOT fake stars, NOT star-for-star schemes — HN and Reddit communities smell this instantly
- The purpose is so the repo doesn't look like it has 0 stars when HN traffic arrives. Even 10 is enough.

### Dev.to Article — Publish Day -1 or -2
**Title options:**
1. "I Built an OAuth 2.1 Identity Provider for AI Agents — Here's What I Learned"
2. "Why AI Agents Need Their Own Identity Provider (and Why I Built One)"
3. "The MCP Auth Gap: Building authgent, an Open-Source OAuth 2.1 Server for Multi-Agent Systems"

**Structure (~2,000 words):**
1. The problem (500 words) — "My agents were passing API keys in plaintext. Then I read the MCP spec."
2. Why existing tools don't work (300 words) — Auth0 stops at first token, Keycloak has no agent awareness, AIM isn't OAuth 2.1
3. What I built (500 words) — Architecture overview, 5 grant types, delegation chains, DPoP, HITL
4. The hardest parts (400 words) — Atomic CAS, refresh token family reuse detection, DPoP nonce management
5. Try it (300 words) — pip install, docker compose up, 30-second quickstart

**Tags:** `#opensource #security #python #ai`

**Cross-post to:** Hashnode (canonical URL on Dev.to)

### PyPI + npm Publish
- [ ] `authgent-server` on PyPI
- [ ] `authgent` (SDK) on PyPI
- [ ] `authgent` on npm
- Publish these BEFORE the Dev.to article so the install commands work

---

## Phase 1: Launch Day (Day 0)

### Timing
- **Tuesday or Wednesday** (NOT Monday — too competitive; NOT Thursday/Friday — momentum dies into weekend)
- **9:00 AM Eastern Time** (6:00 AM Pacific) — catches East Coast morning + early European afternoon

### Hacker News — Show HN (THE anchor)

**Title (critical — only thing people see):**
> Show HN: authgent – Open-source OAuth 2.1 identity provider for AI agents

**Why this title works:**
- "Show HN" — categorizes correctly, people browsing for new projects
- "authgent" — name
- "Open-source" — HN loves this
- "OAuth 2.1" — signals standards-based, not toy
- "identity provider for AI agents" — clear value prop, timely topic

**Post body (first comment — keep it casual per HN culture):**

> Hey HN! I built authgent because I was trying to secure multi-agent systems and found a gap: MCP mandates OAuth 2.1 for auth, but there's no lightweight, agent-aware OAuth 2.1 server in the Python ecosystem.
>
> authgent is a FastAPI-based authorization server that handles the full OAuth 2.1 spec plus agent-specific features:
> - RFC 8693 token exchange with nested `act` claims (delegation chains — who authorized what)
> - DPoP (RFC 9449) — sender-constrained tokens so stolen tokens from logs are useless
> - Agent identity registry with lifecycle management
> - Human-in-the-loop step-up for sensitive operations
> - Python + TypeScript SDKs with LangChain/Express/Hono middleware
>
> It's ~6k lines of server code, 320 tests, and can run standalone or alongside your existing IdP (exchange Auth0/Okta id_tokens to start a delegation chain).
>
> GitHub: [link]
> Quick start: `pip install authgent-server && authgent serve`
>
> Happy to answer any questions about the architecture, the MCP auth gap, or the delegation chain splicing problem.

**HN Rules to Follow:**
- Link directly to GitHub repo (not your website — HN dev audience expects this)
- Don't send direct links to friends to upvote (HN detects this via referrer)
- Instead, screenshot your post position and text friends "search for authgent on HN"
- Respond to EVERY comment within 2 hours — this is the #1 factor for staying on front page
- Be candid about limitations: "No dashboard yet," "Single-tenant for now," "Attestation providers are pluggable but we ship a null default"

### Reddit — 30 Minutes After HN

**Subreddits (stagger across the day, don't spam all at once):**

| Subreddit | Time | Post Style |
|---|---|---|
| r/Python | +30 min | "I built an OAuth 2.1 authorization server for AI agents in FastAPI" |
| r/MachineLearning | +2 hours | "Securing multi-agent delegation chains with OAuth 2.1 [Project]" |
| r/selfhosted | +4 hours | "Self-hosted OAuth 2.1 server for AI agents — Docker, SQLite/Postgres" |
| r/opensource | +6 hours | "authgent: open-source identity provider for AI agents (Apache 2.0)" |
| r/netsec | Day 2 | "Delegation chain splicing in RFC 8693 — a structural weakness and mitigation" (security angle, link to IETF thread) |

**Reddit rules:**
- Each subreddit has different norms. r/Python loves "I built X" posts. r/netsec wants security analysis, not product launches. r/MachineLearning wants [Project] tags.
- Don't cross-post the same text. Tailor each post.
- Engage in comments. Reddit upvotes engaged authors.

### LinkedIn — Same Day, After HN is Live

**Post style:**
- Personal story format (LinkedIn algorithm loves this)
- "I spent the last few months building something I wish existed: an OAuth 2.1 identity provider for AI agents..."
- Include the architecture diagram as an image (LinkedIn prioritizes native images over links)
- Tag relevant people: if you know anyone at Auth0, Anthropic, Google, LangChain — tag them respectfully
- End with a clear CTA: "If you're building multi-agent systems and struggling with auth, give it a try: [GitHub link]"
- **Do NOT post the HN link on LinkedIn** — that's seen as vote solicitation

### X (Twitter) — Same Day

- Thread format: 5–7 tweets
- Tweet 1: Hook + architecture diagram image
- Tweet 2–5: Key features (delegation chains, DPoP, HITL, MCP compliance)
- Tweet 6: The "try it" tweet with quickstart command
- Tweet 7: "Built in the open. 320 tests. Apache 2.0. PRs welcome."
- Screenshot your HN ranking as it climbs and post updates

---

## Phase 2: Week 1 — Momentum Maintenance

### Day 1–2: Respond to Everything
- Every HN comment, every Reddit reply, every GitHub issue, every LinkedIn comment
- File bugs reported by community immediately (shows you're responsive)
- Star count screenshot → LinkedIn/X update ("100 stars in 24 hours — thanks!")

### Day 3–4: Follow-Up Dev.to Article
**Title:** "How authgent Handles Multi-Hop Agent Delegation with RFC 8693 Token Exchange"
- Deep-dive into ONE feature (delegation chains)
- Show the decoded JWTs at each step
- This serves as linkable reference for HN/Reddit commenters asking "how does delegation work?"

### Day 5–7: GitHub Hygiene
- Label and respond to all issues
- Merge any reasonable PRs from community
- Update README with anything people asked about repeatedly
- Add "Featured in" section if you hit HN front page / any newsletter mentions

---

## Phase 3: Weeks 2–4 — Sustained Growth

### Content Cadence (1 article per week)
| Week | Platform | Topic |
|---|---|---|
| Week 2 | Dev.to | "DPoP for AI Agents: Why Bearer Tokens in Agent Logs Are a Security Nightmare" |
| Week 3 | Dev.to | "Adding Auth to Your LangChain Agent in 5 Minutes with authgent" |
| Week 4 | Dev.to / Hashnode | "authgent vs. AIM vs. Agent Auth Protocol: An Honest Comparison" |

### Integration PRs
- **LangChain** — Submit a documentation PR or example showing authgent integration
- **CrewAI** — Same
- **FastAPI docs** — If appropriate, contribute an OAuth 2.1 example

### Community Building
- Enable GitHub Sponsors (even if nobody pays — it's a credibility signal)
- Discord or GitHub Discussions for real-time community
- Weekly "This week in authgent" update on Discussions

### Metrics Targets (Realistic)

| Metric | Week 1 | Week 4 | Note |
|---|---|---|---|
| GitHub Stars | 100–300 | 500–1,000 | HN front page = ~200 in 48h |
| PyPI downloads | 200–500 | 1,000+ | pip install from article readers |
| npm downloads | 50–150 | 300+ | Smaller TS agent ecosystem |
| GitHub Issues | 10–20 | 30–50 | Sign of real usage |
| Contributors | 1 (you) | 2–5 | First PRs from community |

---

## Phase 4: Weeks 5–8 — Authority (InfoQ Submission)

### Why Wait Until Now

1. **InfoQ acceptance rate is 10%.** They get hundreds of submissions per month. Your proposal is stronger with "500 GitHub stars, featured on HN front page, 1,000+ downloads" than with "I just built this."
2. **InfoQ wants practitioners, not first-time authors.** Having Dev.to articles with engagement (comments, reactions) proves you can write.
3. **InfoQ wants real-world experience.** 4–6 weeks of production feedback, bug fixes, and community questions gives you genuine "lessons learned" content.
4. **InfoQ content must be ORIGINAL.** None of your Dev.to articles can be reused. The InfoQ piece must be a completely different angle — which is why we defined it as the architecture deep-dive, not the launch story.

### InfoQ Submission Checklist

From the actual InfoQ guidelines (https://www.infoq.com/guidelines/):

- [ ] Send to **editors@infoq.com** or use their [submission form](https://docs.google.com/forms/d/e/1FAIpQLSc2FVGgAh-_QTuXWLDolKfpRLr9nI5R80WtGIlntl-CMb9Dvg/viewform)
- [ ] **One proposal at a time**, max one per quarter, max 3 consecutive declines per year
- [ ] Include:
  - Proposed title
  - Topic focus
  - Target reader persona (Architecture & Design + AI/ML)
  - Technologies discussed (OAuth 2.1, RFC 8693, RFC 9449, MCP, FastAPI, Python)
  - What makes it different (gap analysis from INFOQ_PROPOSAL.md)
  - Based on real-world experience? YES (6+ weeks of building + community feedback)
  - Case studies: multi-agent delegation, agent deactivation incident response, HITL step-up
  - Code examples: YES (token exchange, DPoP proof, delegation chain validation)
  - 5 key takeaways (already written in INFOQ_PROPOSAL.md)
  - Confirmation of AI usage policy review
  - Confirmation of image/legal policy review
  - Author bio + LinkedIn
  - Timeline for draft completion
- [ ] Article must be **1,500–4,000 words** (target 3,000)
- [ ] **Conversational voice**, assume expert readers, no introductory explanations
- [ ] **Marketing-free** — authgent is the reference implementation, not the subject

### InfoQ Article Content (Different from Dev.to!)

**Use the full plan from INFOQ_PROPOSAL.md**, but key difference from Dev.to articles:
- No "I built this" framing
- No install instructions
- No star counts
- Focus: "Here is the architectural problem, here are the standards, here is how you solve it, here is working code"
- authgent mentioned as "the reference implementation" in section 3, not in the title

---

## Phase 5: Ongoing (Months 2–6)

### Second HN Post (Month 2–3)
- HN allows re-posting if you have **substantial new content**
- Angle: "authgent now supports X" or a technical blog post about a specific problem
- Must use a different URL than the first post (HN greys out visited links)

### Conference Talks
- **PyCon** — CFP typically closes months in advance, but lightning talks often available
- **Local meetups** — Python, security, AI meetups. Lower bar, immediate.
- **IETF side meeting** — If you have the nerve, present signed delegation receipts at an OAuth-WG side meeting

### Potential Newsletter Pickups (Organic — Don't Pitch)
- **TLDR** — Monitors HN front page, auto-features
- **Python Weekly** — Submit via their form
- **This Week in Security** — If you angle the security story
- **daily.dev** — Auto-aggregates from Dev.to

---

## Decision Matrix: What to Do When

| Situation | Action |
|---|---|
| "Should I post Dev.to before or after HN?" | **Before** — 1-2 days. SEO indexing + Google Discover. |
| "Should I get stars before HN?" | **Seed 5-15** from network. HN IS how you get stars. |
| "Should I post InfoQ before or after launch?" | **After** — 4-6 weeks. You need credibility + original angle. |
| "Can I post the same article on Dev.to and InfoQ?" | **NO.** InfoQ requires exclusive original content. Two different articles. |
| "Should I post on Reddit same day as HN?" | **Yes** — stagger by subreddit, 30min to 6hr gaps. |
| "Should I email Auth0/Okta/Anthropic?" | **Not yet.** Wait until you have stars + community. Cold outreach without traction is ignored. |
| "What if HN post dies?" | Post a technical article (not Show HN) 2-3 weeks later with a different angle. |
| "When do I pitch TLDR/newsletters?" | **Don't.** TLDR monitors HN automatically. Python Weekly has a submit form. Let it be organic. |

---

## The Critical Path (Summary)

```
TODAY
  │
  ▼
WEEK -1: Polish repo, publish PyPI/npm, write Dev.to article
  │
  ▼
DAY -1: Publish Dev.to article (get indexed)
  │
  ▼
DAY 0 (Tuesday/Wednesday):
  09:00 ET — Show HN (link to GitHub)
  09:30 ET — r/Python
  11:00 ET — r/MachineLearning
  12:00 ET — LinkedIn personal story
  13:00 ET — X/Twitter thread
  14:00 ET — r/selfhosted
  16:00 ET — r/opensource
  │
  ▼
WEEK 1: Engage everything, follow-up Dev.to article, fix bugs
  │
  ▼
WEEKS 2-4: Weekly Dev.to articles, integration PRs, community building
  │
  ▼
WEEK 5-6: Submit InfoQ proposal (DIFFERENT article, original content)
  │
  ▼
WEEK 8-10: InfoQ publication (if accepted) — coordinate with v0.2 release
  │
  ▼
MONTH 3+: Second HN post, conference talks, sustained content
```

---

## Anti-Patterns to Avoid

1. **Don't launch on InfoQ first.** You'll waste your one quarterly shot with zero traction. InfoQ editors check your GitHub — 0 stars is a red flag.
2. **Don't post the same content everywhere.** Dev.to = builder story. Reddit = tailored per subreddit. InfoQ = architecture deep-dive. Each platform has different norms.
3. **Don't ask people to "star my repo."** Show the work, let it be organic. Star-begging on HN or Reddit gets you downvoted.
4. **Don't launch on Friday.** Momentum dies over the weekend.
5. **Don't ignore HN comments.** Responding within 2 hours is the strongest signal of an engaged maintainer. HN readers become contributors.
6. **Don't make the InfoQ article a product pitch.** Their guidelines are explicit: "marketing-free." Present it as "here's how to solve this architectural problem" with authgent as the reference implementation.
7. **Don't wait for perfection.** Ship with known limitations and be honest about them. "No dashboard yet" is fine. "We're working on multi-tenancy" is fine. HN respects honesty.
8. **Don't submit to InfoQ before you have the Dev.to articles as proof of writing ability.** InfoQ editors will Google you. Having published technical content = credibility.
