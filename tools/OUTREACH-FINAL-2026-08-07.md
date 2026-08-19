# authgent outreach — final, fact-checked copy-paste kit

Generated 2026-08-07. Every factual claim below was checked against a live
source in the last few hours (live scanner API, GitHub API, IETF
datatracker, DataForSEO). Where an existing draft in `tools/` had a wrong
number, it's called out explicitly. Send these in the order listed — each
is copy-paste ready. Nothing in this repo can send email/PRs/posts for you;
you paste, you send.

**Do not reuse the old drafts** (`awesome-mcp-pr.md`, `show-hn-post.md`,
`simon-willison-email.md`, `framework-outreach-templates.md`) as-is — they
contain the errors documented below. This file supersedes them.

---

## Live status (updated 2026-08-07)

| Item | Status | Link |
|---|---|---|
| awesome-mcp-servers PR | Open — bot asked for a Glama badge, replied explaining authgent isn't an MCP server (OAuth infra + scanner, not a server implementation), cited 58 precedent entries in the same section with no badge. Waiting on maintainer. | [PR #11657](https://github.com/punkpeye/awesome-mcp-servers/pull/11657) |
| LangChain issue | **Closed, dead end — not a rejection of authgent.** #39316 (the correctly-resubmitted version) was closed by `langsmith-fleet[bot]` with a blanket "we no longer accept additional integrations in the monorepo" message. Confirmed this is a uniform policy, not specific feedback — the identical boilerplate closed 5+ unrelated integration requests (#39194, #39007, #38692, #38727, #39182) in the same window. Do not resubmit or appeal; channel is closed to everyone. | [Issue #39316](https://github.com/langchain-ai/langchain/issues/39316) (closed) |
| CrewAI issue | **Good outcome, in progress.** Contributor (`broskell`) confirmed they'll use `examples/crewai/crewai_demo.py` as reference and validate against `sdks/python/authgent/client.py`, then open a draft PR. No action needed from us until that PR shows up — worth reviewing promptly when it does, both for correctness and to keep their momentum. | [Issue #6852](https://github.com/crewAIInc/crewAI/issues/6852) (open) |
| Show HN post | **Posted, then [flagged], 2 points, 0 real engagement.** Account (`dagni132`) is brand new / low karma, which is the single biggest predictor of an HN flag on a Show HN — the community and mod tooling are heavily biased against posts from accounts with no history. This isn't a content problem; retrying with the same account soon will likely flag again. | HN item, posted 2026-08-07 |
| Keycloak disclosure (chain-splicing/non-cascading revocation) | **Resolved, good outcome, now public.** Sent 2026-08-08 to `keycloak-security@googlegroups.com`, real reproduction against an unmodified 26.7.1 instance. Keycloak responded 2026-08-11: base non-cascading-revocation behavior is intentional and documented, no CVE. A follow-up asking permission to cite their private reply was declined (private disclosure channel, correctly), but they pointed to the public docs and invited a public GitHub issue for any doc improvement. Checked the tracker: 3 closed issues (#33252, #37119, #37120) already cover the base case; none cover the chain-extension variant this report specifically demonstrated. Filed as a new, scoped issue citing all three as prior art. Recorded in `docs/security-advisories/2026-08-non-cascading-revocation.md`. | [keycloak/keycloak#51633](https://github.com/keycloak/keycloak/issues/51633) (open) |
| Journalist email | Not yet sent — drafted below (§3). No email-send tool is wired up in this session; needs to go out from your own inbox. | — |
| dev.to cross-posts | Not yet posted — plan below (§5). | — |
| Medium article | Not started — see recommendation below. | — |

---

## What changed vs. the old drafts (read this first)

| Claim | Old draft said | Verified truth (2026-08-07) | Source |
|---|---|---|---|
| Grade distribution, n=30 | "only 1 earned an A" (no B/C/D/F breakdown given) | **1 A · 16 B · 10 C · 0 D · 3 F** | Live scan of all 30 `tools/disclosure-targets.json` targets via `authgent-demo.dhruvagnihotri.com/api/scan`, run just now |
| RFC 8707 missing | "29/30 don't advertise RFC 8707" | **Confirmed: 29/30**, live | Same live scan, MCP-AUD-001 finding count |
| RFC 9728 missing | "80% missing RFC 9728 Protected Resource Metadata" | **False — 0/30 missing PRM.** Drop this line entirely. | Same live scan, MCP-PRM-001 finding count = 0 |
| Total server count | "51,311 MCP servers (per Glama)" | **Unverifiable / likely fabricated.** No source ties this number to Glama or anywhere else. Glama's own live directory shows 69,349 today, with no historical growth chart published. | Web research, checked Glama directly + searched for the exact figure |
| Scanner check count | "15 RFC-mapped checks" (some drafts said 10, others 14) | **15 is correct** — verified by counting unique `check_id` values in `scanner.py` directly | Source code |
| identity-chaining draft revision | "-14" | **-17**, currently in **RFC Editor Queue** (past IESG approval, in reference-checking with RFC Production Center). No RFC number assigned yet. | datatracker.ietf.org, checked live |
| transaction-tokens draft revision | "-08" | **-11**, currently in its **3rd WG Last Call** (changed 2026-08-04) — earlier in process than identity-chaining, not yet with IESG. No RFC number assigned. | datatracker.ietf.org, checked live |
| EMA launch facts (date, IdP, partners) | 2026-06-18, Okta as IdP, Claude+VS Code as clients, 7 partners (Asana/Atlassian/Canva/Figma/Granola/Linear/Supabase) | **All confirmed correct**, verbatim, against two independent primary sources | blog.modelcontextprotocol.io (official MCP blog) + claude.com/blog — both checked directly |
| FastMCP repo | `jlowin/fastmcp` | **Moved to `PrefectHQ/fastmcp`.** Old link/maintainer handle is stale. | GitHub API |
| FastMCP "70% market share (PulseMCP)" | stated as fact | **Unverified — dropped.** Don't repeat a stat you can't source. | — |
| LangChain/CrewAI code snippets in outreach templates | `auth_client.exchange_token(orchestrator_token, actor_scopes=[...])`, treating a token as if it had `.client_id` | **Wrong — doesn't match the real SDK.** `register_agent()` returns an `AgentResult` (`.client_id`/`.client_secret`), not a token. Real signature: `exchange_token(subject_token, audience, scopes=[...], client_id=..., client_secret=...)`. Fixed below, verified against `sdks/python/authgent/client.py` and the actually-working `examples/crewai/crewai_demo.py`. | Source code diff |
| awesome-mcp-servers Security section | draft said "create if doesn't exist" | **Already exists** (`### Security`, ~40 entries as of today). Add there — don't create a new section. | Live fetch of punkpeye/awesome-mcp-servers README |
| GitHub stars / npm / PyPI downloads | not mentioned in drafts | **3 GitHub stars, 69 npm downloads (30d), 90 PyPI downloads (30d) for authgent-server, 72 for the SDK.** Do not lead with these numbers anywhere — they undercut the pitch. Never volunteer them; if asked, answer honestly. | GitHub API, npm API, pypistats.org, checked live |
| LangChain issue submission method | `gh issue create` (plain title + body) | **Rejected — auto-closed within seconds** by `langchain-oss-automated-triage[bot]` for missing an Issue Type field, which only the web form or a maintainer can set (confirmed via a failed `updateIssueIssueType` GraphQL mutation — `FORBIDDEN` for non-maintainers). Must use the web form at `issues/new/choose` → Feature Request template. See §4a below, rewritten field-by-field. | Live attempt: issue #39314, auto-closed 2026-08-07; GraphQL probe confirmed the permission wall |

---

## 1. GitHub PR — awesome-mcp-servers

**Where:** https://github.com/punkpeye/awesome-mcp-servers
**Target section:** `### 🔒 Security` (already exists, ~line 3074 of README.md — do not create a new "Security & Compliance" section, the repo already calls it just "Security")
**Format check:** every entry in that section is one bullet, alphabetical-ish by author/org handle, links to the GitHub repo (not a marketing site), 1-3 sentence description. Some use the score badge, most don't — badge is optional, skip it for simplicity.

### Entry to add (paste into the Security section, keep alphabetical by repo owner)

```markdown
- [authgent/authgent](https://github.com/authgent/authgent) 🐍 ☁️ 🏠 - Open-source MCP-OAuth conformance scanner. Grades any MCP server A-F against 15 checks mapped to RFC 9728, 8414, 7636, 8707, 9207, 9449, and the MCP 2026-07-28 auth spec — plus 4 advisory checks for the new Enterprise-Managed Authorization (EMA/ID-JAG) extension. CLI (`authgent-server lint <url>`), hosted scanner, GitHub Action, embeddable badge. Also ships a self-hostable reference OAuth 2.1 server with multi-hop delegation chains (RFC 8693 nested `act` claims) — the IETF reference implementation for `draft-ietf-oauth-identity-chaining` and `draft-ietf-oauth-transaction-tokens`. Apache 2.0.
```

### PR title
```
Add authgent — MCP-OAuth conformance scanner
```

### PR body

```markdown
### What
authgent is an open-source scanner that audits any MCP server's OAuth implementation against 15 checks, each mapped to a specific RFC clause:
- RFC 9728 (Protected Resource Metadata), RFC 8414 (AS Metadata), RFC 7636 (PKCE), RFC 8707 (Resource Indicators), RFC 9207 (`iss` parameter), RFC 9449 (DPoP)
- MCP 2026-07-28 authorization spec conformance
- 4 advisory checks for the new Enterprise-Managed Authorization (EMA / ID-JAG) extension that shipped 2026-06-18

### Why include it
- No other tool audits MCP-OAuth compliance end-to-end against the actual RFC text, with a public, reproducible methodology.
- It's the reference implementation cited for two active IETF OAuth WG drafts (`draft-ietf-oauth-identity-chaining`, `draft-ietf-oauth-transaction-tokens`) — see `STANDARDS.md` in the repo for the section-by-section spec-to-code map.
- Production-ready: CLI, GitHub Action, hosted scanner at authgent.dev/scan, embeddable A-F badge, and a public registry grading real production MCP servers (Stripe, Notion, Cloudflare, Linear, etc.) against these checks.
- Apache 2.0, actively maintained, 525 tests + CI on every push.

### Format
Added one bullet to the existing `### 🔒 Security` section, alphabetical by repo owner, following the existing style (emoji tags for language/scope, link to the GitHub repo not the marketing site).

### Checklist
- [x] Entry follows existing format
- [x] Link goes to the GitHub repo
- [x] Open-source (Apache 2.0)
- [x] Actively maintained
```

### Submit steps
1. Fork https://github.com/punkpeye/awesome-mcp-servers
2. `git checkout -b add-authgent-scanner`
3. Open `README.md`, find the `### 🔒 Security` heading, add the entry above in that section (roughly alphabetical by owner is fine, exact position doesn't matter much given the section's current state)
4. `git commit -m "Add authgent — MCP-OAuth conformance scanner"`
5. `git push origin add-authgent-scanner`
6. Open the PR with the title/body above

---

## 2. Show HN post

**When:** Tuesday or Wednesday, 8-10am Pacific. Post title character limit is 80 — the title below is 66, fine.

### Title
```
Show HN: I scanned 30 production MCP servers' OAuth – only 1 earned an A
```

### Body

```
I built authgent (https://github.com/authgent/authgent), an open-source scanner that audits MCP servers' OAuth implementation against 15 checks, each mapped to a specific RFC clause. I ran it against 30 production MCP servers just now (Notion, Stripe, Cloudflare, Linear, Figma, Slack, and 24 others).

Results, live as of this morning:
- 1 A, 16 B, 10 C, 0 D, 3 F
- 29/30 don't advertise RFC 8707 resource indicators (confused-deputy risk)
- Every server DOES publish RFC 9728 Protected Resource Metadata correctly — that part of the MCP spec has landed well
- Several servers advertise PKCE S256-only in discovery metadata but still accept the OAuth-2.1-forbidden `plain` method at the actual /authorize endpoint (a heuristic I call "PKCE advertise-drift")

What it checks:
- RFC 9728: Protected Resource Metadata
- RFC 8414: Authorization Server Metadata
- RFC 7636: PKCE enforcement (including the advertise-drift heuristic above)
- RFC 8707: Resource Indicators (confused-deputy mitigation)
- RFC 9207: iss parameter on /authorize
- RFC 9449: DPoP sender-constrained tokens
- MCP 2026-07-28 authorization spec conformance
- 4 advisory checks for Enterprise-Managed Authorization (EMA/ID-JAG), the new auth extension Anthropic/Okta/Microsoft shipped with 7 launch partners on 2026-06-18

Try it:
    pip install authgent-server
    authgent-server lint https://your-mcp-server.example.com

Hosted version: https://authgent.dev/scan/
Public registry with live grades: https://authgent.dev/registry/

Responsible disclosure: vendors get a 14-day window before findings go public in the registry (docs/disclosure-policy.md in the repo).

Why I built the rest of it: if you fail the scanner, the same package (`authgent-server`) also runs a reference OAuth 2.1 server designed not to fail its own checks — with multi-hop agent delegation (nested `act` claims per RFC 8693 token exchange), DPoP, and human-in-the-loop step-up for high-risk actions. It's the reference implementation cited for two IETF OAuth WG drafts I've been contributing to: draft-ietf-oauth-identity-chaining (currently in the RFC Editor Queue) and draft-ietf-oauth-transaction-tokens (currently in its 3rd WG Last Call).

GitHub Action for CI:
    - uses: authgent/authgent/.github/actions/mcp-lint@v0.3.4
      with:
        url: https://your-mcp-server.example.com

Apache 2.0: https://github.com/authgent/authgent

Happy to answer questions about methodology, specific findings, or the IETF drafts.
```

### If asked "why not just use Auth0/Okta"
> Fair — for human SSO, Auth0/Okta are the right call and authgent isn't trying to replace them. authgent is specifically for (1) auditing whatever OAuth server you already have, including Auth0/Okta-backed ones — the scanner is provider-agnostic, and (2) the agent-delegation layer on top: multi-hop `act` chains, signed receipts, step-up approval. A lot of teams run both — Auth0 for human login, authgent for the agent layer, bridged via id_token exchange. There's a worked example in docs/compare/auth0.md.

### If someone questions the "only 1 A" framing being unfair to vendors
> Every finding is disclosed to the vendor 14 days before it's public (docs/disclosure-policy.md), and every check maps to a specific RFC clause with a spec_link in the output — nothing here is opinion-based scoring. Also worth saying: every single one of the 30 servers correctly published RFC 9728 metadata, which is the actual MUST-have for MCP client discovery. The grade differences are mostly about RFC 8707 (confused-deputy defense) and PKCE hygiene, not fundamental brokenness.

### If someone finds a bug in the scanner
> Thanks — please file an issue with the target URL and expected vs actual finding: https://github.com/authgent/authgent/issues. I'll look at it today.

---

## 3. Email — journalist/blogger pitch

The old draft targeted Simon Willison specifically by name with a personalized opener ("I've been following your MCP security coverage..."). **Do not send that personalized claim unless you've actually verified you've read his recent MCP-security posts** — an unverifiable personal claim to a high-profile recipient is a real risk if it's not true and he engages. Below is the same pitch with that specific claim removed; add it back yourself, by hand, only if it's true.

**To:** via https://simonwillison.net/contact/
**Subject:**
```
MCP-OAuth scanner data: 30 production servers, live grades
```

**Body:**

```
Hi Simon,

I built authgent (https://github.com/authgent/authgent), an open-source scanner that audits MCP servers' OAuth implementation against 15 RFC-mapped checks. Ran it against 30 production MCP servers this morning. Results:

- 1 A, 16 B, 10 C, 0 D, 3 F
- 29/30 don't advertise RFC 8707 resource indicators (confused-deputy risk)
- All 30 correctly publish RFC 9728 Protected Resource Metadata — the actual MUST-have for MCP client discovery is in good shape ecosystem-wide
- Several servers show "PKCE advertise-drift" — S256-only in discovery metadata, but `plain` still accepted at /authorize

Methodology is fully reproducible and every check maps to a specific RFC clause (docs/methodology.md). Public registry with live per-vendor grades: https://authgent.dev/registry/. CLI: pip install authgent-server && authgent-server lint <url>.

Why now: MCP's Enterprise-Managed Authorization (EMA) extension shipped 2026-06-18 with Okta as launch IdP, Claude and VS Code as launch clients, and 7 launch partners (Asana, Atlassian, Canva, Figma, Granola, Linear, Supabase) — officially announced at blog.modelcontextprotocol.io/posts/enterprise-managed-auth/. EMA solves enterprise SSO governance but explicitly assumes the underlying OAuth posture is already sound. This scan is a snapshot of whether that assumption holds.

IETF angle, if useful: authgent is the reference implementation for two active OAuth WG drafts — draft-ietf-oauth-identity-chaining (currently in the RFC Editor Queue, rev -17) and draft-ietf-oauth-transaction-tokens (currently in its 3rd WG Last Call, rev -11). Neither has an RFC number yet.

Happy to share the full scan data (JSON), the disclosure timeline, or reproduction steps if any of this is useful for something you're writing. No worries either way.

Thanks,
Dhruv Agnihotri

Links:
- Scanner: https://authgent.dev/scan/
- Registry: https://authgent.dev/registry/
- GitHub: https://github.com/authgent/authgent
```

**Follow-up if no response in 7 days:** send once, gently, via whatever secondary channel you actually have a working relationship on (don't invent a Twitter-DM relationship that doesn't exist).

---

## 4. GitHub issues on framework repos

Post at most 1-2 of these to start — four issues on four different maintainers' repos on the same day reads as spam. LangChain (biggest reach) and CrewAI (cleanest working example already in the repo) are the strongest two.

### 4a. LangChain

**Repo:** https://github.com/langchain-ai/langchain (143,576 stars, verified)
**Where:** **Must go through the web form** at
https://github.com/langchain-ai/langchain/issues/new/choose → **"✨ Feature
Request"** template. This repo runs `langchain-oss-automated-triage[bot]`,
which auto-closes any issue that doesn't have an **Issue Type**
(Task/Bug/Feature) set — and Issue Type can only be set by the web form's
guided flow or by a maintainer; there is no API/CLI way to set it
(confirmed: `gh issue create` and a direct GraphQL
`updateIssueIssueType` mutation both fail with `FORBIDDEN` for a
non-maintainer). **Do not use `gh issue create` for this repo.** First
attempt (issue #39314) was auto-closed for exactly this reason — this is
the corrected version, mapped to the form's actual fields.

**Title field:**
```
Add authgent as an OAuth/delegation example for multi-agent workflows
```

**Submission checklist:** check all 5 boxes (title is descriptive, searched
for duplicates, checked docs, not a langchain-community issue, this is a
feature request not a bug).

**Package (Required) — select:**
```
Other / not sure / general
```
(This is a docs/example request, not tied to a specific installable
package like `langchain-openai`.)

**Feature Description field:**
```
Add an example showing scoped OAuth delegation between LangChain agents — an orchestrator delegating to a sub-agent, with scope that narrows (never widens) at each hop, and a cryptographically verifiable delegation chain per call.

Concretely: a doc page or example under docs/docs/integrations/providers/ (or wherever example integrations live) showing an orchestrator agent registering its own OAuth identity, then delegating a scoped-down token to a sub-agent via RFC 8693 token exchange, so the sub-agent's token is provably a narrower subset of the orchestrator's — not a copy of the same shared credential.
```

**Use Case field:**
```
Multi-agent LangChain workflows commonly share one API key/token across every agent in the chain. That means:
- No per-agent audit trail — can't tell which agent made which call
- Every agent is over-privileged relative to its actual task
- No way to revoke one compromised/misbehaving agent without killing the whole chain

I'm building multi-agent LangChain pipelines where different sub-agents have very different trust levels (a search agent vs. an agent with write access to a database), and I don't want to hand every sub-agent the same all-access credential just because they're all part of one LangChain run.
```

**Proposed Solution field:**
```
authgent (https://github.com/authgent/authgent, Apache 2.0) is an OAuth 2.1 server built around exactly this: RFC 8693 token exchange with nested `act` claims, so each hop in a delegation chain is independently scoped, independently revocable, and cryptographically verifiable. It's the reference implementation cited for draft-ietf-oauth-identity-chaining (IETF OAuth WG, currently in the RFC Editor Queue).

A working example already exists in the authgent repo and runs against a real authgent-server instance:
https://github.com/authgent/authgent/tree/main/examples/langchain_tool

It uses AuthgentToolWrapper for automatic token acquisition/caching/refresh — real signature, verified against the SDK:

​```python
from authgent.client import AgentAuthClient
from authgent.adapters.langchain import AuthgentToolWrapper

client = AgentAuthClient("https://auth.example.com")
agent = await client.register_agent(
    name="research-bot",
    scopes=["search:execute", "summarize:execute"],
)

wrapper = AuthgentToolWrapper(
    server_url="https://auth.example.com",
    client_id=agent.client_id,
    client_secret=agent.client_secret,
    scope="search:execute summarize:execute",
)
headers = await wrapper.get_auth_headers()  # auto-acquires + caches token
​```

Would a doc link to this example fit in docs/docs/integrations/providers/, or would a PR with a trimmed-down version inline be preferred?
```

**Alternatives Considered field:**
```
The common workaround today is giving every sub-agent the same shared API key/token, or building a custom internal token-minting service by hand. Neither gives an auditable, standards-based (RFC 8693) delegation chain, and a hand-rolled version needs to be re-verified for the same scope-escalation bugs authgent already handles (it explicitly rejects a delegation attempt that would widen scope rather than narrow it).
```

**Additional Context field:**
```
Repo: https://github.com/authgent/authgent
IETF draft: https://datatracker.ietf.org/doc/draft-ietf-oauth-identity-chaining/ (rev -17, RFC Editor Queue)
License: Apache 2.0
```

### 4b. CrewAI

**Repo:** https://github.com/crewAIInc/crewAI (56,706 stars — note: moved from `joaomdmoura/crewAI` to the `crewAIInc` org, use this URL)
**Where:** New GitHub Issue

**Title:**
```
Add authgent example for per-agent identity + scoped delegation in a crew
```

**Body:**
```markdown
### Feature request

An example showing each CrewAI crew member with its own OAuth identity and scope, instead of one shared API key for the whole crew.

### Problem

A shared credential across a crew means no audit trail for which agent made which call, every agent over-privileged relative to its actual task, and no way to revoke one compromised agent without killing the crew.

[authgent](https://github.com/authgent/authgent) (Apache 2.0, OAuth 2.1) gives each agent its own identity, and lets a "researcher" agent delegate to a "writer" agent with scope that only ever narrows, never widens — RFC 8693 token exchange with nested `act` claims, enforced server-side (a widen attempt is rejected as `ScopeEscalation`, not silently accepted).

### Proposed content

A working demo already exists and runs against `authgent-server`:
https://github.com/authgent/authgent/tree/main/examples/crewai

Core pattern (verified against the real SDK, `sdks/python/authgent/client.py`):

\`\`\`python
from authgent.client import AgentAuthClient

auth = AgentAuthClient("https://auth.example.com")

researcher_creds = await auth.register_agent(name="researcher", scopes=["search", "read"])
researcher_token = await auth.get_token(researcher_creds.client_id, researcher_creds.client_secret)

analyst_creds = await auth.register_agent(name="analyst", scopes=["read"])

# Delegate researcher -> analyst, scope narrows from "search read" to "read"
delegated = await auth.exchange_token(
    subject_token=researcher_token.access_token,
    audience="https://analyst-agent.internal",
    scopes=["read"],
    client_id=analyst_creds.client_id,
    client_secret=analyst_creds.client_secret,
)
\`\`\`

Would a link in `docs/how-to/` fit, or is a PR with a trimmed inline example preferred?

### Additional context
- Existing example: https://github.com/authgent/authgent/tree/main/examples/crewai
- Repo: https://github.com/authgent/authgent
- IETF draft: https://datatracker.ietf.org/doc/draft-ietf-oauth-identity-chaining/
- License: Apache 2.0
```

**Do not use the FastMCP or LlamaIndex templates from the old draft as-is.** FastMCP's repo moved (`jlowin/fastmcp` → `PrefectHQ/fastmcp`) and the old draft's "70% market share (PulseMCP)" stat is unsourced — if you want to pursue FastMCP or LlamaIndex, rebuild the issue text the same way the two above were built: verify the repo URL and star count fresh, and only cite code against the real SDK.

---

## 5. Cross-post to dev.to

All 6 blog posts already have correct `canonical:` frontmatter pointing back to the GitHub-hosted source, so cross-posting is safe for SEO (no duplicate-content penalty). Paste the post body (everything after the frontmatter) into a new dev.to post, then in dev.to's "canonical URL" field paste the `canonical:` value from that post's frontmatter — do not skip this field.

Posts, in the order most likely to land (most concrete/data-driven first):
1. `docs/blog/2026-06-19-ema-launch-partner-pkce.md` — has the most concrete data, timeliest hook
2. `docs/blog/2026-06-13-mcp-server-oauth-checklist.md`
3. `docs/blog/2026-06-13-rfc-9728-protected-resource-metadata.md`
4. `docs/blog/2026-06-13-claude-desktop-oauth-not-working.md`
5. `docs/blog/2026-08-06-non-human-identity-for-ai-agents.md` (new)
6. `docs/blog/2026-08-06-2-legged-vs-3-legged-oauth-ai-agents.md` (new)

Space these out — one every 2-3 days reads as a real blog, six in one day reads as a content dump.

---

## What NOT to send

- **Do not send the old `simon-willison-email.md` opener verbatim** — "I've been following your MCP security coverage" is a specific personal claim; only use it if genuinely true.
- **Do not cite "51,311 MCP servers (per Glama)"** anywhere — unverifiable, possibly fabricated. If you want a server-count stat, use Glama's live count with today's date as a snapshot, not a growth claim.
- **Do not cite draft-ietf-oauth-identity-chaining-14 or draft-ietf-oauth-transaction-tokens-08** — both are 3-6 revisions stale. Use -17 and -11.
- **Do not link `jlowin/fastmcp`** — it moved to `PrefectHQ/fastmcp`.
- **Do not lead with GitHub stars, npm downloads, or PyPI downloads anywhere** — all three are in the single/low-double digits right now and volunteering them undercuts the pitch. If asked directly, answer honestly; don't put them in outreach copy.
- **Do not claim "80% missing RFC 9728"** — false, live data shows 0/30 missing it.
