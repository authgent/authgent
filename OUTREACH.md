# authgent — Outreach Drafts

These are **drafts the maintainer reviews and sends.** Nothing here is
auto-published. Each section is self-contained and ready to copy.

The strategic goal: get authgent listed in the IETF "Implementation
Status" section of the two WG-track drafts it implements, surface it on
HN/InfoQ at the right moment, and start the conversation that leads to
co-authorship on at least one of the active drafts.

---

## 1. IETF OAuth WG mailing list announcement

**To:** `oauth@ietf.org`
**Subject:** Open-source reference implementation of draft-ietf-oauth-identity-chaining-14 and draft-ietf-oauth-transaction-tokens-08

```
Hi all,

I'd like to share an open-source reference implementation of two
WG-track drafts:

  * draft-ietf-oauth-identity-chaining-14 (in IESG approval)
  * draft-ietf-oauth-transaction-tokens-08 (in WG Last Call)

Both are implemented in authgent, an Apache-2.0 OAuth 2.1 server in
Python:

    https://github.com/authgent/authgent

Conformance details, including a per-section spec → file:func mapping
and the full test suite (420 tests, 82% coverage):

    https://github.com/authgent/authgent/blob/main/STANDARDS.md
    https://github.com/authgent/authgent/blob/main/docs/identity-chaining.md
    https://github.com/authgent/authgent/blob/main/docs/transaction-tokens.md

Both flows are also exposed through Python and TypeScript SDKs
(`pip install authgent`, `npm install authgent`).

Happy to participate in interop testing and to update the
implementations as the drafts evolve. If the editors of either draft
would like authgent listed in an Implementation Status appendix, the
canonical citation is in CITATION.cff.

Comments, bug reports, and conformance failures welcome.

Thanks,
Dhruv Agnihotri
```

**When to send:** after the next CI green build on `main`. Best timing
is mid-week (Tuesday–Thursday morning Pacific).

---

## 2. Email to identity-chaining draft authors

**To:** Aaron Parecki <aaron@parecki.com>, Pieter Kasselman
<pieter.kasselman@defakto.io>, Brian Campbell <bcampbell@pingidentity.com>,
Arndt Schwenkschuster <arndt@defakto.io>
**Cc:** Kelley Burgin <kburgin@mitre.org>, Michael Jenkins
<mjjenki@cyber.nsa.gov>
**Subject:** Reference implementation of draft-ietf-oauth-identity-chaining-14

```
Hi all,

I've shipped an Apache-2.0 reference implementation of
draft-ietf-oauth-identity-chaining-14 in authgent (an open-source
OAuth 2.1 server). It covers §2.3, §2.4, §2.5, §3, and §5.1–5.5,
with a 17-test conformance suite mapped section-by-section:

    https://github.com/authgent/authgent/blob/main/STANDARDS.md
    https://github.com/authgent/authgent/blob/main/docs/identity-chaining.md
    https://github.com/authgent/authgent/blob/main/server/tests/test_identity_chaining.py

Two specific things I'd appreciate your input on:

  1. If you maintain an Implementation Status section in a future
     revision, please consider listing authgent. Citation metadata
     is in CITATION.cff.

  2. I'd be glad to do interop testing with another implementation
     against the spec text — particularly the §2.5 claims-transcription
     edge cases, which authgent exposes as a pluggable policy.

Happy to take any conformance feedback. The code base has CI gates
on lint/format/strict mypy, and 82% test coverage.

Thanks,
Dhruv Agnihotri
```

**When to send:** after the IETF-list announcement (so the public
context exists). Wait 2–3 days for any list responses first.

---

## 3. Email to transaction-tokens draft authors

**To:** Atul Tulshibagwale <atulskt@crowdstrike.com>, George Fletcher
<george.fletcher@gmail.com>, Pieter Kasselman <pieter.kasselman@defakto.io>
**Subject:** Reference implementation of draft-ietf-oauth-transaction-tokens-08

```
Hi all,

I've shipped an Apache-2.0 reference implementation of
draft-ietf-oauth-transaction-tokens-08 in authgent. Coverage spans §3
(token type, typ header, required claims, tctx/rctx), §7 (lifetime,
scope policy), and §11 (no refresh tokens). 8-test conformance suite:

    https://github.com/authgent/authgent/blob/main/STANDARDS.md
    https://github.com/authgent/authgent/blob/main/docs/transaction-tokens.md
    https://github.com/authgent/authgent/blob/main/server/tests/test_transaction_tokens.py

If you'd like authgent listed in the WG Last Call discussion or in
an Implementation Status appendix, the canonical citation is in
CITATION.cff.

Two implementation notes that may be useful for the spec:

  1. §7.2 ("scope MUST NOT exceed subject_token") — authgent
     enforces this with a strict subset check; I included a test
     that exercises both the allowed and rejected paths.
  2. §3 lists `tctx` and `rctx` as optional. authgent always emits
     `rctx` with auto-derived `req_ip` (from the form-post origin)
     and a default `authn` of `urn:ietf:rfc:6749`. Happy to adjust
     if §3 should be stricter on the `rctx` shape.

Thanks,
Dhruv Agnihotri
```

**When to send:** same window as #2. Personalized cc list increases
reply rate vs the public list.

---

## 4. Show HN draft

**Title:** "Show HN: authgent – open-source reference impl of two IETF agent-OAuth drafts"

**Body:**

```
authgent is an Apache-2.0 OAuth 2.1 server. It's the open-source
reference implementation of two WG-track IETF drafts:

  - draft-ietf-oauth-identity-chaining-14 (IESG approval): cross-domain
    delegation. Domain A mints a short-lived JWT grant; Domain B
    redeems it via jwt-bearer.
  - draft-ietf-oauth-transaction-tokens-08 (WG Last Call): short-lived
    `txntoken+jwt` JWTs that propagate authorization context through
    internal call chains.

It also ships RFC 8693 nested-`act` delegation, RFC 9449 DPoP, RFC
9728 Protected Resource Metadata, and the MCP 2026-07-28 auth spec.

Why bother? "OAuth for agents" is now contested by Auth0 ($38M
funded), Okta, Descope, WorkOS, Keycard, and Stytch — but every
shipping product is closed-source SaaS. authgent is the
self-hostable, vendor-neutral implementation that the IETF specs
were written against. If you want to deploy a Trust Domain in your
VPC, or you're an IETF implementer testing your draft against
another impl, this is meant for you.

  - 420 tests, 82% coverage
  - Zero lint/format/type errors (ruff strict + mypy strict)
  - Python + TypeScript SDKs
  - Works alongside Auth0/Okta via id_token bridge

  https://github.com/authgent/authgent
  https://github.com/authgent/authgent/blob/main/STANDARDS.md

Happy to answer questions about the spec implementations or the
trade-offs around `act` chain depth, DPoP key rebinding, and the
single-use / replay model for cross-domain grants.
```

**When to post:** after the IETF mailing-list message and at least one
spec-author reply. Posting first thing Tuesday morning Pacific (≈8am)
catches the maximum "morning HN" window.

---

## 5. dev.to post — "Implementing IETF identity-chaining in 600 lines of Python"

A long-form companion to the Show HN. Save this for after Show HN
lands (or doesn't); it can be syndicated regardless.

**Hook:** dissect the §2.3 / §2.4 spec language and walk through how
authgent's code maps line-for-line. Helps anyone else implementing
the draft.

(Draft to be expanded. Pull material from `docs/identity-chaining.md`
and embed code excerpts.)

---

## 6. InfoQ pitch

**To:** InfoQ news editorial (existing InfoQ relationship per Dhruv's
publication history)
**Subject pitch:** "After implementing two IETF drafts for AI-agent
auth, here's what's still missing"

500-word news piece that lands on InfoQ once at least one of the two
drafts lands as RFC. The piece can also be a 2,000-word deep-dive if
the editor prefers.

---

## 7. OWASP AISVS C09-04 — alignment PR

The OWASP AI Security Verification Standard, chapter 9 (Orchestration
and Agents), section C09-04 (Agent Identity and Audit) already
references identity-chaining and transaction-tokens. authgent should
be listed as a reference implementation in the C09-04 chapter.

**Repo:** https://github.com/OWASP/AISVS
**Action:** open a PR that adds authgent to the section's references.
**Body sketch:**

```
Adding a reference to authgent (Apache-2.0), an open-source OAuth 2.1
server that implements the IETF agent-identity stack — including
draft-ietf-oauth-identity-chaining-14 and
draft-ietf-oauth-transaction-tokens-08 cited in this section.

Conformance map: https://github.com/authgent/authgent/blob/main/STANDARDS.md
```

---

## 8. MCP SEP-2350 Python SDK PR (separate repo)

**Repo:** https://github.com/modelcontextprotocol/python-sdk
**Issue:** #2801 (currently open + unassigned)

Plan in a separate document; this is the highest-leverage item *outside*
the authgent repo. Goal: become a named SDK contributor on a WG-approved
MCP SEP that ships in the 2026-07-28 release.

---

## When NOT to outreach yet

- **Before the next CI run is green.** Senders verify links; broken
  links destroy credibility.
- **Before the README + STANDARDS.md are at v1.** Reviewers click the
  first link and skim. If the headline doesn't say "reference
  implementation of [exact draft name]", they bounce.
- **Before there's at least one tagged release** (`v0.2.1`) with the
  identity-chaining + transaction-tokens code. Pre-tag installs are
  hard to cite.

## Tracking

Maintain a tiny log here as messages go out:

| Date | Channel | Recipient | Status |
|---|---|---|---|
| _YYYY-MM-DD_ | _e.g. ietf list_ | _oauth@ietf.org_ | _sent / replied / etc._ |
