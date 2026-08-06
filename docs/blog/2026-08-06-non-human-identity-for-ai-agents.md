---
title: "Non-Human Identity for AI Agents: Why OAuth Alone Isn't Enough"
description: A practitioner's map of the non-human identity (NHI) landscape as it applies to AI agents — what NHI means, where OAuth 2.1 stops being sufficient, and how delegation chains close the gap.
target_query: "non-human identity"
publish_targets: ["dev.to", "lobste.rs", "medium"]
canonical: https://github.com/authgent/authgent/blob/main/docs/blog/2026-08-06-non-human-identity-for-ai-agents.md
date: 2026-08-06
draft: false
---

# Non-Human Identity for AI Agents: Why OAuth Alone Isn't Enough

"Non-human identity" (NHI) has become the industry's shorthand for the security problem that shows up once you count how many of the credentials in a modern system belong to something that isn't a person: service accounts, CI/CD pipelines, IoT devices, and now, AI agents. The [Non-Human Identity Management Group](https://nhimg.org) formed around exactly this gap, and vendors like Aembit have built entire platforms on workload-identity for machine-to-machine calls.

AI agents are the newest and fastest-growing member of that category, and they break the NHI model in a way service accounts and CI pipelines never did: **an AI agent doesn't just authenticate once and act — it acts on someone's behalf, then hands part of that authority to another agent, which hands part of it to another.** A static API key or a long-lived service-account credential answers "is this machine allowed to call this API," which is the NHI question everyone already knows how to answer. It cannot answer "acting for whom, with how much of the original authority, and who signed off at each hop," which is the question multi-agent systems actually need answered.

This post is a map of that gap: what NHI covers today, why OAuth 2.1 client credentials get you partway, and where identity chaining and delegation take over.

## The three generations of non-human identity

**Generation 1: static secrets.** API keys, database passwords, `.env` files. No expiry, no scope, no audit trail beyond "this key was used." Still the majority of NHI in production today, and the majority of NHI-related breaches.

**Generation 2: workload identity.** SPIFFE/SPIRE, cloud IAM roles, OAuth 2.1 client credentials. A workload proves *what it is* (via a certificate, a cloud metadata endpoint, or a client secret) and gets a short-lived token scoped to what that workload is allowed to do. This is a real improvement — tokens expire, scopes are enforced, and platforms like Aembit have built credential-issuance and rotation around this model. It answers "is this specific service allowed to call this specific API right now."

**Generation 3: delegated identity.** This is where AI agents live, and it's the generation NHI tooling mostly hasn't caught up to yet. A workload-identity token says "Service X is calling." A delegated-identity token has to say "Service X is calling *on behalf of* User A, *because* Orchestrator Agent B asked it to, *within the scope* User A originally granted, *narrowed* at each hop." That's not a bigger scope string. It's a chain.

## Why agent delegation isn't just OAuth client credentials with extra steps

Client credentials grant (`grant_type=client_credentials`) is generation-2 NHI: a client authenticates as itself and gets a token for itself. It's the right tool when a single service calls a single API. It's the wrong tool the moment Agent A needs to call Agent B, which needs to call a database, on behalf of a human user who authorized the *first* action but never heard of the second or third.

Three things happen in a real multi-agent pipeline that plain client credentials can't express:

1. **Scope has to narrow, not just exist.** If a user grants an orchestrator `read:calendar write:email`, the orchestrator's downstream search agent should get `read:calendar` at most — not the full grant re-issued under a new name. Client credentials has no mechanism for "issue me a token that's a subset of a different token I'm holding."
2. **The chain has to be provable, not just claimed.** When something goes wrong three hops deep, "which human, through which agents, authorized this specific tool call" is the incident-response question, and a flat token can't answer it. RFC 8693 token exchange with nested `act` claims can: each hop signs a claim that says who acted for whom, and the chain is verifiable end to end.
3. **A human sometimes has to be back in the loop.** Delegation chains that cross a risk threshold (a payment, a destructive action, a cross-org boundary) need a synchronous point where a person approves, not just an audit log after the fact. That's a distinct primitive — human-in-the-loop step-up — that neither raw OAuth nor generic NHI platforms provide today.

This is the gap [authgent](https://github.com/authgent/authgent) is built to close: an OAuth 2.1 authorization server where token exchange (RFC 8693) mints nested `act` claims for multi-hop delegation, where [identity chaining](../identity-chaining.md) extends that trust across organizational boundaries via `draft-ietf-oauth-identity-chaining-14`, and where a step-up flow can pause a chain for human approval before a scoped action executes.

## Where this sits relative to the rest of the NHI stack

To be concrete about scope: authgent is not a workload-identity platform, a secrets manager, or a certificate authority, and it doesn't compete with SPIFFE/SPIRE or cloud IAM for machine-to-machine authentication at the infrastructure layer. Those solve "prove what you are." authgent solves the layer above that: "prove what you're allowed to do right now, on whose authority, and how that authority narrowed to get here" — specifically for OAuth-based AI-agent and MCP-server delegation.

If you're evaluating NHI tooling for an agent-heavy system, the practical checklist is:

- **Workload identity** — do your agents authenticate with short-lived, verifiable credentials rather than static secrets? (SPIFFE/SPIRE, cloud IAM, or OAuth client credentials.)
- **Delegation chains** — when Agent A calls Agent B on a user's behalf, is there a cryptographically verifiable record of *who* authorized *what*, narrowed at each hop? (RFC 8693 token exchange + `act` claims.)
- **Cross-domain trust** — if agents span organizational boundaries, is there a signed handoff rather than a shared secret or an implicit trust relationship? (Identity chaining, RFC 7523 JWT-bearer.)
- **Human-in-the-loop** — for actions above a risk threshold, is there a synchronous approval gate, not just a post-hoc log line?
- **MCP-specific posture** — if your agents talk to MCP servers, do those servers actually implement the OAuth metadata (RFC 9728, 8414) and PKCE enforcement the MCP spec requires? ([Run the scanner](https://authgent.dev/scan/) — this is the one most teams haven't checked.)

The first item is solved territory; several good platforms exist. The last four are where the non-human-identity conversation is heading next, and where most tooling — including, frankly, most of the OAuth ecosystem before agents existed — hasn't been tested yet.

## Try it

```bash
pip install authgent-server
authgent-server run     # reference OAuth 2.1 server with delegation chains, DPoP, step-up
```

Or scan an existing MCP server's OAuth posture in ten seconds at [authgent.dev/scan](https://authgent.dev/scan/), and see how ~30 production MCP servers grade today at [authgent.dev/registry](https://authgent.dev/registry/).

## Read more

- [Identity chaining across trust domains](../identity-chaining.md) — the cross-domain half of this problem
- [Transaction tokens](../transaction-tokens.md) — `txntoken+jwt` context for the "narrowed at each hop" requirement
- [STANDARDS.md](../../STANDARDS.md) — section-by-section spec-to-code map
- [Non-Human Identity Management Group](https://nhimg.org)
- [draft-ietf-oauth-identity-chaining](https://datatracker.ietf.org/doc/draft-ietf-oauth-identity-chaining/) (IETF OAuth WG)

Comments and counter-readings welcome — the repo's [issue tracker](https://github.com/authgent/authgent/issues) is the right venue.
