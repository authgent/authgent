---
title: "2-Legged vs 3-Legged OAuth: What Changes When the Third Leg Is an AI Agent"
description: A refresher on 2-legged and 3-legged OAuth, and why multi-agent AI systems need a third model neither one covers — delegated, multi-hop authorization with narrowing scope.
target_query: "2-legged vs 3-legged oauth"
publish_targets: ["dev.to", "lobste.rs", "medium"]
canonical: https://github.com/authgent/authgent/blob/main/docs/blog/2026-08-06-2-legged-vs-3-legged-oauth-ai-agents.md
date: 2026-08-06
draft: false
---

# 2-Legged vs 3-Legged OAuth: What Changes When the Third Leg Is an AI Agent

"2-legged" and "3-legged" OAuth are old terms — older than OAuth 2.0 itself, dating back to when OAuth 1.0a needed a shorthand for whether a resource owner was in the flow at all. They're still the fastest way to explain the two flows most engineers actually use, and they're a useful starting point for a question the terminology never anticipated: what do you call the flow where a *third party acting on the resource owner's behalf* isn't a browser redirect, but another AI agent?

## 2-legged OAuth: two parties, no resource owner

Two legs: the client and the authorization server. No human clicks "Allow" anywhere in the flow. This is `grant_type=client_credentials` in OAuth 2.0/2.1 terms — a service authenticates as itself, gets a token that represents *itself*, and calls an API with it.

```http
POST /token
grant_type=client_credentials
&client_id=inventory-service
&client_secret=***
```

The resulting token says "the inventory service is calling," full stop. There's no user in the loop, so there's nothing to delegate — the service's own identity is the entire authorization context. This is exactly right for machine-to-machine calls where the calling service has its own standing authority: a nightly batch job, a health-check probe, a metrics exporter.

## 3-legged OAuth: three parties, one human in the loop

Three legs: the client, the resource owner (a human), and the authorization server. This is the authorization code flow — the redirect-to-consent-screen dance every OAuth tutorial starts with.

```
User → Client → Authorization Server (consent screen) → Client (code) → Authorization Server (token)
```

The resulting token represents *the user, as expressed through the client the user approved*. This is the model nearly every "Sign in with X" and "Connect your Y account" integration uses, and it's the right model when a human is present to grant a scoped, revocable permission to a specific app they chose to trust.

## Where AI agents break both models

Neither model has a slot for "Agent A is calling Agent B, which needs to call a database, and the user who's ultimately responsible authorized the *first* step in this chain but has never heard of the third."

If you force this into 2-legged OAuth, every agent in the chain gets its own client-credentials token representing *itself*, with no record of who it's acting for. That's the fast path to the confused-deputy problem: Agent B can't tell whether the request in front of it came with the user's actual authorization or whether Agent A is just calling with its own standing service identity, and if Agent B's token is scoped broadly enough to be useful for any of Agent A's requests, it's scoped too broadly for the specific one in front of it.

If you force it into 3-legged OAuth, you get a consent screen for the *first* hop and then nothing for the rest — the user approved "Orchestrator Agent may access your calendar," full stop, with no visibility into which sub-agents that authority actually flowed through, and no mechanism to narrow what each sub-agent gets.

## The third model: delegated, multi-hop, narrowing authorization

What multi-agent systems actually need is RFC 8693 token exchange used as a delegation primitive, not just a format converter. The mechanics:

1. A human authorizes the first agent through a normal 3-legged flow (or the client-credentials-equivalent 2-legged flow, if the "user" is another system). This produces a token scoped to what the human actually approved — call it the top-level grant.
2. When Agent A needs Agent B to do part of the work, Agent A exchanges its token for a **new token scoped to a subset of its own authority**, with Agent B as the intended holder. This is `grant_type=urn:ietf:params:oauth:grant-type:token-exchange`, and the resulting token carries a nested `act` claim: `{"sub": "user_alice", "act": {"sub": "agent_a", "act": {"sub": "agent_b"}}}`. The claim is a signed, verifiable record of exactly who is acting for whom.
3. Scope only ever narrows going down the chain — Agent B's token is a subset of Agent A's, never a superset — and each hop is independently auditable because the `act` chain is part of the signed token, not a separate log a downstream service has to trust.
4. If a hop crosses an organizational boundary — Agent A and Agent B trust different authorization servers — the same token-exchange mechanism, layered with RFC 7523 JWT-bearer, extends the chain across domains without either side needing a shared secret. That's [identity chaining](https://github.com/authgent/authgent/blob/main/docs/identity-chaining.md), and it's the subject of an active IETF draft (`draft-ietf-oauth-identity-chaining`) for exactly this reason — the gap is real enough that a WG-track spec is being written to close it.

The result isn't 2-legged or 3-legged. It's *N*-legged, where N is the depth of the delegation chain, with a hard-enforced maximum depth and a scope that can only shrink as it descends.

## What this looks like in practice

```bash
# Agent A exchanges its token, scoped down, naming Agent B as delegate
curl -X POST https://as.example.com/token \
  -d "grant_type=urn:ietf:params:oauth:grant-type:token-exchange" \
  -d "subject_token=$AGENT_A_TOKEN" \
  -d "subject_token_type=urn:ietf:params:oauth:token-type:access_token" \
  -d "scope=read:calendar" \
  -d "actor_token=$AGENT_B_CLIENT_ASSERTION"
```

[authgent](https://github.com/authgent/authgent) implements this as its core primitive — every token exchange builds nested `act` claims, enforces a configurable maximum delegation depth (`MAX_DELEGATION_DEPTH`), and rejects any exchange that tries to *widen* scope rather than narrow it (`ScopeEscalation`, a dedicated error class, not a generic 403). If a hop needs a human back in the loop — say, the chain is about to trigger a payment three agents deep — a step-up flow can pause and require synchronous approval before the token is minted.

Try the 7-step interactive version of this at [authgent.dev/playground](https://authgent.dev/playground/), or read the full mechanics in [identity-chaining.md](https://github.com/authgent/authgent/blob/main/docs/identity-chaining.md) and [transaction-tokens.md](https://github.com/authgent/authgent/blob/main/docs/transaction-tokens.md).

## Read more

- [Identity chaining across trust domains](https://github.com/authgent/authgent/blob/main/docs/identity-chaining.md)
- [Non-human identity for AI agents](./2026-08-06-non-human-identity-for-ai-agents.md) — the broader NHI framing this post's delegation model fits into
- [RFC 8693 — OAuth 2.0 Token Exchange](https://datatracker.ietf.org/doc/html/rfc8693)
- [draft-ietf-oauth-identity-chaining](https://datatracker.ietf.org/doc/draft-ietf-oauth-identity-chaining/)

Comments and counter-readings welcome — the repo's [issue tracker](https://github.com/authgent/authgent/issues) is the right venue.
