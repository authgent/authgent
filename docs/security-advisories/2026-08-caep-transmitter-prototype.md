# Design Note: CAEP Session-Revoked Transmitter Prototype

**Date:** 2026-08-18
**Status:** Prototype on branch `caep-transmitter-prototype`, not merged to `main`.
**Purpose:** Research artifact backing a magazine column on applying OpenID's
CAEP (Continuous Access Evaluation Profile 1.0, final:
https://openid.net/specs/openid-caep-1_0-final.html) to real-time revocation
notification for compromised AI-agent credentials. Written in the same
honest, precise, "what's fixed / what's explicitly not" style as
`docs/security-advisories/2026-08-non-cascading-revocation.md`.

## What this is

Before this prototype, authgent had zero CAEP/SSF/SET code. This adds a
narrow, real, working slice: when an operator or automated detector flags an
agent's token as compromised, authgent (1) blocklists the token and cascades
to its delegation descendants using the existing revocation machinery, and
(2) constructs, signs, and pushes a CAEP `session-revoked` Security Event
Token (SET) to a fixed list of configured receiver endpoints.

## What was built

- **SET construction** (`server/authgent_server/providers/caep.py:74`,
  `build_session_revoked_set`): an RFC 8417 SET claim set (`iss`, `aud`,
  `iat`, `jti`, `events`) carrying the CAEP `session-revoked` event type URI
  (`server/authgent_server/providers/caep.py:50`,
  `SESSION_REVOKED_EVENT_TYPE`) and a subject identifier referencing the
  compromised token's `actor_id`, `client_id`, and `jti`.
- **Subject identifier format**: RFC 9493 defines no registered
  subject-identifier format specifically for an OAuth `client_id`/agent
  identity as of this writing, so this prototype uses RFC 9493 §3.5's
  generic `opaque` format (`server/authgent_server/providers/caep.py:59`,
  `SUBJECT_FORMAT_OPAQUE`) carrying those three fields directly. This is a
  deliberate, documented choice, not a claim that authgent implements a
  standardized subject-identifier format for agent identities. No such
  format is standardized yet.
- **Signing**: the SET is signed with authgent's existing token-signing
  infrastructure, `JWKSService.sign_jwt`
  (`server/authgent_server/services/jwks_service.py:132`), the same
  mechanism and the same active signing key used to sign ordinary access
  tokens. No new key management was introduced. The `typ` header is set to
  `secevent+jwt` per RFC 8417 §2.1. `server/tests/test_caep.py:76`
  (`test_transmitter_signs_with_real_jwks_key`) verifies the delivered SET's
  signature against the real JWKS document served at
  `GET /.well-known/jwks.json`.
- **Delivery** (`server/authgent_server/providers/caep.py:108`,
  `CAEPTransmitter`): HTTP POST push per RFC 8935 semantics, to every
  receiver in `Settings.caep_receiver_url_list`
  (`server/authgent_server/config.py:123`), concurrently, each with its own
  independent retry+backoff loop
  (`CAEPTransmitter._deliver_one`, same file, line 192) so one
  slow or down receiver cannot delay delivery to the others. The
  push-delivery HTTP body carries an HMAC-SHA256 signature
  (`X-Authgent-Signature-256`) over the raw bytes, distinct from the SET's
  own JWS signature, computed with `Settings.caep_hmac_secret`
  (`server/authgent_server/config.py:111`). This mirrors
  `WebhookHITLProvider` (`server/authgent_server/providers/hitl.py:19`) so
  the codebase has one shared shape for both of its push-delivery
  mechanisms, HITL approval requests and CAEP SETs.
- **Trigger path** (`server/authgent_server/services/token_service.py:1054`,
  `TokenService.flag_compromised`): a new, distinct entry point from
  `revoke_token` (`server/authgent_server/services/token_service.py:966`).
  Exposed as `POST /security/tokens/compromise`
  (`server/authgent_server/endpoints/security.py:78`), gated unconditionally
  on a bearer token carrying `Settings.caep_operator_scope`
  (default `admin:security`,
  `server/authgent_server/config.py:120`), checked in
  `_require_operator_scope` (`server/authgent_server/endpoints/security.py:50`).
  See the "Why compromise-flagging is a separate path" section below for the
  full rationale, which is also inlined as a docstring on
  `flag_compromised` itself.
- **Toy local receiver**: implemented as a research artifact rather than a
  product feature. `server/tests/research/caep_latency_benchmark.py`'s
  `VerifyingReceiver` class (line 108) is a genuine `asyncio` TCP server: it
  parses a real HTTP/1.1 request, verifies the HMAC transport signature, and
  verifies the SET's own ES256 JWS signature against authgent's real public
  key fetched from the JWKS document, then records a high-resolution
  (`time.perf_counter()`) timestamp at the instant both checks pass. This is
  not a mock, but it is also not shipped as an application endpoint; see
  "What is explicitly NOT implemented" below.
- **Tests**: `server/tests/test_caep.py`, 15 tests covering SET shape and
  jti-uniqueness (2), signing against the real JWKS key and HMAC transport
  signing (2), no-receivers no-op, retry-then-succeed, retry-exhaustion, and
  independent multi-receiver delivery (5), the `flag_compromised` service
  path (blocklist + transmit, cascade to descendants, idempotency) (3), and
  the `POST /security/tokens/compromise` endpoint (auth required, scope
  required, happy path) plus a regression guard proving routine
  `revoke_token` does *not* trigger CAEP transmission (4).

## Why compromise-flagging is a separate trigger path

CAEP transmission is wired into a new `flag_compromised` method, not bolted
onto the existing RFC 7009 `revoke_token` self-revocation flow, for three
reasons (also documented inline at
`server/authgent_server/services/token_service.py:1054`):

1. **Different caller and trust level.** `revoke_token` is called by the
   token's own client authenticating with its own client secret, a routine
   action (logout, credential rotation). `flag_compromised` is called by an
   operator or detector acting on a third party's token, gated on a scope
   (`caep_operator_scope`) that is always enforced, with no "open" mode.
2. **Different externally-visible effect.** Routine revocation is a purely
   local blocklist row; nothing is broadcast. Compromise-flagging
   additionally transmits a signed SET over the network to external relying
   parties, an action with cost, latency, and failure modes that a routine
   self-revocation call should not incur or be delayed by.
3. **Different semantics for the receiving relying party.** A CAEP
   `session-revoked` event tells a relying party "treat this as an active
   compromise, right now." Firing it on every ordinary revocation would
   make it useless as a compromise signal, since this prototype defines no
   payload field distinguishing "routine" from "urgent."

## Event types supported

**`session-revoked` only.** This prototype does not implement, and does not
claim to implement, any other CAEP event type (`credential-change`,
`assurance-level-change`, `token-claims-change`, `device-compliance-change`).

It also does **not** implement delegation-chain-ancestry events or
relationship-graph propagation signals. That is explicitly out of scope and
belongs to a different, unrelated line of work (the delegation-chain
revocation cascade described in
`docs/security-advisories/2026-08-non-cascading-revocation.md` is a separate,
already-shipped mechanism that this prototype reuses for the local
blocklist side-effect, but it is not a CAEP event and is not transmitted to
receivers as one).

## What is explicitly NOT implemented

- **Full SSF (Shared Signals Framework) stream management.** No stream
  registration API, no delivery-method negotiation, no per-stream
  configuration or status endpoint, no stream verification event. Receivers
  are a flat, server-wide, comma-separated URL list read from `Settings`
  (`Settings.caep_receiver_urls`,
  `server/authgent_server/config.py:110`), configured once for the whole
  server, analogous to `WebhookHITLProvider`'s single `webhook_url`.
- **Poll-based delivery.** Only RFC 8935 push delivery is implemented. No
  polling endpoint for receivers that prefer to pull.
- **Receiver-address storage tied to `DelegationReceipt` rows or any
  per-agent registration concept.** `DelegationReceipt`
  (`server/authgent_server/models/delegation_receipt.py`) has no
  receiver-endpoint field and none was added; receivers are not scoped
  per-agent, per-client, or per-delegation-chain.
- **Cross-domain support.** Delivery targets are plain URLs with no
  cross-domain trust negotiation, mutual TLS, or receiver identity
  verification beyond the shared HMAC secret.
- **A production receiver endpoint.** The verifying receiver used for the
  benchmark (`server/tests/research/caep_latency_benchmark.py`,
  `VerifyingReceiver`) is a research artifact: a standalone `asyncio` TCP
  server started and torn down by the benchmark script itself, not an
  authgent application route. It performs real signature verification but
  ships no persistence, no replay-detection store for received SET `jti`s,
  and no operational hardening.
- **Replay detection on the receiving side.** Nothing in this prototype
  tracks previously-seen SET `jti` values to reject replayed pushes; RFC
  8417 §2's replay-detection requirement is satisfied on the *sending* side
  (each SET gets a fresh, random `jti`,
  `server/tests/test_caep.py:61`) but no receiver-side dedup store exists.
- **Delivery acknowledgment beyond an HTTP status code.** No SET-specific
  ack/negative-ack payload protocol (RFC 8935 supports this as an option);
  a receiver returning any 2xx status is treated as successful delivery.

## Benchmark: compromise-flagged to receiver-verified latency

**Methodology.** For each receiver count N in {1, 10, 50, 100, 250}: start N
independent real `asyncio` TCP servers on `127.0.0.1`, each performing
genuine HTTP/1.1 parsing, HMAC-SHA256 transport-signature verification, and
ES256 JWS verification of the SET against authgent's real public signing key
(fetched once from `JWKSService.get_jwks_document` before timing starts,
mirroring a relying party's warm JWKS cache). Record `t0` immediately before
calling `TokenService.flag_compromised` (the "compromise flagged" instant);
each receiver records its own `time.perf_counter()` timestamp at the instant
both signature checks pass. All receivers and the transmitter share one
process and one event loop, so no cross-machine clock-skew correction is
needed. Each N was run 5 times (`REPEAT_COUNT = 5`); all per-run,
per-receiver latencies are saved raw, not just aggregates. Full methodology
and reproduction steps: `server/tests/research/caep_latency_benchmark.py`
module docstring. Raw results:
`server/tests/research/caep_latency_results.json`.

**What this does NOT measure:** real WAN network latency (everything runs
over loopback), receiver-side business-logic processing after verification
(e.g., actually tearing down a session), the one-time JWKS fetch, or
receiver downtime/retry behavior (all benchmark receivers return 200 on the
first attempt, so the retry+backoff path is never exercised by the
benchmark itself, only by the dedicated retry tests in `test_caep.py`).

**Measured results** (from `caep_latency_results.json`, generated
2026-08-18T04:11:39Z; all figures in milliseconds, aggregated across 5 runs
per N, over every individual receiver's verified latency):

| N receivers | min (ms) | median (ms) | mean (ms) | max (ms) |
|---|---|---|---|---|
| 1 | 6.66 | 7.25 | 11.54 | 28.66 |
| 10 | 35.90 | 40.11 | 39.86 | 42.44 |
| 50 | 166.24 | 182.85 | 183.83 | 199.94 |
| 100 | 315.65 | 351.47 | 351.17 | 379.26 |
| 250 | 802.87 | 889.99 | 891.83 | 1009.80 |

**Baseline comparison.** The alternative to real-time CAEP notification is
waiting for the compromised token's natural expiry. This codebase's own
default access-token TTL is 900 seconds (15 minutes):
`access_token_ttl: int = 900`, `server/authgent_server/config.py:31`. This
is authgent's own configured default, not an externally assumed value. At
every N tested, worst-case measured CAEP delivery-and-verification latency
(up to ~1.01 seconds at N=250) is roughly three orders of magnitude faster
than the 900-second natural-expiry baseline.

**Honest caveat on scaling.** Latency grows roughly linearly with receiver
count in this single-process benchmark (approximately 3.5-4ms per receiver
at N=250), because all receivers and the transmitting client share one
process, one event loop, and, implicitly, one machine's CPU and one
loopback network stack. This is not a claim about production fan-out
behavior with receivers on separate machines and real network paths; it
reflects the specific, disclosed methodology above.

## Reproduction

```
cd server && source .venv/bin/activate
python tests/research/caep_latency_benchmark.py
```

Regenerates `server/tests/research/caep_latency_results.json`. Not part of
the default CI/regression suite (real sockets, real wall-clock timing); run
explicitly.
