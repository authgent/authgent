# Transaction Tokens in authgent

A walkthrough of how authgent implements
[draft-ietf-oauth-transaction-tokens-09](https://datatracker.ietf.org/doc/draft-ietf-oauth-transaction-tokens/),
the IETF OAuth WG specification (currently in WG Last Call) for propagating
authorization context through internal call chains within a Trust Domain.

This document is the deep dive. The summary table is in [STANDARDS.md](../STANDARDS.md).

## Why Transaction Tokens?

Once a request enters your Trust Domain (typically through an API gateway),
it usually fans out across many internal services: order service, ledger,
audit, notifications, etc. Each downstream service needs to know **the
same things**:

- which user / agent is acting,
- what they're allowed to do for **this specific transaction**,
- where the request came from (IP, channel, authentication method),
- and *that the gateway already validated the external token*.

Without Txn-Tokens, every service either re-validates the gateway's
external token (slow, leaks the token, stretches its lifetime) or trusts
unsigned headers (insecure). The Transaction Token Service (TTS) issues a
short-lived signed JWT that **encodes the answer** to all four questions
and travels with the request.

## Sequence

```
┌─────────┐    ┌────────┐    ┌─────────┐     ┌──────────┐     ┌──────────┐
│ External│    │ API    │    │  TTS    │     │ Order    │     │ Ledger   │
│ caller  │    │ Gateway│    │(authgent│     │ Service  │     │ Service  │
│         │    │        │    │ )       │     │          │     │          │
└────┬────┘    └───┬────┘    └────┬────┘     └────┬─────┘     └────┬─────┘
     │             │              │                │                │
     │ external    │              │                │                │
     │ access tok  │              │                │                │
     │ ───────────►│              │                │                │
     │             │ token-exch + │                │                │
     │             │ requested=   │                │                │
     │             │ txn_token    │                │                │
     │             │ ─────────────►                │                │
     │             │              │                │                │
     │             │ ◄─────────── │ Txn-Token      │                │
     │             │   typ:txntoken+jwt            │                │
     │             │   tctx,rctx, │                │                │
     │             │   txn        │                │                │
     │             │              │                │                │
     │             │ POST /orders │                │                │
     │             │ Txn-Token: <jwt>              │                │
     │             │ ─────────────────────────────►│                │
     │             │              │                │ POST /debit    │
     │             │              │                │ Txn-Token: <jwt> (unmodified)
     │             │              │                │ ──────────────►│
     │             │              │                │                │
```

Every internal service:

1. validates the JWT signature against the TTS public key (cached),
2. checks `aud` matches the Trust Domain,
3. checks `exp` not expired,
4. trusts `tctx` / `rctx` as authoritative,
5. forwards the **same** Txn-Token unmodified to the next hop.

## Minting a Txn-Token

```http
POST /token HTTP/1.1
Host: tts.trust-domain.example
Content-Type: application/x-www-form-urlencoded

grant_type=urn:ietf:params:oauth:grant-type:token-exchange
&subject_token=<gateway's external access token>
&subject_token_type=urn:ietf:params:oauth:token-type:access_token
&requested_token_type=urn:ietf:params:oauth:token-type:txn_token
&audience=https://trust-domain.example/
&scope=trade.stocks
&request_details={"action":"BUY","ticker":"MSFT","quantity":"100"}
&request_context={"channel":"mobile"}
```

authgent's response (`token_type=N_A`, no refresh token per §11):

```json
{
  "access_token": "<JWT>",
  "issued_token_type": "urn:ietf:params:oauth:token-type:txn_token",
  "token_type": "N_A",
  "expires_in": 120,
  "scope": "trade.stocks"
}
```

Decoded JWT:

```json
{
  "iss": "https://tts.trust-domain.example",
  "iat": 1717930900,
  "aud": "https://trust-domain.example/",
  "exp": 1717931020,
  "txn": "fM3kQ7PdvLWp8uAxRSn2",
  "sub": "user:alice@a.example",
  "scope": "trade.stocks",
  "req_wl": "client:gateway-1",
  "tctx": {
    "action": "BUY",
    "ticker": "MSFT",
    "quantity": "100"
  },
  "rctx": {
    "channel": "mobile",
    "req_ip": "203.0.113.7",
    "authn": "urn:ietf:rfc:6749"
  }
}
```

JWT header:

```json
{ "kid": "...", "alg": "ES256", "typ": "txntoken+jwt" }
```

## authgent code path

`endpoints/token.py` → `TokenService.issue_token()` →
`_handle_token_exchange()` detects
`requested_token_type == TXN_TOKEN_TYPE` and forwards to
`_issue_transaction_token()`:

1. **Verify subject_token** — same dispatch as the regular flow.
2. **§7.2 scope policy** — requested `scope` must be a subset of the
   subject_token's scope. Otherwise raise `AccessDenied`. (The spec text:
   *"TTS MUST ensure that the requested scope of the Txn-Token is equal
   or less than the scope(s) identified in the subject_token."*)
3. **Generate `txn`** — `secrets.token_urlsafe(24)`. Unique per issuance.
4. **Compose `tctx`** from `request_details` form param if it parses as a
   JSON object.
5. **Compose `rctx`** = `request_context` ∪ auto-derived `req_ip` (from
   `request.client.host`) and `authn = urn:ietf:rfc:6749` default.
6. **Sign** — ES256 JWT with header `typ: txntoken+jwt`. Required claims
   per §3: `iat, aud, exp, txn, sub, scope, req_wl`. Plus `iss` (always
   set in authgent), `tctx`, `rctx`.
7. **Audit** — `token.txn_token_issued` with `txn`, `trust_domain`, `ttl`.
8. **Response** — `token_type=N_A`, `issued_token_type=...txn_token`, no
   `refresh_token`.

## Security considerations applied

| Spec §  | Concern | authgent enforcement |
|---|---|---|
| 7  | short-lived | `txn_token_ttl` defaults to **120s** |
| 7.2 | scope MUST NOT exceed subject_token | inline `requested.issubset(parent_scopes)` check |
| 7.3 | MUST NOT embed access tokens | only the parent's `sub`/`scope`/IdP provenance carry forward; the raw `subject_token` is never copied into the Txn-Token |
| 11 | no refresh tokens | response omits `refresh_token` |
| 3  | unique `txn` | 24-byte URL-safe random, tested for cross-issuance uniqueness |

## Configuration

```bash
# Trust Domain identifier emitted as `aud` (defaults to caller-provided audience)
export AUTHGENT_TXN_TOKEN_TRUST_DOMAIN="https://trust-domain.example/"

# Lifetime in seconds. §7 says "minutes or less". Default 120.
export AUTHGENT_TXN_TOKEN_TTL=120
```

## SDK helpers

**Python:**

```python
from authgent import AgentAuthClient

async with AgentAuthClient("https://tts.trust-domain.example") as tts:
    txn = await tts.issue_transaction_token(
        subject_token=external_token,
        trust_domain="https://trust-domain.example/",
        scope="trade.stocks",
        client_id=gateway_id,
        client_secret=gateway_secret,
        request_details={"action": "BUY", "ticker": "MSFT", "quantity": "100"},
        request_context={"channel": "mobile"},
    )
```

**TypeScript:**

```typescript
const txn = await tts.issueTransactionToken({
  subjectToken: externalToken,
  trustDomain: "https://trust-domain.example/",
  scope: "trade.stocks",
  clientId: gatewayId, clientSecret: gatewaySecret,
  requestDetails: { action: "BUY", ticker: "MSFT", quantity: "100" },
  requestContext: { channel: "mobile" },
});
```

## Internal-service validation pattern

Receiving services should:

1. fetch authgent's JWKS from `/.well-known/jwks.json` (cached);
2. verify the JWT (`alg=ES256`, signature, `iss`, `aud == trust_domain`,
   `exp`);
3. check `header.typ == "txntoken+jwt"`;
4. trust `tctx`/`rctx` as the authoritative authorization context;
5. forward the JWT unmodified to the next hop.

The Python SDK's existing `verify.py` and `JWKSFetcher` already handle the
mechanics — only the typ-header check is new.

## Interop testing

[`server/tests/test_transaction_tokens.py`](../server/tests/test_transaction_tokens.py)
covers all 8 normative paths with the spec section numbers in docstrings.
