# Identity Chaining Across Trust Domains in authgent

A walkthrough of how authgent implements
[draft-ietf-oauth-identity-chaining-14](https://datatracker.ietf.org/doc/draft-ietf-oauth-identity-chaining/),
the IETF OAuth WG specification (currently in IESG approval) for preserving
identity and authorization context across organisational trust boundaries.

This document is the deep dive. The summary table is in [STANDARDS.md](../STANDARDS.md).

## Why identity chaining?

OAuth's `act` claim chain (RFC 8693) handles agent-to-agent delegation
*within* one organisation. When an agent in your domain needs to call a
resource in **another organisation's** domain, the receiving authorization
server doesn't trust your `act` chain — it has its own identity model.

Identity chaining solves this by combining:

1. **RFC 8693 token exchange** — Domain A's AS exchanges your existing
   token for a short-lived JWT *grant* whose audience is Domain B's AS.
2. **RFC 7523 `jwt-bearer`** — Domain B's AS validates the grant and
   issues a Domain-B access token that the caller uses against Domain B's
   resources.

The chain becomes **two cryptographic steps over two trust boundaries**,
each enforced by an authorization server, with no shared session state.

## Sequence

```
┌─────────┐      ┌──────────────┐     ┌──────────────┐     ┌──────────┐
│ Client  │      │ Domain A AS  │     │ Domain B AS  │     │ Domain B │
│ in A    │      │ (authgent)   │     │ (authgent or │     │ Resource │
│         │      │              │     │  any RFC7523-│     │  Server  │
│         │      │              │     │  capable AS) │     │          │
└────┬────┘      └──────┬───────┘     └──────┬───────┘     └────┬─────┘
     │                  │                     │                   │
     │ 1. token-exchange│                     │                   │
     │ requested_token_type=jwt               │                   │
     │ audience=Domain-B-AS                   │                   │
     │ ────────────────►│                     │                   │
     │                  │                     │                   │
     │ ◄────────────────│ JWT grant           │                   │
     │   issued_token_type=jwt                │                   │
     │                  │                     │                   │
     │ 2. jwt-bearer    │                     │                   │
     │    assertion=<JWT grant>               │                   │
     │ ─────────────────────────────────────►│                   │
     │                  │                     │                   │
     │                  │   verify signature, │                   │
     │                  │   aud, iss, jti     │                   │
     │                  │   single-use guard  │                   │
     │                  │                     │                   │
     │ ◄─────────────────────────────────────│ Domain B access   │
     │                  │                     │ token             │
     │                  │                     │                   │
     │ 3. call resource (Domain B token)     │                   │
     │ ──────────────────────────────────────────────────────────►│
```

## Domain A: minting the JWT authorization grant

`POST /token` with the spec-mandated parameters:

```http
POST /token HTTP/1.1
Host: as.a.example
Content-Type: application/x-www-form-urlencoded

grant_type=urn:ietf:params:oauth:grant-type:token-exchange
&subject_token=<existing token>
&subject_token_type=urn:ietf:params:oauth:token-type:access_token
&requested_token_type=urn:ietf:params:oauth:token-type:jwt
&audience=https://as.b.example/token
&scope=api.read
```

authgent's response:

```json
{
  "access_token": "<JWT grant>",
  "issued_token_type": "urn:ietf:params:oauth:token-type:jwt",
  "token_type": "N_A",
  "expires_in": 60,
  "scope": "api.read"
}
```

The JWT grant looks like:

```json
{
  "iss": "https://as.a.example",
  "aud": "https://as.b.example/token",
  "sub": "user:alice@a.example",
  "exp": 1717930960,
  "iat": 1717930900,
  "nbf": 1717930900,
  "jti": "tok_QrLHhzj9...",
  "scope": "api.read",
  "client_id": "agnt_caller_in_a"
}
```

### authgent code path

`endpoints/token.py` → `TokenService.issue_token()` →
`_handle_token_exchange()` detects `requested_token_type == JWT_TOKEN_TYPE`
and forwards to `_issue_chaining_grant()`:

1. **Policy check (§2.3.2)** — `audience_target` must be in
   `AUTHGENT_TRUSTED_CHAINING_TARGETS` (if non-empty). Empty list = open.
2. **Verify subject_token** — same dispatch as the regular token-exchange
   flow (`access_token` → JWKS verify + blocklist; `id_token` → external
   OIDC verifier).
3. **Claims transcription (§2.5)** — `claims_transcription.py` filters
   parent claims through the configured policy (`preserve_sub` by default,
   or `minimize` for privacy-preserving deployments).
4. **Sign** — ES256 JWT with `iss`, `aud=audience_target`, `exp` = `iat + 60s`,
   plus transcribed claims.
5. **Audit** — `token.chaining_grant_issued` event with `txn_id`, `audience`,
   `ttl`.

## Domain B: consuming the grant

```http
POST /token HTTP/1.1
Host: as.b.example
Content-Type: application/x-www-form-urlencoded

grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer
&assertion=<JWT grant from above>
```

### authgent code path

`endpoints/token.py` → `TokenService.issue_token()` →
`_handle_jwt_bearer()`:

1. **Verify assertion (§2.4.2 + RFC 7523 §§3, 3.1)** —
   `ChainingGrantVerifier.verify_assertion()` does:
   - decode header for `kid`, payload for `iss`
   - `iss` must be in `AUTHGENT_TRUSTED_CHAINING_ISSUERS`
   - if `iss == self`, look up the kid in our local `signing_keys` table
     (this is the **co-located fast path** used by single-instance
     federations and tests)
   - else, fetch JWKS over HTTPS with TTL caching and thundering-herd
     protection (mirrors the proven pattern from `external_oidc.py`)
   - PyJWT verifies signature, `exp`, `iat`, `iss`, `aud` (must equal our
     `server_url` or `server_url + /token`)
   - require `jti`, `sub`, `aud`, `iss`, `exp`, `iat`
2. **Single-use guard (§5.5)** — insert assertion's `jti` into
   `token_blocklist` with `reason="chaining_grant_consumed"`. If insert
   raises (UNIQUE constraint) or the jti is already blocklisted, reject.
3. **Issue Domain-B access token** — normal access token bound to
   `resource` (or our issuer). Carries `chained_from = assertion.iss` so
   downstream services see the cross-domain origin. **No refresh token**
   is issued (§5.4).
4. **Audit** — `token.chaining_grant_consumed` event linking `assertion_iss`,
   `assertion_jti`, new access-token `jti`.

## Security considerations applied

| Spec § | Concern | authgent enforcement |
|---|---|---|
| 5.1 | client authentication | inherits `client_secret_post` / `client_secret_basic` |
| 5.2 | sender-constrained tokens | DPoP `cnf.jkt` propagated into Domain-B access token |
| 5.3 | authorized use of `subject_token` | `verify_and_check_blocklist` rejects revoked tokens before mint |
| 5.4 | no refresh tokens | `_handle_jwt_bearer` deliberately omits refresh issuance |
| 5.5 | short-lived | `chaining_grant_ttl` defaults to **60s**; tested by `test_chaining_grant_ttl_is_short` |
| 5.5 | single-use | `token_blocklist` row blocks reuse; tested by `test_chaining_grant_replay_rejected` |
| 5.5 | known client at Domain B | inherited (Domain B AS authenticates the client redeeming the grant) |

## Configuration

```bash
# Domain A allow-list (which downstream ASes we will issue grants for; empty = open)
export AUTHGENT_TRUSTED_CHAINING_TARGETS='["https://as.b.example/token"]'

# Domain B allow-list (which upstream ASes we accept grants from; empty disables consumer)
export AUTHGENT_TRUSTED_CHAINING_ISSUERS='["https://as.a.example"]'

# Grant TTL (seconds). Default 60.
export AUTHGENT_CHAINING_GRANT_TTL=60

# Claims transcription policy: "preserve_sub" (default) or "minimize"
export AUTHGENT_CHAINING_CLAIMS_POLICY=preserve_sub
```

## SDK helpers

**Python:**

```python
from authgent import AgentAuthClient

async with AgentAuthClient("https://as.a.example") as a:
    grant = await a.start_identity_chain(
        subject_token=existing_token,
        target_authorization_server="https://as.b.example/token",
        client_id=..., client_secret=...,
    )

async with AgentAuthClient("https://as.b.example") as b:
    access = await b.consume_identity_chain(
        assertion=grant.access_token,
        client_id=..., client_secret=...,
    )
```

**TypeScript:**

```typescript
const grant = await aClient.startIdentityChain({
  subjectToken: existingToken,
  targetAuthorizationServer: "https://as.b.example/token",
  clientId, clientSecret,
});

const access = await bClient.consumeIdentityChain({
  assertion: grant.accessToken,
  clientId, clientSecret,
});
```

## Interop testing

The 17-test conformance suite at
[`server/tests/test_identity_chaining.py`](../server/tests/test_identity_chaining.py)
maps each test to the spec section it exercises (see "Conformance test
matrix" in [STANDARDS.md](../STANDARDS.md)).

Co-locating Domain A and Domain B inside one authgent instance is supported
for testing and single-tenant deployments. Set
`AUTHGENT_TRUSTED_CHAINING_ISSUERS` to your own `server_url` and the
`ChainingGrantVerifier` will use the local `signing_keys` table instead of
making an HTTPS call to `/.well-known/jwks.json`.

## Reporting non-conformance

If authgent diverges from the spec, open a GitHub issue with:

- the section number
- the verbatim spec text
- the divergence observed
- a minimal reproduction
