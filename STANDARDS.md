# Standards Implementation Report -- authgent

**This document is the authoritative map between IETF/RFC specifications
and authgent's source code.** It is written for spec authors, implementers,
auditors, and reviewers evaluating authgent as a reference implementation.

Last updated: 2026-06-12. authgent version: 0.3.x (see [CHANGELOG.md](CHANGELOG.md)).
Test count: **476**, all passing. Coverage: **83%**. Lint/format/type: clean.

**IETF Internet-Draft (canonical citation)**: `draft-agnihotri-oauth-agent-impl-status-00`,
posted 2026-06-12, available at <https://datatracker.ietf.org/doc/draft-agnihotri-oauth-agent-impl-status/>.
Editors of `draft-ietf-oauth-identity-chaining` and `draft-ietf-oauth-transaction-tokens`
considering an Implementation Status section may reference the I-D directly,
or cite the per-section maps below.

---

## At a glance

| Status | Spec | Section coverage | Tests |
|---|---|---|---|
| **WG-track reference impl** | [draft-ietf-oauth-identity-chaining-15](https://datatracker.ietf.org/doc/draft-ietf-oauth-identity-chaining/) | §2.1, §2.2, §2.3, §2.4, §2.5, §3, §5.1–5.5 | [test_identity_chaining.py](server/tests/test_identity_chaining.py) — 17 tests |
| **WG-track reference impl** | [draft-ietf-oauth-transaction-tokens-09](https://datatracker.ietf.org/doc/draft-ietf-oauth-transaction-tokens/) | §3, §7, §11, §13.6, §13.14 | [test_transaction_tokens.py](server/tests/test_transaction_tokens.py) — 9 tests |
| **Production** | [RFC 8693](https://datatracker.ietf.org/doc/html/rfc8693) Token Exchange | Full + nested `act` chain extension | test_token_advanced.py, test_delegation.py |
| **Production** | [RFC 7523](https://datatracker.ietf.org/doc/html/rfc7523) JWT Profile | §3, §3.1 (assertion validation) | test_identity_chaining.py |
| **Production** | [RFC 9449](https://datatracker.ietf.org/doc/html/rfc9449) DPoP | Full | test_dpop.py, test_dpop_integration.py |
| **Production** | [RFC 9728](https://datatracker.ietf.org/doc/html/rfc9728) PRM | Full | test_wellknown.py |
| **Production** | [RFC 8414](https://datatracker.ietf.org/doc/html/rfc8414) AS Metadata | Full | test_wellknown.py |
| **Production** | [RFC 7591](https://datatracker.ietf.org/doc/html/rfc7591) DCR | Full | test_register.py, test_registration_policy.py |
| **Production** | [RFC 7662](https://datatracker.ietf.org/doc/html/rfc7662) Introspection | Full | test_introspect.py |
| **Production** | [RFC 7009](https://datatracker.ietf.org/doc/html/rfc7009) Revocation | Full + RFC 7009 §2.1 ownership check | test_revoke.py |
| **Production** | [RFC 8628](https://datatracker.ietf.org/doc/html/rfc8628) Device Auth | Full | test_device.py |
| **Production** | [RFC 8707](https://datatracker.ietf.org/doc/html/rfc8707) Resource Indicators | Full | tests across token flows |
| **Production** | [RFC 9457](https://datatracker.ietf.org/doc/html/rfc9457) Problem Details | Error responses | test_error_handler.py |
| **Production** | [RFC 7636](https://datatracker.ietf.org/doc/html/rfc7636) PKCE (S256 only) | Full | test_authorize.py |
| **Production** | OAuth 2.1 (BCP) | Required PKCE, no implicit, no password | server-wide |

---

## draft-ietf-oauth-identity-chaining-15 — section by section

### §2.1 Overview

The two-step flow is implemented as two distinct code paths:

- **Domain A (mint a JWT authorization grant)**:
  [`token_service.py`](server/authgent_server/services/token_service.py) →
  `_issue_chaining_grant()`.
- **Domain B (consume the grant via `jwt-bearer`)**:
  [`token_service.py`](server/authgent_server/services/token_service.py) →
  `_handle_jwt_bearer()` plus
  [`chaining_verifier.py`](server/authgent_server/services/chaining_verifier.py) →
  `ChainingGrantVerifier.verify_assertion()`.

### §2.2 Discovery

> "A client may use the `authorization_servers` property as defined in OAuth 2.0 Protected Resource Metadata [RFC9728]…"

Implemented by the existing
[`/.well-known/oauth-protected-resource`](server/authgent_server/endpoints/wellknown.py) endpoint.

### §2.3 Token Exchange step

| Spec requirement | authgent code |
|---|---|
| §2.3.1 `requested_token_type=urn:ietf:params:oauth:token-type:jwt` | `JWT_TOKEN_TYPE` constant + branch in `_handle_token_exchange` |
| §2.3.1 *one of* `resource` or `audience` REQUIRED | enforced in `_handle_token_exchange` (raises `InvalidRequest`) |
| §2.3.2 deny invalid/policy-rejected requests per RFC 8693 §2.2.2 | `trusted_chaining_targets` allowlist + `AccessDenied` |
| §2.3.2 AS may add/remove/change claims | `services/claims_transcription.py` (pluggable) |
| §2.3.3 `aud` MUST identify the requested AS in Domain B | claim built directly from `audience_target` |
| §2.3.3 RECOMMENDED single AS in `aud` | single string (not array) |
| §2.3 response `issued_token_type=urn:ietf:params:oauth:token-type:jwt` | hardcoded in `_issue_chaining_grant` return |

### §2.4 JWT Authorization Grant step

| Spec requirement | authgent code |
|---|---|
| §2.4.1 `grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer` | `JWT_BEARER_GRANT` constant + handler dispatch |
| §2.4.1 `assertion` parameter | plumbed via `endpoints/token.py` |
| §2.4.2 validate per RFC 7523 §§3, 3.1 | `ChainingGrantVerifier.verify_assertion` |
| §2.4.2 `aud` MUST identify this AS | accepted = `[server_url, server_url + "/token"]` |
| §2.4.2 deny if subject unidentifiable | explicit `if not subject: raise InvalidGrant` |

### §2.5 Claims Transcription

> "The authorization server in trust domain A can add, remove or change claims…"

[`services/claims_transcription.py`](server/authgent_server/services/claims_transcription.py)
ships two policies (`PreserveSubjectTranscription`, `MinimizeTranscription`) and
exposes a `ClaimsTranscriber` Protocol so operators can plug in custom mappers.

### §3 Authorization Server Metadata

> "`identity_chaining_requested_token_types_supported` … OPTIONAL."

Advertised by
[`/.well-known/oauth-authorization-server`](server/authgent_server/endpoints/wellknown.py).

### §5 Security Considerations

| Section | authgent enforcement |
|---|---|
| §5.1 client authentication | inherits authgent's existing `client_secret_post` / `client_secret_basic` |
| §5.2 sender-constraining (DPoP) | DPoP `cnf.jkt` is preserved into the Domain-B access token |
| §5.3 authorized use of subject_token | `verify_and_check_blocklist` checks revocation before mint |
| §5.4 SHOULD NOT issue refresh tokens | `_handle_jwt_bearer` deliberately omits refresh issuance |
| §5.5 short-lived | `chaining_grant_ttl` defaults to **60s** |
| §5.5 single-use | grant `jti` is added to `token_blocklist` with `reason="chaining_grant_consumed"` on consumption; reuse rejected |
| §5.5 client auth at Domain B | inherited |

---

## draft-ietf-oauth-transaction-tokens-09 — section by section

### §3 Token Service request/response

| Spec requirement | authgent code |
|---|---|
| `requested_token_type=urn:ietf:params:oauth:token-type:txn_token` | `TXN_TOKEN_TYPE` constant + branch in `_handle_token_exchange` |
| `typ` header `txntoken+jwt` | `_jwks.sign_jwt(claims, headers={"typ": "txntoken+jwt"})` |
| Required claims iat / aud / exp / txn / sub / scope / req_wl | built in `_issue_transaction_token` |
| Optional `tctx` (immutable transaction context) | from `request_details` form param |
| Optional `rctx` (requester context) with auto `req_ip`, `authn` | composed in `_issue_transaction_token` |
| Response `issued_token_type=urn:ietf:params:oauth:token-type:txn_token`, `token_type=N_A` | hardcoded |

### §7 Lifetime + replay

> "Expected to be short-lived (on the order of minutes or less)."

`txn_token_ttl` defaults to **120s**. `txn` is generated via
`secrets.token_urlsafe(24)` so two issuances differ — verified by
`test_txn_claim_is_unique_across_issuances`.

### §13.6 / §13.14 Scope policy

> "TTS MUST ensure that the requested `scope` of the Txn-Token is equal or less
> than the scope(s) associated with the original `subject_token`." (§13.6)
>
> "If the scope associated with a `subject_token` cannot be determined... the
> TTS MUST reject the Txn-Token Request and MUST NOT treat an unknown scope as
> unconstrained." (§13.14, added in -09 in response to an authgent-filed
> [issue](https://github.com/oauth-wg/oauth-transaction-tokens/issues/357))

Enforced inline — an absent or empty `scope` claim on the `subject_token`
yields an empty available-scope set, so any non-empty request is rejected
rather than passed through unconstrained:

```python
parent_scopes = set((parent_claims.get("scope") or "").split())
requested = set(scope.split()) if scope else set()
if requested and not requested.issubset(parent_scopes):
    raise AccessDenied(...)
```

Tested by `test_txn_token_scope_escalation_rejected`,
`test_txn_token_scope_subset_allowed`, and
`test_txn_token_no_parent_scope_rejects_nonempty_request` (§13.14).

### §11 No refresh tokens

`_issue_transaction_token` returns a `TokenResponse` without a `refresh_token`
field. Verified by `test_txn_token_no_refresh_token`.

---

## How to cite this implementation

If you are an IETF draft author maintaining an "Implementation Status"
section, please cite:

> **authgent** — open-source OAuth 2.1 server with identity-chaining
> and transaction-tokens reference implementations. Apache 2.0.
> <https://github.com/authgent/authgent>

See [`CITATION.cff`](CITATION.cff) for the machine-readable form.

---

## Conformance test matrix

| Spec section | Test | File |
|---|---|---|
| identity-chaining §3 metadata | `test_metadata_advertises_chaining_token_types` | test_identity_chaining.py |
| identity-chaining §2.3.1 audience required | `test_chaining_grant_missing_audience_and_resource_rejected` | test_identity_chaining.py |
| identity-chaining §2.3.1 resource alone | `test_chaining_grant_resource_alone_is_accepted` | test_identity_chaining.py |
| identity-chaining §2.3.2 trusted target | `test_chaining_grant_untrusted_target_rejected` | test_identity_chaining.py |
| identity-chaining §5.5 short-lived | `test_chaining_grant_ttl_is_short` | test_identity_chaining.py |
| identity-chaining §2.3 + §2.4 round trip | `test_round_trip_chaining_a_to_b` | test_identity_chaining.py |
| identity-chaining §5.5 single-use | `test_chaining_grant_replay_rejected` | test_identity_chaining.py |
| identity-chaining §2.4.1 assertion required | `test_chaining_grant_missing_assertion_rejected` | test_identity_chaining.py |
| identity-chaining §2.4.2 untrusted iss | `test_chaining_assertion_untrusted_issuer` | test_identity_chaining.py |
| identity-chaining §2.4.2 wrong aud | `test_chaining_assertion_wrong_audience_rejected` | test_identity_chaining.py |
| identity-chaining §2.4.2 unknown kid | `test_chaining_assertion_unknown_kid_rejected` | test_identity_chaining.py |
| identity-chaining regression of nested-act | `test_default_token_exchange_unchanged_by_chaining` | test_identity_chaining.py |
| txn-tokens §3 typ header + required claims | `test_txn_token_issuance_required_claims` | test_transaction_tokens.py |
| txn-tokens §3 tctx/rctx | `test_txn_token_carries_tctx_and_rctx` | test_transaction_tokens.py |
| txn-tokens §7 short-lived | `test_txn_token_short_lived` | test_transaction_tokens.py |
| txn-tokens §7.2 scope policy | `test_txn_token_scope_escalation_rejected`, `test_txn_token_scope_subset_allowed` | test_transaction_tokens.py |
| txn-tokens §11 no refresh | `test_txn_token_no_refresh_token` | test_transaction_tokens.py |
| txn-tokens §3 unique txn | `test_txn_claim_is_unique_across_issuances` | test_transaction_tokens.py |
| txn-tokens metadata advertisement | `test_metadata_advertises_txn_token_type` | test_transaction_tokens.py |

---

## Reproducing the conformance run

```bash
git clone https://github.com/authgent/authgent.git
cd authgent/server
pip install -e ".[dev]"

# All tests
pytest tests/ \
  --ignore=tests/simulation_test.py \
  --ignore=tests/agent_to_agent_simulation.py \
  --ignore=tests/adversarial_live_test.py -v

# Just the IETF-track reference implementations
pytest tests/test_identity_chaining.py tests/test_transaction_tokens.py -v
```

Expected: **525 tests pass** in ~2 minutes on a 2024-vintage laptop.

---

## Reporting issues

Found a place where authgent diverges from spec text? Open an issue:
<https://github.com/authgent/authgent/issues>. Spec-conformance bugs are
prioritised.
