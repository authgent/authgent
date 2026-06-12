---
title: "Implementation Status of draft-ietf-oauth-identity-chaining and draft-ietf-oauth-transaction-tokens"
abbrev: "Agent OAuth Impl Status"
docname: draft-agnihotri-oauth-agent-impl-status-00
category: info
ipr: trust200902
area: Security
workgroup: OAuth Working Group
keyword:
  - OAuth
  - identity chaining
  - transaction tokens
  - implementation status
  - AI agent
author:
  -
    fullname: Dhruv Agnihotri
    organization: Independent
    email: dhruv@authgent.dev
normative:
  I-D.draft-ietf-oauth-identity-chaining-14:
  I-D.draft-ietf-oauth-transaction-tokens-08:
informative:
  RFC8693:
  RFC7523:
  RFC9449:
  RFC9728:
--- abstract

This document reports an open-source implementation of two WG-track OAuth
drafts: `draft-ietf-oauth-identity-chaining-14` (cross-domain identity
chaining) and `draft-ietf-oauth-transaction-tokens-08` (transaction
tokens). It maps every normative section of each draft to the corresponding
source location in the implementation, identifies one ambiguity surfaced
during implementation, and offers the implementation as an interop partner
for any WG-adopted draft revision.

The intent is to give the editors of both drafts material they can include
in an Implementation Status appendix without further work on their part.

--- middle

# Introduction

Two WG-track OAuth drafts that currently lack listed implementations:

- `draft-ietf-oauth-identity-chaining-14` (state: Approved-announcement
  to be sent / Revised I-D Needed)
- `draft-ietf-oauth-transaction-tokens-08` (state: WG Last Call)

This document reports an Apache-2.0 implementation of both, suitable for
inclusion in an Implementation Status appendix per RFC 7942. The
implementation is in production use at <https://authgent.github.io/authgent/>
and is published as `authgent-server` on PyPI.

The implementation tracks the drafts at the revision in the title; this
document will be revised when a successor draft of either is published.

# Conventions

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and
"OPTIONAL" in this document are to be interpreted as described in
BCP 14.

# Implementation: identity-chaining

## Implementer

- Project: authgent
- Repository: <https://github.com/authgent/authgent>
- License: Apache 2.0
- Maturity: production-deployed; 476 tests; 83% coverage; live demo
  at <https://authgent-demo.dhruvagnihotri.com>.
- Contact: <dhruv@authgent.dev>

## Coverage map

| Spec section | Implemented | Source |
|---|---|---|
| §2.1 Overview / sequence | Yes | `services/token_service.py:_issue_chaining_grant`, `services/token_service.py:_handle_jwt_bearer` |
| §2.2 Discovery via RFC 9728 PRM | Yes | `endpoints/wellknown.py` |
| §2.3.1 Token Exchange request | Yes | `services/token_service.py:_handle_token_exchange` (branches on `requested_token_type=jwt`) |
| §2.3.1 audience or resource REQUIRED | Yes | enforced; raises `InvalidRequest` |
| §2.3.2 Policy: deny invalid/policy-rejected; AS may add/remove/change claims | Yes | `trusted_chaining_targets` allowlist; `services/claims_transcription.py` (pluggable) |
| §2.3.3 `aud` MUST identify Domain B | Yes | claim built directly from `audience_target` |
| §2.4.1 `urn:ietf:params:oauth:grant-type:jwt-bearer` | Yes | `JWT_BEARER_GRANT` constant + handler dispatch |
| §2.4.2 RFC 7523 §§3, 3.1 validation | Yes | `services/chaining_verifier.py:verify_assertion` |
| §2.5 Claims transcription | Yes | `services/claims_transcription.py` ships `preserve_sub` (default) and `minimize` policies; pluggable Protocol |
| §3 Metadata field `identity_chaining_requested_token_types_supported` | Yes | `endpoints/wellknown.py` |
| §5.1 Client authentication | Inherited | `client_secret_post` / `client_secret_basic` |
| §5.2 Sender constraining (DPoP) | Yes | DPoP `cnf.jkt` is preserved into the Domain-B access token |
| §5.3 Authorized use of subject_token | Yes | `verify_and_check_blocklist` checks revocation before mint |
| §5.4 SHOULD NOT issue refresh tokens | Yes | `_handle_jwt_bearer` deliberately omits refresh issuance |
| §5.5 short-lived; single-use | Yes | `chaining_grant_ttl` defaults to 60s; assertion `jti` is added to `token_blocklist` with `reason="chaining_grant_consumed"` on consumption; reuse rejected |

Test surface: `server/tests/test_identity_chaining.py` (17 tests, named
after the spec sections they exercise).

## Editorial observation

§2.5 ("Claims Transcription") permits the Domain-A authorization server
to add, remove, or change claims, but is silent on the case where the
incoming `subject_token` carries no `sub` claim. Two reasonable
interpretations exist:

1. The transcribed grant inherits the absence of `sub` and Domain B
   resolves identity from `idp_iss`/`idp_sub` (or refuses).
2. The transcription policy is required to produce a `sub` (e.g. by
   synthesising one from the IdP claims) so Domain B has a stable
   subject identifier.

The implementation currently picks (1) and refuses the chaining flow when
`sub` is unresolvable, but (2) is also defensible. Editorial guidance in
a future revision would help interop.

# Implementation: transaction-tokens

## Coverage map

| Spec section | Implemented | Source |
|---|---|---|
| §3 token type URN | Yes | `TXN_TOKEN_TYPE` constant |
| §3 `typ` header `txntoken+jwt` | Yes | `_jwks.sign_jwt(claims, headers={"typ": "txntoken+jwt"})` |
| §3 required claims `iat`, `aud`, `exp`, `txn`, `sub`, `scope`, `req_wl` | Yes | built in `_issue_transaction_token` |
| §3 optional `tctx` (immutable transaction context) | Yes | from `request_details` form param |
| §3 optional `rctx` (requester context) with auto `req_ip`, `authn` | Yes | composed in `_issue_transaction_token` |
| §3 response `issued_token_type=...:txn_token`, `token_type=N_A` | Yes | hardcoded |
| §7 short-lived | Yes | `txn_token_ttl` defaults to 120s |
| §7.2 scope MUST NOT exceed subject_token | Yes | inline `requested.issubset(parent_scopes)` check; raises `AccessDenied` |
| §11 no refresh tokens | Yes | response omits `refresh_token` |

Test surface: `server/tests/test_transaction_tokens.py` (8 tests).

# Implementation Notes

## Scanner

The implementation also publishes an open-source conformance scanner
that audits any deployed MCP authorization server against the discovery
metadata required by RFC 9728, RFC 8414, RFC 7591, RFC 7636, RFC 9207,
RFC 8707, and the relevant MCP authorization spec sections. The scanner
runs the same code path as the implementation's CI test suite, so
"authgent passes the scanner" and "authgent passes its conformance
tests" produce the same answer.

The scanner is available at `<https://authgent.github.io/authgent/scan/>`
and as a CLI (`authgent-server lint <url>`). Scanner check `MCP-PKCE-002`
operationalises the advertise-vs-enforce sub-variant of the known
PKCE-downgrade family (OAuch BCP_4_8; Authentik CVE-2024-23647;
Better-Auth GHSA-9h47-pqcx-hjr4) for MCP-OAuth deployments
specifically; the scanner does not claim to originate the underlying
attack class.

## Calibration

The implementation publishes a calibration set
(<https://github.com/authgent/authgent/blob/main/docs/calibration.md>)
documenting the expected grade for six known shapes (perfect MCP-2026
conformant; legacy IdP without MCP-only fields; PKCE-plain advertised;
PRM missing; implicit grant advertised; DCR-mirror critical) so weight
changes can't drift silently.

# Interoperability

The implementer offers interop testing against any other implementation
of either draft. Contact the address in the front matter, or open a
GitHub issue at <https://github.com/authgent/authgent/issues>.

# IANA Considerations

This document requests no IANA actions.

# Security Considerations

This document reports the existence of an implementation; security
considerations of the implemented protocols are addressed in the
respective drafts.

--- back

# Acknowledgments

Thanks to the editors of `draft-ietf-oauth-identity-chaining` (Arndt
Schwenkschuster, Pieter Kasselman, Kelley Burgin, Michael Jenkins,
Brian Campbell, Aaron Parecki) and `draft-ietf-oauth-transaction-tokens`
(Atul Tulshibagwale, George Fletcher, Pieter Kasselman) for the
specifications this document reports on.
