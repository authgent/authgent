---
title: "Implementation Status of OAuth Identity Chaining and Transaction Tokens"
abbrev: "Agent OAuth Impl Status"
docname: draft-agnihotri-oauth-agent-impl-status-00
category: info
ipr: trust200902
submissionType: IETF
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
    email: dagni@umich.edu
normative:
  I-D.draft-ietf-oauth-identity-chaining-14:
  I-D.draft-ietf-oauth-transaction-tokens-08:
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

# Status of This Memo

This section is to be removed before publishing as an RFC.

This section records the status of known implementations of the
protocols defined by {{I-D.ietf-oauth-identity-chaining}} and
{{I-D.ietf-oauth-transaction-tokens}} at the time of posting of
this Internet-Draft, in accordance with the guidelines in {{!RFC7942}}.
The description of implementations in this section is intended to
assist the IETF in its decision processes in progressing drafts to
RFCs. Please note that the listing of any individual implementation
here does not imply endorsement by the IETF. Furthermore, no effort
has been spent to verify the information presented here that was
supplied by IETF contributors. This is not intended as, and must not
be construed to be, a catalog of available implementations or their
features. Readers are advised to note that other implementations may
exist.

According to {{!RFC7942}}, "this will allow reviewers and working
groups to assign due consideration to documents that have the benefit
of running code, which may serve as evidence of valuable
experimentation and feedback that have made the implemented protocols
more mature. It is up to the individual working groups to use this
information as they see fit".

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

The key words "**MUST**", "**MUST NOT**", "**REQUIRED**", "**SHALL**",
"**SHALL NOT**", "**SHOULD**", "**SHOULD NOT**", "**RECOMMENDED**",
"**NOT RECOMMENDED**", "**MAY**", and "**OPTIONAL**" in this document
are to be interpreted as described in BCP 14 {{!RFC2119}} {{!RFC8174}}
when, and only when, they appear in all capitals, as shown here.

# Implementation: identity-chaining

## Implementer

- Project: authgent
- Repository: <https://github.com/authgent/authgent>
- License: Apache 2.0
- Maturity: production-deployed; 476 tests; 83% coverage; live demo
  at <https://authgent-demo.dhruvagnihotri.com>.
- Contact: <dagni@umich.edu>

## Coverage map

Section 2.1 (Overview / sequence)
: Implemented in `services/token_service.py` functions
  `_issue_chaining_grant` and `_handle_jwt_bearer`.

Section 2.2 (Discovery via RFC 9728 PRM)
: Implemented in `endpoints/wellknown.py`.

Section 2.3.1 (Token Exchange request)
: Implemented in `services/token_service.py` function
  `_handle_token_exchange`, which branches on
  `requested_token_type=jwt`.

Section 2.3.1 (audience or resource REQUIRED)
: Enforced; raises `InvalidRequest` when neither is present.

Section 2.3.2 (Policy and claims transformation)
: Trust-domain policy via `trusted_chaining_targets` allowlist;
  claim transformation in `services/claims_transcription.py`
  (pluggable Protocol).

Section 2.3.3 (`aud` MUST identify Domain B)
: The audience claim is built directly from `audience_target`.

Section 2.4.1 (`jwt-bearer` grant type URN)
: `JWT_BEARER_GRANT` constant plus handler dispatch.

Section 2.4.2 (RFC 7523 Sections 3 and 3.1 validation)
: Implemented in `services/chaining_verifier.py` function
  `verify_assertion`.

Section 2.5 (Claims transcription)
: `services/claims_transcription.py` ships `preserve_sub` (default)
  and `minimize` policies via a pluggable Protocol.

Section 3 (Metadata field `identity_chaining_requested_token_types_supported`)
: Advertised by `endpoints/wellknown.py`.

Section 5.1 (Client authentication)
: Inherited; supports `client_secret_post` and `client_secret_basic`.

Section 5.2 (Sender constraining via DPoP)
: The DPoP `cnf.jkt` value is preserved into the Domain-B access
  token.

Section 5.3 (Authorized use of subject_token)
: Revocation check via `verify_and_check_blocklist` before mint.

Section 5.4 (SHOULD NOT issue refresh tokens)
: `_handle_jwt_bearer` deliberately omits refresh issuance.

Section 5.5 (short-lived; single-use)
: `chaining_grant_ttl` defaults to 60 seconds; the assertion `jti`
  is added to `token_blocklist` with reason
  `chaining_grant_consumed` on consumption; replay is rejected.

Test surface: `server/tests/test_identity_chaining.py` (17 tests, named
after the spec sections they exercise).

## Editorial observation

Section 2.5 ("Claims Transcription") permits the Domain-A authorization server
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

Section 3 (token type URN)
: `TXN_TOKEN_TYPE` constant.

Section 3 (`typ` header `txntoken+jwt`)
: Set via `_jwks.sign_jwt(claims, headers={"typ": "txntoken+jwt"})`.

Section 3 (required claims)
: `iat`, `aud`, `exp`, `txn`, `sub`, `scope`, and `req_wl`
  are all built in `_issue_transaction_token`.

Section 3 (optional `tctx` immutable transaction context)
: Carried from the `request_details` form parameter.

Section 3 (optional `rctx` requester context)
: Composed in `_issue_transaction_token` with auto-derived
  `req_ip` and `authn`.

Section 3 (response `issued_token_type=...:txn_token`, `token_type=N_A`)
: Hardcoded.

Section 7 (short-lived)
: `txn_token_ttl` defaults to 120 seconds.

Section 7.2 (scope MUST NOT exceed subject_token)
: Inline `requested.issubset(parent_scopes)` check; raises
  `AccessDenied` on violation.

Section 11 (no refresh tokens)
: Response omits `refresh_token`.

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

This document is informational and reports the existence of an
implementation. The security considerations of the protocols
implemented are addressed in the respective specifications:
{{I-D.ietf-oauth-identity-chaining}} Section 5 and
{{I-D.ietf-oauth-transaction-tokens}} Section 11. In particular,
implementers should review:

- Section 5.1-5.5 of identity-chaining-14: client authentication at both
  Domain A and Domain B, sender-constraining via DPoP {{!RFC9449}},
  authorized use of subject_token, and short-lived single-use
  semantics for the JWT authorization grant.
- Section 11 of transaction-tokens-08: short-lived TT-tokens, scope
  reduction relative to the subject_token (Section 7.2), and the
  no-refresh-token requirement.

The reporting implementation discussed here is open source and may
be inspected for adherence to these considerations at the URLs given
in the Implementation sections.

--- back

# Acknowledgments

Thanks to the editors of `draft-ietf-oauth-identity-chaining-14` -
Arndt Schwenkschuster (Defakto Security), Pieter Kasselman (Defakto
Security), Kelley Burgin (MITRE), Michael Jenkins (NSA-CCSS), Brian
Campbell (Ping Identity), and Aaron Parecki (Okta) - and the editors
of `draft-ietf-oauth-transaction-tokens-08` - Atul Tulshibagwale
(CrowdStrike), George Fletcher (Practical Identity LLC), and Pieter
Kasselman (Defakto Security) - for the specifications this document
reports on.
