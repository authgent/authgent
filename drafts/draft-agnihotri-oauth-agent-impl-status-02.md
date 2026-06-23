---
title: "Implementation Status of OAuth Identity Chaining and Transaction Tokens"
abbrev: "OAuth Chaining/TxnTok Impl Status"
docname: draft-agnihotri-oauth-agent-impl-status-02
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
  - running code
author:
  -
    fullname: Dhruv Agnihotri
    organization: Independent
    email: dagni@umich.edu
informative:
  I-D.ietf-oauth-identity-chaining:
    override: true
    title: "OAuth Identity and Authorization Chaining Across Domains"
    target: "https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-chaining-15"
    date: 2026-06-19
    author:
      - name: Arndt Schwenkschuster
        org: Defakto Security
      - name: Pieter Kasselman
        org: Defakto Security
      - name: Kelley Burgin
        org: MITRE
      - name: Michael Jenkins
        surname: Jenkins
        initials: M. J.
        org: NSA-CCSS
      - name: Brian Campbell
        org: Ping Identity
      - name: Aaron Parecki
        org: Okta
    seriesinfo:
      Internet-Draft: draft-ietf-oauth-identity-chaining-15
  I-D.ietf-oauth-transaction-tokens:
  RFC7942:
  RFC7523:
  RFC9449:
  RFC9728:
  RFC8414:

--- abstract

This document reports an open-source implementation of two OAuth Working
Group draft specifications: cross-domain identity chaining and
transaction tokens. For each draft, this report maps every normative
section to the corresponding source location in the implementation
under test, summarises the test surface that exercises the section,
and records one open-issue candidate per parent draft. The report is
prepared in accordance with RFC 7942 and is intended for use by the
editors of the two parent drafts.

--- middle

# Conventions

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and
"OPTIONAL" in this document are to be interpreted as described in
BCP 14 {{!RFC2119}} {{!RFC8174}} when, and only when, they appear in
all capitals, as shown here. This document is itself descriptive
(Informational) and defines no protocol behaviour of its own. The
BCP 14 key words appear in this document only inside text quoted from,
or proposed as suggested wording to, the editors of the parent drafts;
in those quotations the key words carry their BCP 14 meaning with
respect to the parent protocol, not with respect to this report.

# Introduction

This document reports the implementation status of two Working Group
drafts of the OAuth Working Group at the IETF, prepared in accordance
with the guidelines in RFC 7942 ("Improving Awareness of Running Code:
The Implementation Status Section"). The two reported drafts are
identified in {{reported-drafts}}.

The intent of this report is to provide the editors of the two parent
drafts with material that can, at the editors' discretion, be
incorporated into the parent draft as an Implementation Status
section, used to inform Working Group Last Call discussions, or
otherwise referenced during progression of the parent drafts to RFC.

The implementation reported in this document operates a live public
demo deployment under the name "authgent" (see {{implementation}}),
and is offered as an interoperability partner for any other
implementation of either parent draft.

# Reported Drafts {#reported-drafts}

This document reports the implementation status of:

1. The Internet-Draft "OAuth Identity and Authorization Chaining Across
   Domains," version -15
   ({{I-D.ietf-oauth-identity-chaining}}). At the time of writing,
   this draft has been approved by the IESG and is in the RFC Editor
   queue.

2. The Internet-Draft "Transaction Tokens," version -08
   ({{I-D.ietf-oauth-transaction-tokens}}). At the time of writing,
   this draft is in Working Group Last Call.

Subsequent revisions of either parent draft may necessitate revision
of this report.

# Implementation: authgent {#implementation}

This section provides per-implementation metadata in the format
recommended by Section 2 of RFC 7942.

Organisation:
: Independent. Author of record: Dhruv Agnihotri.

Name and URL:
: authgent, https://github.com/authgent/authgent

Description:
: An open-source OAuth 2.1 authorisation server implemented in Python,
  with both cross-domain identity chaining (per the first reported
  draft) and transaction-token issuance (per the second reported
  draft) as first-class flows on the token endpoint.

Maturity:
: Experimental to operational. The implementation is published as the
  authgent-server distribution on PyPI and as the authgent
  distribution on PyPI and npm, and operates a live public demo
  deployment published via the repository above. Continuous-integration
  test surface: 522 tests with 84 percent line coverage as of the date
  of this document; the test and coverage figures are reproducible from
  the public continuous-integration workflow in the repository above
  (GitHub Actions).

Coverage:
: All normative sections of both reported drafts that this
  implementation could realistically exercise from a single-organisation
  test harness. See {{cov-chaining}} and {{cov-txn}} for per-section
  detail. One open issue per draft is recorded in {{open-issues}}. Of
  the 522 continuous-integration tests, 25 directly exercise the two
  reported drafts (17 for identity-chaining, 8 for transaction-tokens);
  the remainder cover the underlying OAuth 2.1 authorisation server and
  are not specific to either reported draft. Error and negative paths
  beyond those named in the per-section maps, and conformance points
  that require a second cooperating implementation, are out of scope of
  the present report.

Interoperability:
: No interoperability testing against a second, independent
  implementation of either parent draft has been performed to date. The
  implementer offers to participate in interoperability testing (see
  Contact, below, and {{implementation}}).

Version compatibility:
: identity-chaining: tracks revision -15. transaction-tokens: tracks
  revision -08.

Licensing:
: Apache License, Version 2.0.

Implementation experience:
: Roughly six months of implementation effort by a single author. No
  unworkable spec text was encountered; the open issues recorded in
  {{open-issues}} were resolved by local interpretation but interop
  testing has not yet been performed against a second implementation.

Contact:
: dagni@umich.edu

Last updated:
: The date of this Internet-Draft.

# Coverage of identity-chaining-15 {#cov-chaining}

This section maps each normative requirement of
{{I-D.ietf-oauth-identity-chaining}} to the source location in the
authgent implementation that fulfils it. Source paths are relative to
the repository root.

Section 2.1 (Overview / sequence):
: Implemented across two functions in `services/token_service.py`:
  `_issue_chaining_grant` (Domain A) and `_handle_jwt_bearer`
  (Domain B).

Section 2.2 (Discovery via Protected Resource Metadata):
: Discovery is served by `endpoints/wellknown.py`, conforming to
  {{RFC9728}}.

Section 2.3.1 (Token Exchange request):
: `_handle_token_exchange` in `services/token_service.py` branches
  on `requested_token_type=urn:ietf:params:oauth:token-type:jwt`.

Section 2.3.1 (audience or resource REQUIRED):
: Enforced. The token endpoint raises an error of type
  `InvalidRequest` when neither parameter is present.

Section 2.3.2 (policy and claims transformation):
: Trust-domain policy is applied via a configurable
  `trusted_chaining_targets` allowlist. Claim transformation is
  delegated to `services/claims_transcription.py`, which exposes a
  pluggable Protocol so that operators can provide their own
  transformation policy without modifying core code.

Section 2.3.3 (`aud` MUST identify Domain B):
: The audience claim of the issued JWT authorisation grant is
  populated from the `audience_target` derived from the inbound
  `audience` or `resource` parameter.

Section 2.4.1 (`urn:ietf:params:oauth:grant-type:jwt-bearer`):
: The grant type is recognised by the token endpoint and dispatched
  to `_handle_jwt_bearer`.

Section 2.4.2 (assertion validation per RFC 7523):
: Implemented in `services/chaining_verifier.py` function
  `verify_assertion`, which applies the validation steps of Sections 3
  and 3.1 of {{RFC7523}}.

Section 2.5 (claims transcription):
: `services/claims_transcription.py` ships two transformation
  policies: `preserve_sub` (default), which copies the parent `sub`
  through; and `minimize`, which carries only `idp_iss` and
  `idp_sub`. See {{open-issue-chaining}} for an interpretation
  question encountered while implementing this section.

Section 3 (metadata field
`identity_chaining_requested_token_types_supported`):
: Advertised by `endpoints/wellknown.py`, conforming to {{RFC8414}}.

Section 5.1 (client authentication):
: Inherited from the OAuth 2.1 framework support in the implementation.
  Both `client_secret_post` and `client_secret_basic` are supported.

Section 5.2 (sender constraining via DPoP):
: When the inbound subject token is DPoP-bound, the `cnf.jkt`
  thumbprint is propagated into the Domain-B access token, in
  conformance with {{RFC9449}}.

Section 5.3 (authorised use of subject_token):
: Revocation is checked via `verify_and_check_blocklist` before any
  Domain-B token is minted.

Section 5.4 (no refresh tokens for chaining):
: The `_handle_jwt_bearer` function omits refresh-token issuance,
  matching the spec recommendation.

Section 5.5 (short-lived; single-use):
: The chaining grant time-to-live (parameter `chaining_grant_ttl`)
  defaults to 60 seconds. The `jti` claim of each consumed assertion
  is added to the token blocklist with reason
  `chaining_grant_consumed`, and any subsequent attempt to consume
  the same assertion is rejected.

Test surface for identity-chaining: `server/tests/test_identity_chaining.py`,
17 tests, named after the spec sections they exercise.

# Coverage of transaction-tokens-08 {#cov-txn}

Section 16.1 (token type URN, registered in IANA; used in Section 12):
: The constant `TXN_TOKEN_TYPE` is the value
  `urn:ietf:params:oauth:token-type:txn_token`, the URN registered in
  Section 16.1 and used as the `requested_token_type` /
  `issued_token_type` value in the Section 12 request/response flow.

Section 10.1 (`typ` header `txntoken+jwt`):
: The JWT Header requirement that "the typ Header Parameter MUST be
  present and MUST have the value txntoken+jwt" is met by the signing
  helper, which sets the header via
  `_jwks.sign_jwt(claims, headers={"typ": "txntoken+jwt"})`.

Section 10.2 (required JWT body claims):
: The claims `iat`, `aud`, `exp`, `txn`, `sub`, `scope`, and `req_wl`
  (each marked REQUIRED in Section 10.2) are constructed in
  `_issue_transaction_token` for every issued Txn-Token.

Section 10.2.3 (optional `tctx`, immutable context):
: Carried verbatim from the `request_details` form parameter on the
  token endpoint when present.

Section 10.2.2 (optional `rctx`, requester context):
: Composed in `_issue_transaction_token` with auto-derived `req_ip`
  and `authn` values, the two members defined in Section 10.2.2.

Section 12.4 (Txn-Token Response shape):
: Per Section 12.4, `issued_token_type` is set to the value
  `urn:ietf:params:oauth:token-type:txn_token` and `token_type` is set
  to `N_A`.

Section 7 (Txn-Token Lifetime; short-lived tokens):
: The Txn-Token time-to-live (parameter `txn_token_ttl`) defaults to
  120 seconds, consistent with the Section 7 expectation that
  Txn-Tokens are short-lived (on the order of minutes or less).

Section 14.6 (Scope Processing; requested scope equal or less than
subject_token scope):
: Section 14.6 requires that "the TTS MUST ensure that the requested
  scope of the Txn-Token is equal or less than the scope(s) identified
  in the subject_token." An inline subset check
  (`requested.issubset(parent_scopes)`) is applied before issuance; on
  violation, the implementation raises an `AccessDenied` error.

Sections 14.3 and 12.4 (no refresh tokens):
: Section 14.3 states that "the Txn-Token response from the TTS MUST
  NOT include a refresh token" and Section 12.4 that "the Txn-Token
  Response MUST NOT include the refresh_token value." The
  token-endpoint response omits the `refresh_token` field for
  Txn-Token issuance.

Test surface for transaction-tokens:
`server/tests/test_transaction_tokens.py`, 8 tests.

# Open Issues Surfaced During Implementation {#open-issues}

This section records ambiguities encountered while implementing the
two parent drafts, and proposes specific text the editors may wish to
consider for a subsequent revision.

## identity-chaining: missing-`sub` handling in claims transcription {#open-issue-chaining}

Section 2.5 of {{I-D.ietf-oauth-identity-chaining}}, in its
"Transcribing the subject identifier" case, describes mapping a
subject identifier from one trust domain to another (its worked
example maps "johndoe@a.example" to "doe.john@b.example") and states
that "both authorization servers can add, change or remove claims."
The text addresses the case in which the subject identifier differs
between domains, but is silent on the case in which the inbound
subject token carries no `sub` claim at all (for example, a federated
assertion that conveys only `idp_iss` and `idp_sub`).

The editorial revision from -14 to -15 softened the scope-control
language of Section 2.5 from a normative form to "Authorization
Servers need to verify that the requested scopes are not higher
privileged than the scopes of the presented subject_token." That
change concerns scope control and does not bear on the missing-`sub`
case; as of -15, the missing-`sub` handling described below remains
underspecified.

Two reasonable interpretations exist:

1. Refuse at issuance: the Domain A authorisation server declines to
   mint a chaining grant when the subject token has no resolvable `sub`
   (and no documented policy for synthesising one).

2. Allow and defer: the Domain A authorisation server mints a grant
   that inherits the absence of `sub`, leaving the receiving Domain B
   to resolve identity from `idp_iss` and `idp_sub`, to synthesise a
   `sub`, or to refuse on consumption.

A third, related question is whether the transcription policy itself
ought to be required to produce a `sub` value (for example by
deterministically deriving one from `idp_iss` and `idp_sub`) so that
Domain B always has a stable subject identifier.

The authgent implementation effectively follows interpretation 2 (allow
and defer). Concretely, its behaviour is as follows. On the Domain A
issuance side, the grant-minting path (`_issue_chaining_grant` in
`services/token_service.py`) performs no `sub` check: if the subject
token carries no `sub`, a chaining grant is minted that simply lacks a
`sub` claim; issuance is not refused. The claims-transcription policy
discussed in {{cov-chaining}} is orthogonal to this question -- both
shipped policies are pure claim filters (they copy a fixed set of
claims forward when present) and neither adjudicates a missing `sub`.
On the Domain B consumption side, by contrast, `_handle_jwt_bearer` in
the same module applies a fixed (non-pluggable) check: consuming an
assertion that lacks an identifiable subject is rejected with an
`InvalidGrant` ("Assertion missing identifiable subject") error. The
net effect is that a subject token without `sub` is not rejected when
the grant is issued, but is rejected when the resulting assertion is
consumed. This behaviour is not presently covered by an automated
test.

Suggested editorial clarification: a sentence in Section 2.5 making the
choice explicit, for example: "If the subject token does not contain a
`sub` claim, the authorisation server MAY synthesise one from other
identity claims, or MAY refuse the request; the latter behaviour is
recommended unless the synthesis algorithm is documented in the
trust-domain policy." Once the editors indicate a preferred direction,
the implementation would follow it -- for instance, by adding a refusal
at the Domain A issuance step if refuse-at-issuance is chosen.

## transaction-tokens: scope subset check semantics on missing parent scope {#open-issue-txn}

Section 14.6 ("Scope Processing") of
{{I-D.ietf-oauth-transaction-tokens}} requires that "the TTS MUST
ensure that the requested scope of the Txn-Token is equal or less than
the scope(s) identified in the subject_token." The text presupposes
the presence of a `scope` claim on the subject token. The handling of
the case where the subject token has no `scope` claim at all (for
example, a JWT that conveys identity but expresses authorisation
through other claims) is not specified.

Two interpretations:

1. Treat absent parent scope as the empty set, requiring any explicit
   `scope` parameter on the Txn-Token request to also be empty or
   absent.

2. Treat absent parent scope as unconstrained, allowing the
   Txn-Token request to set any `scope` value.

The authgent implementation effectively follows interpretation 2. Its
scope-subset check (`_issue_transaction_token` in
`services/token_service.py`) only fires when the parent scope is
non-empty; when the subject token carries no `scope` claim the check is
skipped, so any requested scope is currently allowed through. This is a
literal reading of the Section 14.6 MUST, but it is arguably the
unintentional-scope-increase case the section exists to prevent -- which
is precisely why the absent-`scope` case warrants explicit text. A
conscientious implementer can land on this permissive behaviour without
realising it. This edge is not presently covered by an automated test.

Suggested editorial clarification: a sentence in Section 14.6 making
the choice explicit, for example: "If the subject_token carries no
`scope` claim, the Transaction Token Service MUST treat the available
scope as the empty set for the purpose of this comparison (and so MUST
NOT issue a Txn-Token bearing a non-empty scope)." Once the editors
indicate a preferred direction, the implementation would follow it.

# Implementation Status {#impl-status}

This section records the status of known implementations of the
protocols defined by {{I-D.ietf-oauth-identity-chaining}} and
{{I-D.ietf-oauth-transaction-tokens}} at the time of posting of this
Internet-Draft, in accordance with the guidelines in {{RFC7942}}. The
description of implementations in this section is intended to assist
the IETF in its decision processes in progressing drafts to RFCs.
Please note that the listing of any individual implementation here
does not imply endorsement by the IETF. Furthermore, no effort has
been spent to verify the information presented here that was supplied
by IETF contributors. This is not intended as, and must not be
construed to be, a catalog of available implementations or their
features. Readers are advised to note that other implementations may
exist.

According to {{RFC7942}}, "this will allow reviewers and working
groups to assign due consideration to documents that have the benefit
of running code, which may serve as evidence of valuable
experimentation and feedback that have made the implemented protocols
more mature. It is up to the individual working groups to use this
information as they see fit".

The single implementation reported here is described in
{{implementation}}, with per-section conformance maps in
{{cov-chaining}} and {{cov-txn}}, and open-issue candidates in
{{open-issues}}.

Note to RFC Editor: this section, and the per-section conformance maps
referenced from it, are to be removed before publication of any
parent draft as an RFC. The reference to RFC 7942 may also be removed
at that time.

# Interoperability Offer

The implementer offers interoperability testing against any other
implementation of either parent draft. Interested implementers may
make contact at the address in the front matter of this document, or
by opening an issue on the GitHub repository identified in
{{implementation}}.

# IANA Considerations

This document has no IANA actions.

# Security Considerations

This document reports the existence of an implementation. The
security considerations of the protocols implemented are addressed in
the parent specifications:
{{I-D.ietf-oauth-identity-chaining}}, Section 5; and
{{I-D.ietf-oauth-transaction-tokens}}, Section 14. Implementers and
reviewers are referred there.

The authgent implementation reported here is open source. Security
properties relevant to the parent drafts (in particular, sender
constraining of access tokens via DPoP {{RFC9449}}, blocklist-backed
revocation, single-use semantics for the JWT authorisation grant, and
scope-reduction enforcement on Txn-Tokens) may be inspected in the
repository identified in {{implementation}}.

--- back

# Document History

Note to RFC Editor: this section is to be removed before publication.

## Changes from -01 to -02

- Corrected the description of the implementation's behaviour in the
  transaction-tokens scope open issue ({{open-issue-txn}}). The -01 text
  stated the implementation followed interpretation 1 (treat absent
  parent scope as the empty set, the conservative reading); in fact the
  scope-subset check is skipped when the parent scope is absent, so the
  implementation follows interpretation 2 (absent parent scope treated
  as unconstrained). The open issue and suggested clarification are
  unchanged in substance; only the description of observed behaviour is
  corrected, and the footgun this represents is now noted explicitly.

## Changes from -00 to -01

- Updated the identity-chaining reference from -14 to -15 (an editorial
  revision; the parent draft is now in the RFC Editor queue), including
  the status line in {{reported-drafts}}, the version-compatibility
  field in {{implementation}}, and the heading of {{cov-chaining}}.
- Refreshed the implementation test surface from 476 tests / 83 percent
  line coverage to 522 tests / 84 percent line coverage.
- Updated the Section 2.5 open issue in {{open-issue-chaining}} to
  reflect the -15 wording. The -14-to-15 revision softened the
  scope-control language of Section 2.5 to "need to verify"; that
  change does not address the missing-`sub` claims-transcription case,
  which remains underspecified as of -15. The open issue is retained
  and its quoted text aligned to -15.
- Corrected the description of the implementation's missing-`sub`
  behaviour in {{open-issue-chaining}}: the implementation does not
  refuse at issuance and does not adjudicate the case in a pluggable
  transcription policy; it mints the grant and rejects the resulting
  assertion at consumption (allow-and-defer). The spec gap itself is
  unchanged.
- Remapped every transaction-tokens section citation in the
  transaction-tokens coverage map ({{cov-txn}}) and open issue
  ({{open-issue-txn}}) to the section structure of revision -08
  (token type URN to Section 16.1; JWT header to Section 10.1; required
  claims to Section 10.2; `rctx`/`tctx` to Sections 10.2.2/10.2.3;
  response shape to Section 12.4; scope processing to Section 14.6;
  no-refresh-token rule to Sections 14.3 and 12.4). The Section 7
  lifetime citation was already correct.
- Surfaced interoperability status and out-of-scope coverage explicitly
  in {{implementation}}, and added concrete suggested text to the
  transaction-tokens open issue.

# Acknowledgments

The author thanks the editors of {{I-D.ietf-oauth-identity-chaining}}
(Arndt Schwenkschuster of Defakto Security, Pieter Kasselman of
Defakto Security, Kelley Burgin of MITRE, Michael Jenkins of NSA-CCSS,
Brian Campbell of Ping Identity, and Aaron Parecki of Okta) and the
editors of {{I-D.ietf-oauth-transaction-tokens}} (Atul Tulshibagwale
of CrowdStrike, George Fletcher of Practical Identity LLC, and Pieter
Kasselman of Defakto Security) for the specifications this document
reports on.
