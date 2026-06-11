---
title: "Transparency Logs for Agent OAuth Tool-Call Events"
abbrev: "Agent Action Transparency"
docname: draft-agnihotri-oauth-agent-action-transparency-00
category: info
ipr: trust200902
area: Security
workgroup: OAuth Working Group
keyword:
  - OAuth
  - AI agent
  - transparency log
  - audit
  - delegation
author:
  -
    fullname: Dhruv Agnihotri
    organization: Independent
    email: dhruv@authgent.dev
normative:
  RFC8693:
  RFC9449:
  RFC9457:
  RFC9162:
informative:
  RFC6962:
  I-D.draft-ietf-oauth-identity-chaining-14: identity-chaining
--- abstract

This document defines a profile of an append-only transparency log for
OAuth 2.0 tool-call events emitted by AI-agent authorization servers. It
borrows the Merkle-tree construction from {{RFC9162}} and is intended to
record, with cryptographic integrity, the delegation chain (RFC 8693
nested ``act`` claims), the issuing authorization server, the calling
client, and the tool invocation that consumed the token. Auditors,
incident responders, and downstream services can verify the log's
contents without trusting the AS at log-read time. This makes
agent-driven tool calls auditable across organisational boundaries in
the way certificate transparency made TLS auditable.

--- middle

# Introduction

OAuth 2.0 audit logs are typically operator-trusted: the AS records
what it issued, and downstream services trust that record. With
multi-hop agent delegation chains -- particularly across trust domains,
as defined in {{identity-chaining}} -- this trust assumption breaks down.
A receiving service cannot independently verify (a) that the issuing
AS in fact issued a particular token, (b) that the chain that led to
this issuance was not spliced from another flow, or (c) that a tool
call that consumed the token actually ran with the claimed scope.

This document specifies a transparency-log format for agent OAuth
tool-call events. Each entry binds:

- The token's ``jti``, ``iss``, ``sub``, and ``act`` chain.
- The DPoP key thumbprint ({{RFC9449}}), if any.
- The tool name and a hash of the tool input.
- The issuing AS's signature.

Entries are appended to an RFC 9162 / RFC 6962-style Merkle tree.
The AS publishes signed tree heads. Verifiers fetch entries plus
inclusion proofs and confirm consistency between successive heads.

The intent is not to replace existing audit logs but to give
auditors, incident responders, and federated services a chain of
custody that is independent of any single AS's good behaviour.

# Conventions

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and
"OPTIONAL" in this document are to be interpreted as described in
BCP 14.

# Log Entry Format

Each log entry is a JSON object with the following claims:

| Claim | Required | Description |
|---|---|---|
| ``ver`` | yes | Format version. ``1`` for this document. |
| ``ts`` | yes | UNIX timestamp of the event. |
| ``iss`` | yes | URL of the issuing authorization server. |
| ``jti`` | yes | JTI of the token whose use is being logged. |
| ``sub`` | yes | Subject claim of the token. |
| ``act`` | optional | Nested ``act`` chain per RFC 8693. |
| ``cnf`` | optional | Confirmation method (e.g. DPoP ``jkt``). |
| ``aud`` | yes | Audience the token was used against. |
| ``tool`` | yes | Identifier of the tool that consumed the token. |
| ``input_hash`` | optional | SHA-256 of the tool's input arguments. |
| ``status`` | yes | ``allowed`` \| ``denied`` \| ``stepped_up``. |
| ``receipt`` | optional | Signed delegation receipt (out of scope here). |

The AS signs each entry with its issuer key over the canonical
serialisation defined in {{Section sig-canonical}}.

## Canonical Serialisation {#sig-canonical}

Entries are canonicalised using JCS (RFC 8785). The signature is an
ES256 JWS detached signature over the canonicalised bytes.

# Log Structure

The log SHOULD be implemented as a Merkle tree following {{RFC9162}}
(Certificate Transparency 2.0). Implementations MAY use the
{{RFC6962}} variant.

The AS exposes:

- ``GET /.well-known/oauth-transparency-log`` returning the
  structure version, the current signed tree head, and the URL of
  the entry endpoint.
- ``GET /transparency/entries?start=N&end=M`` returning a range of
  entries.
- ``GET /transparency/proof?leaf_hash=...`` returning an inclusion
  proof for a specific entry.

# Verifier Behaviour

A consumer of an agent-issued token MAY:

1. Fetch the AS's signed tree head.
2. Compute the leaf hash for the event it expects to find.
3. Request an inclusion proof.
4. Verify the proof against the tree head.
5. Periodically request consistency proofs between historical
   tree heads to detect log forks.

# Reference Implementation

A working open-source reference implementation is available in
authgent (Apache 2.0): <https://github.com/authgent/authgent>.

The reference implementation uses ES256 signing keys, persists
entries in the existing audit subsystem, and exposes the
endpoints defined in this draft.

# Security Considerations

## Privacy

Tool inputs may contain personal data. ``input_hash`` records a
collision-resistant digest rather than the input itself.
Implementations MUST avoid logging plaintext bearer tokens; only the
``jti`` is recorded.

## Log Forks

Verifiers SHOULD periodically check consistency proofs between log
heads obtained from different vantage points (mirrors, gossip
networks). An AS that forks its log to hide events will produce
inconsistent heads to two verifiers; this is the standard CT
threat model applied to agent OAuth.

# IANA Considerations

This document requests no IANA actions in this revision.

--- back

# Acknowledgements

This profile builds directly on RFC 9162 (Certificate Transparency
2.0), the Sigstore Rekor design, and RFC 8693 token exchange. The
problem statement was sharpened in conversation with implementers of
identity-chaining and transaction-tokens.
