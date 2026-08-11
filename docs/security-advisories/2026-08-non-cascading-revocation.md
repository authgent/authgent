# Security Advisory: Non-Cascading Revocation in Delegation Chains

**Date:** 2026-08-08
**Severity:** Medium. Requires the attacker to already hold a
legitimately-issued token from a delegation chain whose root gets
revoked; no forgery or credential theft is involved.
**Status:** Fixed on `main` as of this advisory's publication date.
**Affected versions:** 0.1.0 through 0.3.4 (all versions supporting
RFC 8693 token exchange with nested `act` claims).

## Summary

Revoking the root token of an RFC 8693 delegation chain (built via
repeated token exchange, agent A's token exchanged for agent B's,
exchanged for agent C's, and so on) did not revoke any already-issued
descendant token. Descendant tokens remained fully valid until natural
expiry, and could be exchanged for further tokens, extending a chain
whose root the operator believed was dead.

This is distinct from token forgery or signature bypass: every token in
an affected chain was cryptographically valid and correctly signed. The
gap was purely in revocation semantics: `revoke_token` blocklisted only
the single presented token's own `jti`; the `DelegationReceipt` table,
which records each exchange's `parent_token_jti`, was written at
issuance but never consulted at revocation time.

## What this advisory does NOT cover

This project's documentation (`SECURITY.md`, `ARCHITECTURE.md`,
`docs/DIAGRAMS.md`, `docs/compare/auth0.md`) previously described a
*different* attack, replaying or grafting a token into a delegation
chain it was not issued for, as defended by a rolling `chain_hash`
receipt verification. That description did not match the implementation:
`compute_chain_hash` computes a hash of the current token's own actor
list only (not a rolling hash chaining to the prior receipt, despite an
earlier diagram in `docs/DIAGRAMS.md` showing otherwise), and no
production code path ever reads a receipt back to verify it. This is a
separate, still-open gap. The documentation has been corrected to state
this plainly; a fix is tracked as future work, not shipped in this
advisory.

## Impact

An operator revoking a chain's root token to cut off a compromised or
misbehaving downstream agent would not, in fact, cut off that agent: its
already-issued token, and any tokens it had already exchanged onward,
remained live. In the worst case, the downstream agent could continue
minting further delegated tokens after the operator believed the chain
was terminated.

## Fix

Two independent mechanisms, both required (each closes a different
failure mode):

1. **Eager cascade** (`_cascade_revoke_descendants`,
   `authgent_server/services/token_service.py`): on revocation, a
   breadth-first walk of the `delegation_receipts` table blocklists
   every descendant token, directly and transitively.
2. **Lazy ancestor check** (`_first_revoked_ancestor`, same file, wired
   into `verify_and_check_blocklist`): on every subsequent use of a
   token (introspection, further exchange), walks the receipt chain
   upward and re-derives revocation status from current database
   state. This closes a genuine race the eager mechanism alone cannot:
   a token exchange concurrent with a revocation can commit a new
   descendant receipt after the eager walk has already passed that
   level, permanently escaping it. The lazy check does not depend on
   the eager walk's progress, since the root's own blocklist entry
   commits synchronously before the eager walk even starts.

Schema change: `DelegationReceipt` gained an `expires_at` column
(migration `003_delegation_receipt_expiry.py`) so cascade-generated
blocklist entries expire correctly rather than persisting indefinitely.

## Disclosed limitations of the fix (read before relying on this)

- **Scope: introspection-mediated validation only.** Both mechanisms
  activate when a relying party calls back into the authorization
  server (`/introspect` or a further `/token` exchange). A relying
  party performing local, stateless JWT signature validation, the
  standard reason to prefer JWTs over opaque tokens, never triggers
  either check and will accept a revoked-ancestor token until its
  natural expiry.
- **Unbounded fan-out.** No limit exists on how many descendants a
  token can accumulate. The eager cascade runs synchronously inside the
  `/revoke` request handler, so a large, adversarially-grown delegation
  tree can make a single revocation call perform correspondingly large
  work. Consider capping fan-out at issuance or moving the eager cascade
  to an asynchronous job in high-fan-out deployments; the lazy check
  provides correctness regardless, since it does not depend on the
  eager mechanism's progress.
- **Intra-domain scope only.** `DelegationReceipt` rows are created
  only in the intra-domain RFC 8693 exchange branch. The cross-domain
  identity-chaining and transaction-tokens branches create no receipts,
  so a descendant reachable only through a cross-domain hop is
  currently invisible to both mechanisms.

## Timeline

- 2026-08-08: Vulnerability found during security research into
  RFC 8693 delegation chain revocation semantics.
- 2026-08-08: Fix designed, implemented, and tested (16 dedicated
  regression tests; 541/541 of the full suite passing).
- 2026-08-08: Public documentation corrected; fix merged to `main`.
- 2026-08-08: Cross-implementation finding (the same gap, plus a
  narrower "chain-extension" variant not covered by Keycloak's existing
  documentation) reported to the Keycloak project via its stated
  security channel (`keycloak-security@googlegroups.com`).
- 2026-08-11: Keycloak Security team responded. Verbatim summary: the
  base non-cascading-revocation behavior is confirmed as documented,
  intentional design (avoiding "revocation chain" overhead for access
  tokens); no CVE will be assigned. The chain-extension variant this
  report specifically demonstrated, exchanging a descendant token
  *after* the root's revocation to mint a further token, is not
  addressed by their existing documentation; Keycloak agreed it is
  "worth making explicit in the documentation" and will track that
  separately.
- 2026-08-11: Requested permission to cite the private disclosure
  reply publicly. Declined, correctly: the `keycloak-security` mailing
  list is a private channel and Keycloak cannot authorize quoting or
  paraphrasing it. Keycloak pointed to its own public documentation
  (freely citable without permission) and invited a public GitHub
  issue for the documentation gap.
- 2026-08-11: Checked keycloak/keycloak's public issue tracker before
  filing anything, to avoid duplicating existing discussion. Found
  three closed issues (#33252, #37119, #37120) covering the base
  non-cascading case, none covering the chain-extension variant.
  Filed [keycloak/keycloak#51633](https://github.com/keycloak/keycloak/issues/51633),
  scoped specifically to that gap and citing the three closed issues
  as prior art.

## Credit

Found by the project's own maintainer during research for an academic
paper on this class of vulnerability. The identical base gap, plus the
chain-extension variant, is also present in Keycloak 26.7.1 (an
unrelated production identity server), confirmed via a real
reproduction against an unmodified instance. Keycloak's security team
reviewed the report and confirmed it accurately describes their
system's behavior (see Timeline above); this is offered as an
independent, cross-implementation data point that the vulnerability
class addressed by this advisory is not specific to authgent.
