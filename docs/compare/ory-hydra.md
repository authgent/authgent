# authgent vs Ory Hydra

Ory Hydra (17.2k★) is the spec-purist's OAuth 2.1 / OIDC server. authgent
and Hydra share a "follow the RFC" philosophy and complement each other
when the deployment is agent-heavy.

## TL;DR

- Pick **Hydra** if you want a battle-tested OIDC-Certified OAuth server
  with a managed cloud option and you're comfortable building the agent
  layer yourself on top of consent + login workflows.
- Pick **authgent** if you want the agent layer *included* —
  identity-chaining, transaction tokens, nested-`act` delegation,
  signed receipts, MCP examples + scanner — without building it on
  Hydra's lower-level primitives.

## Side-by-side

| Capability | Ory Hydra (2.x) | authgent |
|---|:-:|:-:|
| OpenID Certified | ✅ | not yet |
| OAuth 2.1 + RFC 7591 DCR | ✅ | ✅ |
| RFC 9728 PRM | community module | ✅ |
| RFC 9207 `iss` | ✅ | ✅ |
| RFC 9449 DPoP | ✅ | ✅ default |
| `draft-ietf-oauth-identity-chaining` | not implemented | ✅ |
| `draft-ietf-oauth-transaction-tokens` | not implemented | ✅ |
| RFC 8693 token exchange | optional plugin | ✅ first-class |
| Multi-hop nested-`act` | not built-in | ✅ |
| Signed delegation receipts | not built-in | ✅ |
| Login + consent UI | external (you build it) | bundled minimal UI |
| Ecosystem (Kratos, Oathkeeper, Keto) | ✅ | not in scope |
| Managed cloud option | ✅ Ory Network | ❌ |
| Language | Go | Python |
| Footprint | ~50 MB | ~80 MB |
| License | Apache 2.0 | Apache 2.0 |

(Sources: ory.com/hydra, oryhydra.com, the linked draft datatracker
pages.)

## Where Hydra wins

- **OpenID Certification.** Hydra has been certified for years.
  authgent has a clean codebase that should certify, but hasn't.
- **Ecosystem.** Hydra plus Kratos (identity), Oathkeeper (gateway),
  and Keto (authorization) form a coherent stack with overlapping
  documentation and joint marketing.
- **Managed cloud.** Ory Network offers a hosted Hydra — useful when
  your team doesn't want to operate the AS at all.
- **Hardening.** A decade of issues filed and closed. authgent's
  surface is small and audited but its history is short.

## Where authgent wins

- **Agent-native specs out of the box.** Hydra is OAuth-correct;
  authgent is OAuth-correct *plus* implements the WG-track agent
  drafts.
- **Receipts + chain integrity.** RFC 8693 has a known structural
  weakness (a compromised intermediary can splice tokens from
  different chains). authgent mitigates this with per-step signed
  receipts; Hydra leaves it to the integrator.
- **MCP support.** First-class `mcp` SDK example with stdio + HTTP,
  client compatibility matrix, and the `authgent lint` scanner.
- **One process.** authgent ships login UI, consent, RFC 7591 DCR,
  RFC 9728 PRM, refresh rotation, revocation, introspection, audit,
  and the JWT signing key store in one binary. Hydra splits these
  across the Ory ecosystem.

## Compose them

Hydra-then-authgent isn't a common pattern (both are full ASes), but
authgent can sit *behind* Oathkeeper as the agent-tier issuer, with
Hydra owning human OIDC.

For most agent-heavy deployments, picking one or the other is the
right call. Use the comparison above plus the SLO requirements your
team needs.

## Joint, not antagonistic

Both projects are spec-purist. If you find a place where authgent
diverges from a normative spec section, please file an issue:
<https://github.com/authgent/authgent/issues>. Spec-conformance bugs
are prioritised.
