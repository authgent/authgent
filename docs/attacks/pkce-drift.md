# PKCE Advertise-Drift: Discovery vs `/authorize` Mismatch in MCP-OAuth

**Class identifier:** `PKCE-ADVERTISE-DRIFT` (sub-variant of "PKCE Downgrade Attack")
**Scanner check:** `MCP-PKCE-002`
**CWE mapping:** [CWE-757](https://cwe.mitre.org/data/definitions/757.html) — Selection of Less-Secure Algorithm During Negotiation
**Related CWE:** [CWE-358](https://cwe.mitre.org/data/definitions/358.html) — Improperly Implemented Security Check for a Standard
**Spec citations:** [OAuth 2.1 §4.1.2.3](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1) · [RFC 7636 §4.4.1](https://datatracker.ietf.org/doc/html/rfc7636) · [MCP 2025-11-25 §authorization](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization)

> ⚠ **Prior art.** The "PKCE Downgrade" family is *not* novel; this page does **not** claim to be the first catalog of PKCE downgrade. What this page contributes is (a) a stable, MCP-OAuth-specific check ID (`MCP-PKCE-002`), (b) an unauthenticated heuristic safe to run from a public scanner, and (c) prevalence numbers for public MCP servers post-embargo. See [Prior art](#prior-art) for the references this work builds on.

---

## Definition

An OAuth 2.1 authorization server exhibits **PKCE-Drift** when its [RFC 8414][rfc8414] discovery metadata advertises only `S256` in `code_challenge_methods_supported`, but its `/authorize` endpoint accepts an authorization request carrying `code_challenge_method=plain` without rejecting it on the basis of the method.

The drift is between two surfaces of the same server:

- **Advertised** (RFC 8414): "I only support S256."
- **Enforced** (RFC 6749 / OAuth 2.1 / RFC 7636): "I will accept whatever the client sends."

A correct OAuth 2.1 server MUST reject `plain` at the `/authorize` endpoint with `error=invalid_request` and a description that names the method, regardless of what its discovery document says. Static metadata is not a substitute for runtime input validation.

[rfc8414]: https://datatracker.ietf.org/doc/html/rfc8414

---

## Why this matters

PKCE was added to OAuth in 2015 ([RFC 7636]) to bind an authorization code to the public client that requested it, defeating the auth-code interception attack. The `S256` method binds via SHA-256; `plain` binds the literal verifier and provides no protection if the verifier leaks (logs, intermediate proxies, browser history).

OAuth 2.1 ([draft-ietf-oauth-v2-1 §4.1.2.3]) makes `S256` mandatory and removes `plain`. The MCP authorization spec ([2025-11-25, §3 client discovery]) inherits OAuth 2.1's profile and likewise requires `S256`.

A server with PKCE-Drift looks compliant in metadata-only audits. A scanner that only fetches `/.well-known/oauth-authorization-server` and reads the JSON body will report a clean PKCE posture. But the actual attack surface — the `/authorize` endpoint — accepts the weaker method anyway, defeating the protection PKCE was added to provide.

[RFC 7636]: https://datatracker.ietf.org/doc/html/rfc7636
[draft-ietf-oauth-v2-1 §4.1.2.3]: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1

---

## Threat model

The attack chain that PKCE-Drift enables:

1. A malicious or compromised client (a rogue MCP integration, a side-loaded agent extension, an attacker-controlled MCP shim) initiates the authorization code flow against a vulnerable AS using `code_challenge_method=plain`.
2. The AS, despite advertising S256-only, accepts the request and issues an authorization code bound to the literal verifier.
3. The verifier ends up in places verifiers are typically considered safe under S256: agent debug logs, LangChain traces, AutoGen message histories, intermediate HTTP proxies, browser dev-tools recordings.
4. An attacker with access to any one of those locations recovers the verifier and exchanges the code for a token at `/token`.

S256 makes step 4 infeasible; the SHA-256 hash in transit is not enough to recover the verifier. `plain` makes step 4 trivial.

PKCE-Drift therefore re-opens the same attack window PKCE was added to close, while presenting a clean compliance posture to anyone reading the discovery document.

---

## How to test

The detection is a single unauthenticated GET to the authorize endpoint with a deliberately weak method, plus a heuristic on the response.

```bash
curl -i -G "${AUTHORIZE_ENDPOINT}" \
  --data-urlencode "response_type=code" \
  --data-urlencode "client_id=pkce-drift-probe" \
  --data-urlencode "redirect_uri=https://authgent.dev/lint-probe" \
  --data-urlencode "code_challenge=plain-probe" \
  --data-urlencode "code_challenge_method=plain" \
  --data-urlencode "state=lintprobe"
```

Compliant server (rejects `plain`):

- `400` with `error=invalid_request` *and* a description that names `code_challenge_method`, `pkce`, or `S256`.
- Or a `302` to the redirect URI with the same `error=invalid_request&error_description=...` query parameters.

PKCE-Drift signal:

- The server rejects the request, but for a *different* reason — typically `unauthorized_client` / `invalid_redirect_uri` validation that runs before PKCE validation. This is the **noisy** case; a probe with an unregistered client_id can't distinguish "method validation runs after client validation" from "method validation never runs". `MCP-PKCE-002` suppresses this case to avoid false-flagging Auth0/Okta/Keycloak (see *Suppression rules* below).
- The server returns `302`/`303` without naming the method in the error response.
- The server returns `200` with a consent page or non-error redirect.

The last two cases are the actionable PKCE-Drift signal. Operators should follow up by registering a real client and replaying with a correct `client_id`; if the AS *still* doesn't reject `plain`, the server has confirmed PKCE-Drift and the corresponding token exchange will succeed.

### Suppression rules

`MCP-PKCE-002` deliberately does **not** report drift when the response contains any of:

- `invalid_client` / `unauthorized_client` / `unknown_client` / `client_not_found`
- `invalid_redirect_uri` / `unregistered`

These are pre-PKCE rejection signals: the AS rejected the probe before its method validator could run, so the test is inconclusive. A scanner that flagged drift here would false-positive on every commercial IdP that validates `client_id` before `code_challenge_method`. Confirming or excluding drift in the suppressed case requires registering a real client (out of scope for an unauthenticated lint).

The intentional consequence is that `MCP-PKCE-002` has a known false-negative rate: a real PKCE-Drift in a server that *also* rejects unknown clients first will not be caught by an unauthenticated probe. Operators should treat the absence of `MCP-PKCE-002` as "not detected" rather than "not present" when the AS pre-validates clients.

---

## Remediation

For server operators:

1. **Validate `code_challenge_method` at request entry to `/authorize`**, before any client lookup or session mutation. Reject any value that is not in `code_challenge_methods_supported` with `error=invalid_request` and `error_description="code_challenge_method must be S256"`.
2. **Reject the request even if `code_challenge` is also missing.** PKCE is mandatory in OAuth 2.1; the authorize request without a code challenge is itself non-compliant.
3. **Treat `code_challenge_method=plain` as an explicit failure**, not a fallback. OAuth 2.1 removed `plain`; OAuth-2.0 servers receiving an OAuth-2.1-shaped flow MUST not silently downgrade.
4. **Do not rely on the `/token` endpoint to catch this.** A server that only enforces PKCE at `/token` has already issued an authorization code with a weak verifier binding; the leak window is between `/authorize` and `/token`. The check has to be at the front door.

For library authors:

- The OAuth-server frameworks that have shipped PKCE-Drift in production (anonymised in the prevalence section below) all share a code path where PKCE method validation lives in the `/token` exchange handler rather than the `/authorize` request validator. Move it forward.

---

## Prevalence

Prevalence numbers will be published here after the first responsible-disclosure window closes (2026-06-25). The methodology:

1. Scanner is run against every public MCP server in the [modelcontextprotocol.io](https://modelcontextprotocol.io) registry plus the [`awesome-mcp`](https://github.com/punkpeye/awesome-mcp-servers) community list.
2. Servers that match the `MCP-PKCE-002` heuristic are notified at their `security.txt` Contact (or, where absent, at the vendor's published security mailbox) on disclosure-day-0.
3. After 14 days, anonymised aggregate counts are published in `docs/attacks/pkce-drift.md` (this file). Per-vendor identification is *not* published unless the vendor explicitly opts in.

The prevalence section will read like:

> Of N public MCP servers scanned in June 2026, X (Y%) responded to a `code_challenge_method=plain` probe at `/authorize` without naming the method in their rejection. Of those, Z were confirmed via registered-client follow-up to accept `plain` in a complete authorization code flow.

This file updates with the numbers when the window closes.

---

## Prior art

The "PKCE Downgrade" family has been catalogued multiple times; we explicitly do not claim novelty for the underlying attack. Direct references this work builds on:

- **OAuch / DistriNet, KU Leuven** — [`Pkce.IsPkcePlainDowngradeDetected`](https://oauch.io/Tests/Info/Pkce.IsPkcePlainDowngradeDetected) and threat catalog entry [`BCP_4_8` — PKCE Downgrade Attack](https://oauch.io/Threats/Info/BCP_4_8). OAuch is the canonical academic OAuth conformance suite; the "PKCE plain downgrade" naming originates here. Source: [`IsPkcePlainDowngradeDetectedTest.cs`](https://github.com/DistriNet/OAuch/blob/main/src/OAuch/OAuch.Tests/Tests/Pkce/IsPkcePlainDowngradeDetectedTest.cs). OAuch's variant exercises the *token-request* surface (modify `code_verifier`); `MCP-PKCE-002` exercises the *authorize-request* surface (`code_challenge_method=plain` accepted), which OAuch's published catalog does not separately call out.
- **Authentik — [CVE-2024-23647](https://nvd.nist.gov/vuln/detail/CVE-2024-23647)** (Jan 2024). PKCE-strip downgrade: removing the `code_challenge` parameter caused PKCE to be skipped entirely. Same family, different sub-variant.
- **Better-Auth — [GHSA-9h47-pqcx-hjr4](https://github.com/better-auth/better-auth/security/advisories/GHSA-9h47-pqcx-hjr4)** (May 31, 2026 — 11 days before this writing). Direct hit: *"Discovery advertises code_challenge_methods_supported: ['S256'], contradicting the runtime acceptance of plain. A missing code_challenge_method parameter is silently downgraded to plain before the allowlist check."* This is the same advertise-vs-enforce shape `MCP-PKCE-002` detects, observed in a popular OSS OIDC provider, named, fixed, and disclosed. It establishes that the advertise-vs-enforce sub-variant occurs in the wild beyond MCP servers.
- **InstaTunnel** — ["PKCE Downgrade Attacks: Why OAuth 2.1 Is..."](https://instatunnel.substack.com/) (Jan 11, 2026). Popularises "PKCE downgrade" as a phrase for security-blog audiences.

What this page contributes that the prior work does not:

1. **A stable scanner check ID** (`MCP-PKCE-002`) suitable for CI suppression, PR-comment linking, and disclosure-email referencing.
2. **An unauthenticated heuristic** safe to run from a public scanner without registering a real client (the suppression rules below distinguish "AS rejected pre-PKCE" from "AS accepted plain").
3. **MCP-spec mapping** — explicit citation of MCP 2025-11-25 §authorization and the inheritance from OAuth 2.1.
4. **Prevalence numbers** for public MCP servers, published post-embargo (see [Prevalence](#prevalence) below).

If you have shipped a similar check in another MCP-OAuth scanner and would like to be cited here, [open an issue](https://github.com/authgent/authgent/issues).

## Why "advertise-drift" (sub-variant naming)

OAuch already names the parent family ("PKCE Downgrade Attack" / `BCP_4_8`). What this page calls out is a specific *sub-variant*: the discovery document's advertised method list and the `/authorize` endpoint's runtime enforcement have drifted apart. Useful to name separately because:

- It is detectable by a scanner that *only reads metadata + makes one unauthenticated GET*, which OAuch's deeper test path is not designed for.
- It generalises to other advertise-vs-enforce mismatches (`response_types_supported`, `grant_types_supported`, `dpop_signing_alg_values_supported`, `token_endpoint_auth_methods_supported`) — the same scanner pattern lifts to those checks.
- "Drift" describes the operational reality observed in the Better-Auth GHSA: the metadata document was authored once and rarely updated; the request validator was edited as the codebase evolved; the two surfaces drifted apart. That's a structural failure mode, not a one-off bug.

---

## References

- [RFC 7636 — Proof Key for Code Exchange](https://datatracker.ietf.org/doc/html/rfc7636)
- [draft-ietf-oauth-v2-1 §4.1.2.3](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1) — PKCE required in OAuth 2.1
- [RFC 8414 §2 — Authorization Server Metadata](https://datatracker.ietf.org/doc/html/rfc8414#section-2)
- [MCP 2025-11-25 authorization spec](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization)
- [Obsidian Security — When MCP Meets OAuth (Jan 2026)](https://www.obsidiansecurity.com/blog/when-mcp-meets-oauth-common-pitfalls-leading-to-one-click-account-takeover) — adjacent disclosure, different mechanism (DCR-mirror, not PKCE downgrade)
- [OAuch — PKCE Plain Downgrade test catalog](https://oauch.io/Threats/Info/BCP_4_8) — DistriNet, KU Leuven; the canonical academic OAuth conformance test for the PKCE-downgrade family
- [Authentik CVE-2024-23647](https://nvd.nist.gov/vuln/detail/CVE-2024-23647) — PKCE-strip downgrade
- [Better-Auth GHSA-9h47-pqcx-hjr4 (May 31, 2026)](https://github.com/better-auth/better-auth/security/advisories/GHSA-9h47-pqcx-hjr4) — exact advertise-vs-enforce shape in a popular OSS OIDC provider
- [CWE-757 — Selection of Less-Secure Algorithm During Negotiation](https://cwe.mitre.org/data/definitions/757.html)
- [CWE-358 — Improperly Implemented Security Check for a Standard](https://cwe.mitre.org/data/definitions/358.html)

## Citation

If you reference this scanner check in a paper, blog post, or issue:

> Agnihotri, D. (2026). *MCP-PKCE-002: a public-scanner heuristic for the PKCE advertise-vs-enforce sub-variant in MCP-OAuth.* authgent. https://github.com/authgent/authgent/blob/main/docs/attacks/pkce-drift.md
>
> Builds on prior PKCE-downgrade catalog work by DistriNet (OAuch) and the Better-Auth GHSA-9h47-pqcx-hjr4 advertise-vs-enforce disclosure (May 2026).

A CITATION.cff is in the repo root for machine-readable citation.

## Reporting

If you discover a server exhibiting PKCE-Drift:

1. Report to the operator via their published security contact (`/.well-known/security.txt` Contact, or the address in their PRM metadata).
2. Allow the standard 14-day responsible-disclosure window before publishing.
3. Coordinate with `security@authgent.dev` if you would like the finding included in this file's prevalence section.

We do not publish vendor-identifying findings inside the disclosure window. See [`docs/disclosure-policy.md`](../disclosure-policy.md).
