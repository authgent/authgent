# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

## Reporting a Vulnerability

If you discover a security vulnerability in authgent, please report it responsibly:

1. **DO NOT** create a public GitHub issue
2. Email: security@authgent.dev (or use GitHub's private vulnerability reporting)
3. Include:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact assessment
   - Suggested fix (if any)

We will acknowledge receipt within **48 hours** and provide a timeline for a fix within **5 business days**.

## Security Design

authgent implements defense-in-depth with 10 layers of token security:

1. **ES256 (ECDSA P-256)** — Asymmetric JWT signing
2. **DPoP (RFC 9449)** — Sender-constrained tokens with JWK thumbprint binding
3. **DPoP-Nonce** — Stateless HMAC-based nonces to prevent precomputed proofs
4. **Resource Indicators (RFC 8707)** — Audience restriction
5. **Scope reduction** — Downstream delegation cannot escalate scope
6. **may_act enforcement** — Explicit delegation authorization
7. **Delegation depth limit** — Configurable maximum chain depth
8. **Signed delegation receipts** — Chain splicing prevention
9. **Refresh token rotation** — Single-use with family-based reuse detection
10. **Token blocklist** — Explicit revocation with JTI tracking

### Secrets Management

- Master secret derived via **HKDF (RFC 5869)** into purpose-specific subkeys
- Client secrets hashed with **bcrypt (cost 12)**
- Signing keys encrypted at rest with **AES-256-GCM**
- Sensitive data never logged (enforced via structlog redaction)

### CSRF Protection

- Consent page protected with session-bound HMAC-signed CSRF tokens
- SameSite=Lax cookie policy

### Input Validation

- Pydantic schema validation on all endpoints
- Redirect URI validation (HTTPS required, no fragments, no query params)
- Scope character whitelist enforcement
- Rate limiting on token and registration endpoints
