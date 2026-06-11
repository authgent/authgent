# authgent vs Keycloak

Keycloak (Red Hat, 34.8k★) is the canonical OSS OAuth/OIDC server.
authgent and Keycloak occupy related but distinct lanes.

## TL;DR

- Pick **Keycloak** if you have a heterogeneous workforce/SSO problem
  and you've been running it for years. It's the right tool for human
  SSO + SAML + a federation realm.
- Pick **authgent** if you need agent-native semantics — multi-hop
  delegation, RFC 8693 nested-`act`, identity-chaining, transaction
  tokens, signed delegation receipts, and an MCP-OAuth lint — without
  filing 4-year-old issues against Keycloak's RFC 8707 support.
- They can co-exist: one tenant in Keycloak, agent layer in authgent
  bridged via id_token exchange.

## Side-by-side

| Capability | Keycloak (26.x) | authgent |
|---|:-:|:-:|
| OAuth 2.1 (PKCE, refresh rotation, DCR) | ✅ | ✅ |
| OIDC + SAML + LDAP federation | ✅ | OIDC only |
| Realm / multi-tenancy admin UI | ✅ | minimal |
| RFC 9728 Protected Resource Metadata | ⚠️ partial | ✅ |
| RFC 8707 Resource Indicators | tracked since 2022 ([#14355](https://github.com/keycloak/keycloak/issues/14355)) | ✅ |
| RFC 9207 `iss` parameter (MCP SEP-2468) | ✅ | ✅ |
| RFC 9449 DPoP | ✅ | ✅ |
| `draft-ietf-oauth-identity-chaining` | tracked ([#41521](https://github.com/keycloak/keycloak/issues/41521)) | ✅ shipped |
| `draft-ietf-oauth-transaction-tokens` | not tracked | ✅ shipped |
| Multi-hop nested-`act` agent delegation | not built-in | ✅ |
| Signed delegation receipts | not built-in | ✅ |
| MCP-server protection out-of-box | manual config | example + scanner |
| MCP-OAuth scanner | none | ✅ `authgent-server lint` |
| Self-host runtime | Java 17 + Quarkus | Python 3.11 + FastAPI |
| Memory footprint (cold) | ~700 MB | ~80 MB |
| First-run time | minutes (Java + DB + admin user setup) | seconds (`pip install authgent-server && authgent-server run`) |
| License | Apache 2.0 | Apache 2.0 |
| Stars | ~34.8k | starting fresh |

(Sources: keycloak.org docs, the linked GitHub issues, authgent's
STANDARDS.md.)

## Where Keycloak wins

- **Human SSO at enterprise scale.** SAML, LDAP, brokering, realms,
  social login, MFA flows. Decade of production hardening.
- **Compliance + ecosystem.** SOC 2, FedRAMP-style hardening guides,
  Red Hat-supported builds, large vendor consultancy market.
- **Customizable workflows.** Keycloak's authentication SPI lets you
  script complex login flows that authgent cannot match today.

## Where authgent wins

- **Agent-native primitives.** Multi-hop nested-`act` chains,
  delegation receipts, identity-chaining, transaction tokens — all
  in the box. Keycloak treats agents as just-another-OAuth-client.
- **MCP support.** authgent ships an `mcp` SDK example, a five-client
  compatibility matrix, and an MCP-OAuth lint scanner. Keycloak
  has community guides but no first-party MCP story.
- **Path-suffixed metadata (MCP SEP-2351).** authgent serves
  `/.well-known/oauth-authorization-server/<tenant>` natively; Keycloak
  realms use a different URL shape that some MCP clients don't
  follow.
- **Footprint and start-up.** A `pip install` + a single CLI command
  beats a Quarkus boot when you're prototyping.
- **Tightly scoped.** authgent is ~7 kLOC of focused agent-OAuth code;
  reading the source to understand a behavior is realistic.

## Compose them

Treat Keycloak as the human IdP, authgent as the agent layer.

```
[Human] → Keycloak realm "corp"
   │  (logs in, gets Keycloak id_token)
   ▼
[Agent] → POST /token to authgent
   subject_token=<keycloak id_token>
   subject_token_type=urn:ietf:params:oauth:token-type:id_token
   ▼
authgent issues an access_token whose `sub` is `user:<keycloak-sub>` and
whose `act` chain is rooted in that human. From here, authgent owns
delegation, receipts, scope reduction, DPoP, and MCP server protection.
```

Configure the trusted issuer:

```bash
export AUTHGENT_TRUSTED_OIDC_ISSUERS='["https://kc.example.com/realms/corp"]'
```

## Migration checklist

If you're considering **adding** authgent next to Keycloak:

1. Stand authgent up on a separate hostname (e.g.
   `agents.example.com`).
2. Configure `AUTHGENT_TRUSTED_OIDC_ISSUERS` to include your Keycloak
   realm.
3. Migrate agent-only OAuth clients out of Keycloak realms into
   authgent's RFC 7591 DCR endpoint. Human SSO stays in Keycloak.
4. Add `authgent-server lint` to your MCP-server CI.
