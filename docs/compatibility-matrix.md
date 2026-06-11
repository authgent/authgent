# MCP Client Compatibility Matrix

What works between authgent and the major MCP clients as of **June 2026**.

This page is the source of truth for the table linked from the README.
If you find a discrepancy with a client version newer than the one
listed here, please open a PR.

## Legend

- ✅ — works end-to-end with default authgent configuration.
- ⚠️ — works with a documented caveat (footnote).
- ❌ — does not work today; tracking link in the footnote.

## Matrix

| Spec / feature | Claude Desktop (1.10) | Cursor (0.45) | Claude Code (latest) | Continue (0.10) | VS Code MCP (0.4) | ChatGPT (Custom MCP) |
|---|:-:|:-:|:-:|:-:|:-:|:-:|
| RFC 7636 PKCE (S256) | ✅[^stdio] | ✅ | ✅ | ✅ | ✅ | ✅ |
| RFC 7591 Dynamic Client Registration | ✅[^stdio] | ✅ | ✅ | ✅ | ✅ | ✅ |
| RFC 7591 software_id / software_version | ✅ | ✅ | ✅ | ⚠️[^cont-sw] | ✅ | ⚠️[^chatgpt-sw] |
| RFC 9728 Protected Resource Metadata | ✅[^stdio] | ✅ | ✅ | ✅ | ✅ | ✅ |
| RFC 9207 `iss` validation on `/authorize` redirect | ✅ | ✅ | ✅ | ⚠️[^cont-iss] | ✅ | ✅ |
| RFC 6750 §3.1 / SEP-2350 step-up `scope=` | ✅[^stdio] | ✅ | ✅ | ✅ | ⚠️[^vscode-stepup] | ⚠️[^chatgpt-stepup] |
| RFC 9449 DPoP token binding | ❌[^dpop-stdio] | ✅ | ✅ | ⚠️[^cont-dpop] | ✅ | ❌[^chatgpt-dpop] |
| Refresh-token rotation | ✅[^stdio] | ✅ | ✅ | ✅ | ✅ | ✅ |
| Token revocation propagation | ✅ | ⚠️[^cursor-revoke] | ✅ | ✅ | ⚠️[^vscode-revoke] | ✅ |
| Path-suffixed metadata (SEP-2351) | ✅ | ✅ | ✅ | ✅ | ✅ | ⚠️[^chatgpt-path] |
| RFC 8693 nested-`act` delegation chain | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |

[^stdio]: Stdio transport delegates auth to the MCP server's startup
    config (see `docs/mcp-quickstart.md` Claude Desktop section).
    authgent mints the token before the subprocess receives any RPC.
[^cont-sw]: Continue 0.10 does not surface `software_id` in DCR; the
    server still receives it from authgent's CLI helper.
[^cont-iss]: Continue 0.10 issuer-validation issue:
    [continuedev/continue#3812](https://github.com/continuedev/continue/issues/3812).
    authgent emits `iss=` regardless.
[^vscode-stepup]: VS Code MCP extension 0.4 surfaces 403 to the user
    instead of attempting a step-up. Manual reconnect required.
[^chatgpt-sw]: ChatGPT does not expose a software_statement field today.
[^chatgpt-stepup]: ChatGPT does not implement step-up; the user re-runs
    the conversation after granting wider scope.
[^dpop-stdio]: DPoP is HTTP-only by design; stdio transport uses Bearer.
[^cont-dpop]: Continue treats DPoP as opt-in via `useDpop: true`.
[^chatgpt-dpop]: ChatGPT Custom MCP only supports Bearer.
[^cursor-revoke]: Cursor caches access tokens for 60s after revocation.
    Sign out + reconnect to clear.
[^vscode-revoke]: Same caveat as Cursor; restart VS Code or wait the TTL.
[^chatgpt-path]: ChatGPT validates the resource URL path; does not yet
    follow the SEP-2351 path-suffix metadata pattern.

## How this is tested

Each cell is tested against the noted client version using the
end-to-end script in `tools/mcp-client-test/run.sh` (a small wrapper
that drives the live client; not committed because it depends on each
binary). The matrix is republished whenever a major MCP client version
ships.

If you maintain one of these clients and want to coordinate, please
file an issue. authgent's goal is to be the OSS server every MCP client
just-works against.
