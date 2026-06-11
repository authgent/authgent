# authgent MCP-Lint — GitHub Action

Lint your MCP server's OAuth conformance on every PR. Composite action
that lives in the main authgent repo; reference it with the published
release tag.

## Usage

```yaml
name: MCP auth lint
on:
  pull_request:
    paths: ['mcp/**']

jobs:
  authgent-lint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Audit my MCP server
        uses: authgent/authgent/.github/actions/mcp-lint@v0.2.1
        with:
          url: https://staging.mcp.example.com
          fail-on: error    # info | warning | error | critical
```

The action installs `authgent-server` from PyPI, runs the same scanner
exposed as `authgent-server lint`, and emits findings as workflow-command
annotations so they appear inline in the PR's "Files changed" tab.

## What it checks

| Check | What it flags |
|---|---|
| `MCP-PRM-001` | Missing/malformed RFC 9728 protected-resource metadata |
| `MCP-AS-001`  | Missing RFC 8414 authorization-server metadata |
| `MCP-PKCE-001` | PKCE S256 not advertised, or `plain` advertised |
| `MCP-AUD-001`  | RFC 8707 resource indicators not supported |
| `MCP-ISS-001`  | RFC 9207 / SEP-2468 `iss` not advertised |
| `MCP-DCR-001`  | Dynamic Client Registration not advertised |
| `MCP-CSRF-001` | OAuth 2.1-forbidden implicit grant advertised |
| `MCP-REFRESH-001` | Refresh tokens issued without DPoP support |
| `MCP-PASSTHROUGH-001` | Root URL responds 200 unauthenticated |
| `MCP-DCR-MIRROR-001` | DCR returns identical client_id for distinct registrations (Obsidian/Jan 2026 disclosure) |

Each check links to the relevant RFC or disclosure in the annotation.
