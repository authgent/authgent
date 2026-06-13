# authgent MCP-OAuth Lint -- GitHub Action

Grade your MCP server's OAuth conformance on every PR. Composite action;
reference it from the main authgent repo at a release tag, or use the
mirrored standalone repo at `authgent/mcp-lint-action` once it is
published to GitHub Marketplace.

## Quick start

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
        uses: authgent/authgent/.github/actions/mcp-lint@v0.3.4
        with:
          url: https://staging.mcp.example.com
          fail-on: error    # info | warning | error | critical
```

The action installs `authgent-server` from PyPI, runs the same scanner
exposed as `authgent-server lint`, and emits findings as workflow-command
annotations so they appear inline in the PR's "Files changed" tab.

## Gate on regressions only

For a server that already has known findings you do not want to fix
right now, commit a baseline file and only fail CI when NEW findings
appear (the recommended mode):

```yaml
- uses: authgent/authgent/.github/actions/mcp-lint@v0.3.4
  with:
    url: https://staging.mcp.example.com
    baseline: .authgent/baseline.json
```

Seed the baseline file once with a manual workflow_dispatch run:

```yaml
- uses: authgent/authgent/.github/actions/mcp-lint@v0.3.4
  with:
    url: https://staging.mcp.example.com
    save-baseline: 'true'
    baseline: .authgent/baseline.json
```

Download the `authgent-lint-findings` artifact from that run, commit it
to the path above, and from then on every PR is gated on regressions.

## Pin a specific scanner version

```yaml
- uses: authgent/authgent/.github/actions/mcp-lint@v0.3.4
  with:
    url: https://staging.mcp.example.com
    scanner-version: 0.3.4
```

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
