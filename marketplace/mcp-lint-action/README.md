# MCP-OAuth Lint Action

Grade an MCP server's OAuth posture against the relevant RFCs on every
pull request. Free, open source, runs in any GitHub Actions workflow.

[![GitHub Marketplace](https://img.shields.io/badge/Marketplace-mcp--lint-blue?logo=github)](https://github.com/marketplace/actions/authgent-mcp-oauth-lint)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)

## What it does

Audits a deployed MCP server's authorization metadata against:

- RFC 7591 (Dynamic Client Registration)
- RFC 7636 (PKCE; S256 enforcement)
- RFC 8414 (Authorization Server Metadata)
- RFC 8707 (Resource Indicators)
- RFC 9207 (`iss` parameter on `/authorize` redirect)
- RFC 9449 (DPoP)
- RFC 9728 (Protected Resource Metadata)
- MCP authorization spec (2025-11-25 / 2026-07-28)

Annotates findings inline as `::error` / `::warning` lines so they
appear in the "Files changed" tab of pull requests. Outputs an
`authgent-lint-findings` JSON artifact for archival.

The action is a thin wrapper around the open-source
[`authgent-server`](https://pypi.org/project/authgent-server/) CLI
([source](https://github.com/authgent/authgent)). The wrapper pins
versions, surfaces findings as PR annotations, and supports
regression-only gating via baseline files.

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
      - uses: authgent/mcp-lint-action@v1
        with:
          url: https://staging.mcp.example.com
          fail-on: error
```

That is the full integration. On the next PR, any normative-spec
violation appears as an inline annotation and fails the check.

## Gate on regressions only

Most MCP servers in production have at least one finding that the
operator is choosing not to fix yet. Use baseline mode to gate CI on
new findings only:

```yaml
- uses: authgent/mcp-lint-action@v1
  with:
    url: https://staging.mcp.example.com
    baseline: .authgent/baseline.json
```

Seed the baseline once with a manual run:

```yaml
on:
  workflow_dispatch:
    inputs: {}

jobs:
  seed-baseline:
    runs-on: ubuntu-latest
    steps:
      - uses: authgent/mcp-lint-action@v1
        with:
          url: https://staging.mcp.example.com
          save-baseline: 'true'
          baseline: .authgent/baseline.json
```

Download the `authgent-lint-findings` artifact, commit the JSON to the
path above, and every subsequent PR is gated on regressions.

## Inputs

| Name | Required | Default | Description |
|---|---|---|---|
| `url` | Yes | -- | MCP server base URL to audit. |
| `fail-on` | No | `error` | Minimum severity that fails the run: `info` / `warning` / `error` / `critical`. |
| `baseline` | No | `""` | Path to a baseline JSON file. When set, the action runs in regression-gate mode. |
| `save-baseline` | No | `false` | When `true`, write the current findings to `baseline` (or `authgent-baseline.json`). |
| `python-version` | No | `3.12` | Python version to install. |
| `scanner-version` | No | `latest` | Pin a specific `authgent-server` version. |

## Outputs

The `authgent-lint-findings` artifact is uploaded on every run with the
full findings JSON. The `authgent-baseline` artifact is uploaded when
`save-baseline: 'true'`.

## Security

The action passes user-controlled inputs through environment variables
and never interpolates them into shell command bodies. Defends against
[GitHub Actions workflow injection](https://github.blog/security/vulnerability-research/how-to-catch-github-actions-workflow-injections-before-attackers-do/).

## Project links

- Scanner source: <https://github.com/authgent/authgent>
- IETF Internet-Draft: <https://datatracker.ietf.org/doc/draft-agnihotri-oauth-agent-impl-status/>
- Methodology: <https://github.com/authgent/authgent/blob/main/docs/methodology.md>
- Disclosure policy: <https://github.com/authgent/authgent/blob/main/docs/disclosure-policy.md>

## License

Apache 2.0.
