# CI integration for MCP server pull requests

Use the authgent MCP-OAuth lint action to grade an MCP server on every
pull request. The action runs `authgent-server lint`, annotates findings
in GitHub's pull request UI, and can fail the workflow when findings meet
or exceed the selected severity.

## Copy-paste workflow

Create `.github/workflows/mcp-auth-lint.yml` in the MCP server repository:

```yaml
name: MCP auth lint

on:
  pull_request:
    paths:
      - "mcp/**"
      - ".github/workflows/mcp-auth-lint.yml"

jobs:
  authgent-lint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Audit MCP OAuth posture
        uses: authgent/authgent/.github/actions/mcp-lint@v0.3.4
        with:
          url: https://staging.mcp.example.com
          fail-on: error
```

Set `url` to the base URL of the MCP server environment that should be
audited. Use `fail-on` to decide which finding severity blocks a pull
request: `info`, `warning`, `error`, or `critical`.

## Gate on regressions only

For a server that already has known findings, commit a baseline and gate
future pull requests only on new findings:

```yaml
name: MCP auth lint

on:
  pull_request:
    paths:
      - "mcp/**"
      - ".authgent/baseline.json"
      - ".github/workflows/mcp-auth-lint.yml"

jobs:
  authgent-lint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Audit MCP OAuth posture
        uses: authgent/authgent/.github/actions/mcp-lint@v0.3.4
        with:
          url: https://staging.mcp.example.com
          baseline: .authgent/baseline.json
          fail-on: error
```

When `baseline` is set, the action runs in `--diff` mode. Existing
findings from the baseline do not block the pull request; new findings at
or above `fail-on` do.

## Seed the baseline

Run the action once manually to capture the current findings:

```yaml
name: Seed MCP auth baseline

on:
  workflow_dispatch:

jobs:
  seed-authgent-baseline:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Capture current MCP OAuth findings
        uses: authgent/authgent/.github/actions/mcp-lint@v0.3.4
        with:
          url: https://staging.mcp.example.com
          save-baseline: "true"
          baseline: .authgent/baseline.json
```

Download the `authgent-lint-findings` artifact from that manual run,
commit it as `.authgent/baseline.json`, and keep the pull request workflow
above in place for regression gating.

## Pin scanner behavior

The action installs `authgent-server` from PyPI. To keep CI behavior stable
while reviewing scanner updates, pin a scanner version:

```yaml
- uses: authgent/authgent/.github/actions/mcp-lint@v0.3.4
  with:
    url: https://staging.mcp.example.com
    scanner-version: 0.3.4
```

## Related reference

- [MCP-OAuth lint GitHub Action](../.github/actions/mcp-lint/README.md)
- [Scanner methodology](methodology.md)
