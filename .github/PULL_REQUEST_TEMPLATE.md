<!-- Thank you for the PR. -->

## What this PR does


## Why


## How it was tested

- [ ] `ruff check .` -- zero errors
- [ ] `ruff format --check .` -- zero diffs
- [ ] `mypy authgent_server/ --ignore-missing-imports` -- zero errors
- [ ] `pytest tests/ ... -v` -- all pass, no warnings I introduced
- [ ] If touching scanner: added or updated a test that exercises the new behaviour
- [ ] If touching the OAuth server: confirmed `/.well-known/oauth-authorization-server` round-trip still works


## Spec / RFC references

(If applicable: which RFC section or MCP spec paragraph motivates this change?)


## Checklist

- [ ] I read the [Code of Conduct](../CODE_OF_CONDUCT.md).
- [ ] I read [CONTRIBUTING.md](../CONTRIBUTING.md).
- [ ] My commit messages follow Conventional Commits (`feat:`, `fix:`, `docs:`, etc).
