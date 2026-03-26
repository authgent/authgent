# Contributing to authgent

Thank you for your interest in contributing to authgent!

## Development Setup

```bash
# Clone
git clone https://github.com/authgent/authgent.git
cd authgent

# Server
cd server
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev,migrations]"

# Initialize
authgent-server init

# Run tests
pytest -v

# Lint
ruff check . && ruff format --check .
mypy authgent_server/

# Python SDK
cd ../sdks/python
pip install -e ".[dev,fastapi]"
pytest -v
```

## Code Style

- Python 3.11+, type hints everywhere
- `ruff` for linting and formatting (100 char line length)
- `mypy --strict` for type checking
- Follow existing patterns — Endpoints → Services → Models → DB

## Pull Request Process

1. Fork the repository
2. Create a feature branch: `git checkout -b feat/your-feature`
3. Write tests first (TDD encouraged)
4. Implement the feature
5. Run the full test suite
6. Submit a PR with a clear description

## Commit Messages

Use [Conventional Commits](https://www.conventionalcommits.org/):

```
feat: add device authorization grant
fix: correct PKCE challenge validation
docs: update SDK quickstart
test: add delegation chain depth tests
chore: bump cryptography to 43.0.1
```

## Architecture Rules

- **Endpoints** are thin — validation + delegation to services
- **Services** are stateless — receive `db: AsyncSession` per call
- **Providers** use Protocol interfaces — never import concrete implementations in services
- **Fail-closed** for security-critical providers (Policy, Attestation)
- **Fail-open** for audit/event providers
- Never log secrets — check the redaction list in `app.py`

## Security

- Read `SECURITY.md` before working on auth-related code
- All new endpoints need rate limiting consideration
- All new token operations need audit logging
- DPoP and delegation changes require extra review
