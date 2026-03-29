# CLAUDE.md — authgent project guide

This file provides essential context for AI assistants (Claude, Cursor, Windsurf, etc.)
working on the authgent codebase. Follow these rules to keep CI green.

## Project overview

**authgent** is an open-source OAuth 2.1 identity provider for AI agents.
Monorepo with three packages:

| Package | Path | Language | Runtime |
|---------|------|----------|---------|
| authgent-server | `server/` | Python 3.11+ | FastAPI + async SQLAlchemy |
| authgent (SDK) | `sdks/python/` | Python 3.11+ | httpx + PyJWT |
| authgent (SDK) | `sdks/typescript/` | TypeScript | jose + native fetch |

## CI pipeline (`.github/workflows/ci.yml`)

CI runs on every push/PR to `main`. **All four gates must pass before pushing.**

### Server (`server/` working directory)

```bash
# 1. Lint — zero errors required
ruff check .

# 2. Format — zero diffs required
ruff format --check .

# 3. Type check — zero errors required
mypy authgent_server/ --ignore-missing-imports

# 4. Tests — all must pass, ≥80% coverage
pytest tests/ --ignore=tests/simulation_test.py --ignore=tests/agent_to_agent_simulation.py -v --tb=short

# 5. Coverage (CI enforces minimum)
coverage run -m pytest tests/ --ignore=tests/simulation_test.py --ignore=tests/agent_to_agent_simulation.py -v
coverage report --fail-under=80
```

### Python SDK (`sdks/python/` working directory)

```bash
ruff check .
pytest tests/ -v --tb=short
```

### TypeScript SDK (`sdks/typescript/` working directory)

```bash
npm ci
npm run typecheck
npm run build
npm test
```

## Pre-push checklist

Run these from the `server/` directory before every commit:

```bash
# Quick all-in-one check (copy-paste this)
ruff check . && ruff format --check . && mypy authgent_server/ --ignore-missing-imports && pytest tests/ --ignore=tests/simulation_test.py --ignore=tests/agent_to_agent_simulation.py -v --tb=short
```

If `ruff format --check` fails, fix with:
```bash
ruff format .
```

If `ruff check` has auto-fixable errors:
```bash
ruff check --fix .
```

## Ruff configuration

Defined in `server/pyproject.toml`:

- **Line length**: 100 characters (NOT the default 88)
- **Target**: Python 3.11
- **Rules**: E, F, I, N, W, UP (pycodestyle, pyflakes, isort, pep8-naming, warnings, pyupgrade)
- **Ignored**: N818 (exception naming)
- **Per-file ignores**: E501 relaxed for `tests/simulation_test.py`, `tests/agent_to_agent_simulation.py`, `migrations/**`

### Common ruff errors and fixes

| Code | Meaning | Fix |
|------|---------|-----|
| E501 | Line too long (>100) | Break line manually — wrap function args, split f-strings |
| I001 | Unsorted imports | `ruff check --fix .` or `ruff format .` |
| F401 | Unused import | Remove the import or add `# noqa: F401` if intentional |
| F541 | f-string without placeholders | Remove the `f` prefix |
| F841 | Unused variable | Remove or prefix with `_` |
| UP037 | Quoted type annotation | Remove quotes; `ruff check --fix .` handles this |

## Mypy configuration

Defined in `server/pyproject.toml`:

- **Strict mode** enabled
- `disallow_any_generics = false`
- `warn_unused_ignores = false`
- Model files: `name-defined` errors disabled (SQLAlchemy mapped columns)
- Services/endpoints: `attr-defined` errors disabled

### Common mypy patterns

- `json.loads()` returns `Any` — assign to typed variable: `result: dict[str, Any] = json.loads(...)`
- All functions need type annotations (strict mode). Use `-> Any` for truly dynamic returns.
- Use `# type: ignore[arg-type]` sparingly and only when the type stub is wrong.

## Test conventions

- **28 test files** in `server/tests/`, auto-discovered by pytest via `tests/` directory.
- **2 excluded files**: `simulation_test.py`, `agent_to_agent_simulation.py` (manual simulation scripts, not unit tests).
- New test files named `test_*.py` are automatically included — no registration needed.
- Fixtures in `tests/conftest.py` provide `test_client`, `db_session`, `monkeypatch`, etc.
- Async tests use `pytest-asyncio` with `asyncio_mode = "auto"`.

## Code style

- **Imports**: Always at the top of the file. Use `from __future__ import annotations` in typed modules.
- **Line length**: 100 chars max. Break long function signatures by putting each arg on its own line.
- **Type annotations**: Required on all public functions (mypy strict).
- **Docstrings**: Use triple-quoted strings. One-line for simple, multi-line for complex.
- **Comments**: Do not add or remove existing comments unless asked.
- **f-strings**: Only use when there are actual placeholders.

### Line-breaking patterns

```python
# Function signatures
def my_function(
    arg1: str,
    arg2: int,
    arg3: bool = False,
) -> dict[str, Any]:

# Decorators with many args
@router.post(
    "/path",
    response_model=MyModel,
    status_code=201,
    dependencies=[Depends(my_dep)],
)

# Long f-strings — split into variables
scope_val = "enforced" if settings.flag else "disabled"
table.add_row("Label", scope_val)
```

## Architecture quick reference

```
server/
├── authgent_server/
│   ├── app.py              # FastAPI app, lifespan, cleanup tasks
│   ├── cli.py              # Typer CLI (authgent-server command)
│   ├── config.py           # Pydantic settings (AUTHGENT_* env vars)
│   ├── db.py               # Async SQLAlchemy engine + session factory
│   ├── dependencies.py     # FastAPI dependency injection
│   ├── endpoints/          # Route handlers (token, agents, introspect, etc.)
│   ├── models/             # SQLAlchemy ORM models (13 tables)
│   ├── providers/          # Pluggable protocol interfaces
│   ├── schemas/            # Pydantic request/response schemas
│   └── services/           # Business logic (token, JWKS, delegation, etc.)
├── tests/                  # 28 test files, ~338 tests
└── migrations/             # Alembic migrations
```

## Environment

- **Do NOT run `authgent-server init`** on an existing dev setup — it overwrites `.env`.
- The existing `server/.env` has `AUTHGENT_SECRET_KEY` and DB config. Use `authgent-server run` directly.
- Config prefix: `AUTHGENT_*` (e.g., `AUTHGENT_SECRET_KEY`, `AUTHGENT_ISSUER`).

## Dependencies

Install server dev dependencies:
```bash
cd server && pip install -e ".[dev]"
```

Install Python SDK dev dependencies:
```bash
cd sdks/python && pip install -e ".[dev]"
```

Install TypeScript SDK:
```bash
cd sdks/typescript && npm ci
```

## Common pitfalls

1. **Forgetting `ruff format`** — ruff check can pass but format can still fail. Always run both.
2. **Line length 100, not 88** — This project uses 100-char lines, not the ruff default of 88.
3. **`json.loads` and mypy** — Always assign to a typed variable to avoid `no-any-return`.
4. **New test files** — Just create `tests/test_*.py`; pytest auto-discovers them. No config changes needed.
5. **Simulation tests** — `simulation_test.py` and `agent_to_agent_simulation.py` are ignored in CI. Don't rename them to match `test_*.py` patterns expecting them to pass in CI.
6. **`from __future__ import annotations`** — Used in most modules. Don't remove it; it enables PEP 604 union syntax on Python 3.11.
