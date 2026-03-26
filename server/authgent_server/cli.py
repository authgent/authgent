"""Typer CLI — authgent-server init/run/create-agent."""

from __future__ import annotations

import asyncio
import os
import secrets

import typer

app = typer.Typer(
    name="authgent-server",
    help="authgent — The open-source identity provider for AI agents.",
    add_completion=False,
)


@app.command()
def init(
    database_url: str = typer.Option(
        "sqlite+aiosqlite:///./authgent.db",
        help="Database URL",
    ),
    force: bool = typer.Option(False, help="Overwrite existing .env"),
) -> None:
    """Initialize authgent-server — generates .env, creates DB, generates signing key."""
    env_path = ".env"
    if os.path.exists(env_path) and not force:
        typer.echo(f"  {env_path} already exists. Use --force to overwrite.")
        raise typer.Exit(1)

    secret_key = secrets.token_hex(32)

    with open(env_path, "w") as f:
        f.write(f"AUTHGENT_SECRET_KEY={secret_key}\n")
        f.write(f"AUTHGENT_DATABASE_URL={database_url}\n")
        f.write("AUTHGENT_HOST=0.0.0.0\n")
        f.write("AUTHGENT_PORT=8000\n")
        f.write("AUTHGENT_CONSENT_MODE=auto_approve\n")
        f.write("AUTHGENT_REGISTRATION_POLICY=open\n")

    typer.echo("  authgent-server initialized!")
    typer.echo(f"  Secret key generated in {env_path}")
    typer.echo(f"  Database: {database_url}")
    typer.echo("")

    # Create DB tables and initial signing key
    async def _init_db() -> None:
        os.environ["AUTHGENT_SECRET_KEY"] = secret_key
        os.environ["AUTHGENT_DATABASE_URL"] = database_url

        from authgent_server.config import get_settings, reset_settings
        reset_settings()
        settings = get_settings()

        from authgent_server.db import get_engine, get_session_factory
        from authgent_server.models.base import Base
        from authgent_server.services.jwks_service import JWKSService

        engine = get_engine(settings)
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

        session_factory = get_session_factory(settings)
        jwks = JWKSService(settings)
        async with session_factory() as session:
            key = await jwks.get_active_key(session)
            typer.echo(f"  Signing key generated: {key.kid}")

        await engine.dispose()

    asyncio.run(_init_db())

    typer.echo("")
    typer.echo("  Ready. Run: authgent-server run")


@app.command()
def run(
    host: str = typer.Option("0.0.0.0", help="Host to bind"),
    port: int = typer.Option(8000, help="Port to bind"),
    reload: bool = typer.Option(False, help="Enable auto-reload (dev)"),
) -> None:
    """Start the authgent server."""
    import uvicorn

    uvicorn.run(
        "authgent_server.app:create_app",
        factory=True,
        host=host,
        port=port,
        reload=reload,
    )


@app.command()
def create_agent(
    name: str = typer.Option(..., help="Agent name"),
    scopes: str = typer.Option("", help="Comma-separated scopes"),
    owner: str = typer.Option("", help="Agent owner"),
) -> None:
    """Create a new agent with OAuth credentials."""

    async def _create() -> None:
        from authgent_server.config import get_settings
        from authgent_server.db import get_engine, get_session_factory
        from authgent_server.schemas.agent import AgentCreate
        from authgent_server.services.agent_service import AgentService
        from authgent_server.services.client_service import ClientService

        settings = get_settings()
        engine = get_engine(settings)
        session_factory = get_session_factory(settings)

        scope_list = [s.strip() for s in scopes.split(",") if s.strip()] if scopes else []

        async with session_factory() as session:
            client_svc = ClientService(settings)
            agent_svc = AgentService(settings, client_svc)
            agent, client_id, client_secret = await agent_svc.create_agent(
                session,
                AgentCreate(
                    name=name,
                    owner=owner or None,
                    allowed_scopes=scope_list,
                ),
            )

            typer.echo(f"  Agent created!")
            typer.echo(f"  Agent ID:      {agent.id}")
            typer.echo(f"  Client ID:     {client_id}")
            typer.echo(f"  Client Secret: {client_secret}")
            typer.echo(f"  Scopes:        {', '.join(scope_list) if scope_list else '(none)'}")

        await engine.dispose()

    asyncio.run(_create())


@app.command()
def rotate_keys() -> None:
    """Rotate the signing key. Old key remains in JWKS for TTL."""

    async def _rotate() -> None:
        from authgent_server.config import get_settings
        from authgent_server.db import get_engine, get_session_factory
        from authgent_server.services.jwks_service import JWKSService

        settings = get_settings()
        engine = get_engine(settings)
        session_factory = get_session_factory(settings)

        jwks = JWKSService(settings)
        async with session_factory() as session:
            new_key = await jwks.rotate_key(session)
            typer.echo(f"  Key rotated. New kid: {new_key.kid}")

        await engine.dispose()

    asyncio.run(_rotate())


@app.command()
def create_user(
    username: str = typer.Option(..., help="Username"),
    password: str = typer.Option(..., prompt=True, hide_input=True, help="Password"),
    email: str = typer.Option("", help="Email address"),
) -> None:
    """Create a human user (for builtin auth mode)."""

    async def _create() -> None:
        import bcrypt
        from authgent_server.config import get_settings
        from authgent_server.db import get_engine, get_session_factory
        from authgent_server.models.user import User

        settings = get_settings()
        engine = get_engine(settings)
        session_factory = get_session_factory(settings)

        password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12)).decode()

        async with session_factory() as session:
            user = User(
                username=username,
                password_hash=password_hash,
                email=email or None,
            )
            session.add(user)
            await session.commit()
            typer.echo(f"  User created: {username} (id: {user.id})")

        await engine.dispose()

    asyncio.run(_create())


@app.command()
def openapi(
    output: str = typer.Option("openapi.json", help="Output file path"),
    fmt: str = typer.Option("json", help="Output format: json or yaml"),
) -> None:
    """Export the OpenAPI spec for SDK generation."""
    import json

    from authgent_server.app import create_app

    fastapi_app = create_app()
    spec = fastapi_app.openapi()

    if fmt == "yaml":
        try:
            import yaml
            content = yaml.dump(spec, default_flow_style=False, sort_keys=False)
        except ImportError:
            typer.echo("  PyYAML not installed. Install with: pip install pyyaml")
            raise typer.Exit(1)
    else:
        content = json.dumps(spec, indent=2)

    if output == "-":
        typer.echo(content)
    else:
        with open(output, "w") as f:
            f.write(content)
        typer.echo(f"  OpenAPI spec written to {output}")


@app.command()
def migrate(
    dry_run: bool = typer.Option(False, "--dry-run", help="Show SQL without executing"),
) -> None:
    """Run database migrations (alembic upgrade head)."""
    import subprocess
    import sys

    migrations_dir = os.path.join(os.path.dirname(__file__), "..", "migrations")
    alembic_ini = os.path.join(migrations_dir, "alembic.ini")

    if not os.path.exists(alembic_ini):
        typer.echo("  Error: alembic.ini not found. Run from the server root directory.")
        raise typer.Exit(1)

    cmd = ["alembic", "-c", alembic_ini]
    if dry_run:
        cmd += ["upgrade", "head", "--sql"]
        typer.echo("  Dry run — showing SQL that would be executed:")
    else:
        cmd += ["upgrade", "head"]

    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.stdout:
        typer.echo(result.stdout)
    if result.stderr:
        typer.echo(result.stderr)

    if result.returncode == 0:
        if not dry_run:
            typer.echo("  Migrations applied successfully.")
    else:
        typer.echo(f"  Migration failed (exit code {result.returncode})")
        raise typer.Exit(result.returncode)


if __name__ == "__main__":
    app()
