"""Typer CLI — authgent-server with rich output for all commands."""

from __future__ import annotations

import asyncio
import base64
import json
import os
import secrets
from datetime import UTC, datetime

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text  # noqa: F401
from rich.tree import Tree

console = Console()
err_console = Console(stderr=True)

app = typer.Typer(
    name="authgent-server",
    help="authgent — The open-source identity provider for AI agents.",
    add_completion=False,
    no_args_is_help=True,
)

__version__ = "0.1.0"


def _version_callback(value: bool) -> None:
    if value:
        from rich.console import Console

        Console().print(f"[bold cyan]authgent-server[/] {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: bool = typer.Option(
        False,
        "--version",
        "-V",
        help="Show version and exit.",
        callback=_version_callback,
        is_eager=True,
    ),
) -> None:
    """authgent — The open-source identity provider for AI agents."""


# ── Helpers ──────────────────────────────────────────────────────────────


def _run_async(coro):
    """Run an async coroutine from sync CLI code."""
    return asyncio.run(coro)


def _get_db_bits():
    """Lazy import and return (settings, engine, session_factory)."""
    from authgent_server.config import get_settings
    from authgent_server.db import get_engine, get_session_factory

    settings = get_settings()
    engine = get_engine(settings)
    session_factory = get_session_factory(settings)
    return settings, engine, session_factory


def _relative_time(dt: datetime) -> str:
    """Human-friendly relative time string."""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    now = datetime.now(UTC)
    diff = now - dt
    seconds = int(diff.total_seconds())
    if seconds < 0:
        return "just now"
    if seconds < 60:
        return f"{seconds}s ago"
    if seconds < 3600:
        return f"{seconds // 60}m ago"
    if seconds < 86400:
        return f"{seconds // 3600}h ago"
    days = seconds // 86400
    if days == 1:
        return "yesterday"
    if days < 30:
        return f"{days}d ago"
    return dt.strftime("%Y-%m-%d")


def _decode_jwt_claims(token: str) -> dict | None:
    """Decode JWT payload without verification (for inspection only)."""
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None
        payload = parts[1]
        # Add padding
        payload += "=" * (4 - len(payload) % 4)
        decoded = base64.urlsafe_b64decode(payload)
        return json.loads(decoded)
    except Exception:
        return None


def _build_delegation_tree(act: dict, tree: Tree | None = None, depth: int = 0) -> Tree:
    """Build a rich Tree from nested act claims."""
    sub = act.get("sub", "unknown")
    label = f"[bold cyan]{sub}[/]"
    if depth == 0 and tree is None:
        tree = Tree(f"[bold green]◉[/] {label} [dim](current actor)[/]")
    elif tree is not None:
        tree = tree.add(f"[bold yellow]↳[/] {label}")
    else:
        tree = Tree(label)

    nested = act.get("act")
    if nested and isinstance(nested, dict):
        _build_delegation_tree(nested, tree, depth + 1)

    return tree


# ── Init ─────────────────────────────────────────────────────────────────


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
        err_console.print(
            f"[bold red]✗[/] {env_path} already exists. Use [bold]--force[/] to overwrite."
        )
        raise typer.Exit(1)

    secret_key = secrets.token_hex(32)

    with open(env_path, "w") as f:
        f.write(f"AUTHGENT_SECRET_KEY={secret_key}\n")
        f.write(f"AUTHGENT_DATABASE_URL={database_url}\n")
        f.write("AUTHGENT_HOST=0.0.0.0\n")
        f.write("AUTHGENT_PORT=8000\n")
        f.write("AUTHGENT_CONSENT_MODE=auto_approve\n")
        f.write("AUTHGENT_REGISTRATION_POLICY=open\n")

    console.print("[bold green]✓[/] Config written to [bold].env[/]")
    console.print(f"  [dim]Database:[/] {database_url}")

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
            console.print(f"[bold green]✓[/] Signing key: [bold]{key.kid}[/]")

        await engine.dispose()

    _run_async(_init_db())

    console.print()
    console.print(
        Panel(
            "[bold]authgent-server run[/]",
            title="[bold green]Ready![/] Next step",
            border_style="green",
            expand=False,
        )
    )


# ── Run ──────────────────────────────────────────────────────────────────


@app.command()
def run(
    host: str = typer.Option("0.0.0.0", help="Host to bind"),
    port: int = typer.Option(8000, help="Port to bind"),
    reload: bool = typer.Option(False, help="Enable auto-reload (dev)"),
) -> None:
    """Start the authgent server."""
    import uvicorn

    console.print(
        Panel(
            f"[bold]http://{host}:{port}[/]\n"
            f"[dim]Docs:[/] http://{host}:{port}/docs\n"
            f"[dim]Health:[/] http://{host}:{port}/health",
            title="[bold cyan]authgent[/] server starting",
            border_style="cyan",
            expand=False,
        )
    )
    uvicorn.run(
        "authgent_server.app:create_app",
        factory=True,
        host=host,
        port=port,
        reload=reload,
    )


# ── Create Agent ─────────────────────────────────────────────────────────


@app.command()
def create_agent(
    name: str = typer.Option(..., help="Agent name"),
    scopes: str = typer.Option("", help="Comma-separated scopes"),
    owner: str = typer.Option("", help="Agent owner"),
) -> None:
    """Create a new agent with OAuth credentials."""

    async def _create() -> None:
        from authgent_server.schemas.agent import AgentCreate
        from authgent_server.services.agent_service import AgentService
        from authgent_server.services.client_service import ClientService

        settings, engine, session_factory = _get_db_bits()
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

            console.print(f"[bold green]✓[/] Agent [bold]{name}[/] created\n")

            table = Table(show_header=False, box=None, padding=(0, 2))
            table.add_column(style="dim")
            table.add_column(style="bold")
            table.add_row("Agent ID", agent.id)
            table.add_row("Client ID", client_id)
            table.add_row("Client Secret", client_secret)
            table.add_row("Scopes", ", ".join(scope_list) if scope_list else "[dim](none)[/]")
            console.print(table)

            console.print()
            console.print(
                Panel(
                    f"[bold]Save the client_secret now![/] It cannot be retrieved later.\n\n"
                    f"[dim]Get a token:[/]\n"
                    f"  authgent-server get-token --client-id {client_id} "
                    f"--client-secret {client_secret}"
                    + (f' --scope "{" ".join(scope_list)}"' if scope_list else ""),
                    title="[bold yellow]⚠ Important[/]",
                    border_style="yellow",
                    expand=False,
                )
            )

        await engine.dispose()

    _run_async(_create())


# ── List Agents ──────────────────────────────────────────────────────────


@app.command()
def list_agents(
    status: str = typer.Option("", help="Filter by status (active/inactive)"),
    owner: str = typer.Option("", help="Filter by owner"),
    limit: int = typer.Option(50, help="Max agents to show"),
) -> None:
    """List all registered agents in a table."""

    async def _list() -> None:
        from authgent_server.services.agent_service import AgentService
        from authgent_server.services.client_service import ClientService

        settings, engine, session_factory = _get_db_bits()

        async with session_factory() as session:
            client_svc = ClientService(settings)
            agent_svc = AgentService(settings, client_svc)
            agents, total = await agent_svc.list_agents(
                session,
                offset=0,
                limit=limit,
                status=status or None,
                owner=owner or None,
            )

            if not agents:
                console.print("[dim]No agents found.[/]")
                console.print("\n[dim]Create one:[/] authgent-server create-agent --name my-agent")
                return

            table = Table(title=f"Agents ({total} total)", title_style="bold")
            table.add_column("Name", style="bold cyan")
            table.add_column("Client ID", style="dim")
            table.add_column("Status")
            table.add_column("Scopes")
            table.add_column("Owner", style="dim")
            table.add_column("Created")

            for agent in agents:
                status_style = "green" if agent.status == "active" else "red"
                scopes_str = (
                    ", ".join(agent.allowed_scopes) if agent.allowed_scopes else "[dim]—[/]"
                )
                table.add_row(
                    agent.name,
                    agent.oauth_client_id or "[dim]—[/]",
                    f"[{status_style}]{agent.status}[/]",
                    scopes_str,
                    agent.owner or "[dim]—[/]",
                    _relative_time(agent.created_at),
                )

            console.print(table)

        await engine.dispose()

    _run_async(_list())


# ── Get Token ────────────────────────────────────────────────────────────


@app.command()
def get_token(
    client_id: str = typer.Option(..., help="Client ID"),
    client_secret: str = typer.Option(..., help="Client secret"),
    scope: str = typer.Option("", help="Space-separated scopes"),
    resource: str = typer.Option("", help="Target resource URI"),
    raw: bool = typer.Option(False, help="Output raw access_token only (for piping)"),
) -> None:
    """Request an access token using client_credentials grant."""

    async def _get() -> None:
        settings, engine, session_factory = _get_db_bits()

        from authgent_server.services.audit_service import AuditService
        from authgent_server.services.client_service import ClientService
        from authgent_server.services.delegation_service import DelegationService
        from authgent_server.services.external_oidc import ExternalIDTokenVerifier
        from authgent_server.services.jwks_service import JWKSService
        from authgent_server.services.token_service import TokenService

        client_svc = ClientService(settings)
        jwks = JWKSService(settings)
        delegation = DelegationService(settings)
        audit = AuditService()
        external_oidc = ExternalIDTokenVerifier(settings)
        token_svc = TokenService(
            settings=settings,
            jwks=jwks,
            delegation=delegation,
            audit=audit,
            external_oidc=external_oidc,
        )

        async with session_factory() as session:
            # Authenticate client first
            await client_svc.authenticate_client(session, client_id, client_secret)

            resp = await token_svc.issue_token(
                db=session,
                grant_type="client_credentials",
                client_id=client_id,
                scope=scope or None,
                resource=resource or None,
            )

            if raw:
                # Raw mode: just the token, for piping to other commands
                typer.echo(resp.access_token)
                return

            console.print("[bold green]✓[/] Token issued\n")

            # Decode and show claims
            claims = _decode_jwt_claims(resp.access_token)

            table = Table(show_header=False, box=None, padding=(0, 2))
            table.add_column(style="dim")
            table.add_column(style="bold")
            table.add_row("Token Type", resp.token_type)
            table.add_row("Expires In", f"{resp.expires_in}s")
            if claims:
                table.add_row("Subject", claims.get("sub", ""))
                table.add_row("Scope", claims.get("scope", "") or "[dim](none)[/]")
                table.add_row("Audience", str(claims.get("aud", "")))
                table.add_row("JTI", claims.get("jti", ""))
            console.print(table)

            console.print()
            # Show truncated token
            token = resp.access_token
            if len(token) > 60:
                display_token = token[:30] + "..." + token[-20:]
            else:
                display_token = token
            console.print(f"[dim]Token:[/] {display_token}")
            console.print()
            console.print("[dim]Full token:[/] authgent-server get-token ... --raw")
            console.print("[dim]Inspect:[/]   authgent-server inspect-token <token>")

        await engine.dispose()

    _run_async(_get())


# ── Exchange Token ────────────────────────────────────────────────────────


@app.command()
def exchange_token(
    subject_token: str = typer.Option(..., help="Parent access token to exchange"),
    audience: str = typer.Option(..., help="Target audience (downstream agent client_id)"),
    client_id: str = typer.Option(..., help="Requesting client ID"),
    client_secret: str = typer.Option(..., help="Requesting client secret"),
    scope: str = typer.Option("", help="Space-separated scopes (must be subset of parent)"),
    raw: bool = typer.Option(False, help="Output raw access_token only (for piping)"),
) -> None:
    """Exchange a token for a delegated downstream token (RFC 8693)."""

    async def _exchange() -> None:
        settings, engine, session_factory = _get_db_bits()

        from authgent_server.services.audit_service import AuditService
        from authgent_server.services.client_service import ClientService
        from authgent_server.services.delegation_service import DelegationService
        from authgent_server.services.external_oidc import ExternalIDTokenVerifier
        from authgent_server.services.jwks_service import JWKSService
        from authgent_server.services.token_service import TokenService

        client_svc = ClientService(settings)
        jwks = JWKSService(settings)
        delegation = DelegationService(settings)
        audit = AuditService()
        external_oidc = ExternalIDTokenVerifier(settings)
        token_svc = TokenService(
            settings=settings,
            jwks=jwks,
            delegation=delegation,
            audit=audit,
            external_oidc=external_oidc,
        )

        async with session_factory() as session:
            # Authenticate the requesting client
            oauth_client = await client_svc.authenticate_client(session, client_id, client_secret)

            resp = await token_svc.issue_token(
                db=session,
                grant_type="urn:ietf:params:oauth:grant-type:token-exchange",
                client_id=client_id,
                subject_token=subject_token,
                subject_token_type="urn:ietf:params:oauth:token-type:access_token",
                audience=audience,
                scope=scope or None,
                oauth_client=oauth_client,
            )

            if raw:
                typer.echo(resp.access_token)
                return

            console.print("[bold green]✓[/] Token exchanged (delegated)\n")

            claims = _decode_jwt_claims(resp.access_token)

            table = Table(show_header=False, box=None, padding=(0, 2))
            table.add_column(style="dim")
            table.add_column(style="bold")
            table.add_row("Token Type", resp.token_type)
            table.add_row("Expires In", f"{resp.expires_in}s")
            if claims:
                table.add_row("Subject", claims.get("sub", ""))
                table.add_row("Scope", claims.get("scope", "") or "[dim](none)[/]")
                table.add_row("Audience", str(claims.get("aud", "")))
                table.add_row("JTI", claims.get("jti", ""))
                act = claims.get("act")
                if act:
                    table.add_row("Actor (act.sub)", act.get("sub", ""))
            console.print(table)

            console.print()
            token = resp.access_token
            if len(token) > 60:
                display_token = token[:30] + "..." + token[-20:]
            else:
                display_token = token
            console.print(f"[dim]Token:[/] {display_token}")
            console.print()
            console.print("[dim]Full token:[/] authgent-server exchange-token ... --raw")
            console.print("[dim]Inspect:[/]   authgent-server inspect-token <token>")

        await engine.dispose()

    _run_async(_exchange())


# ── Inspect Token ────────────────────────────────────────────────────────


@app.command()
def inspect_token(
    token: str = typer.Argument(help="JWT access token to inspect"),
) -> None:
    """Decode and inspect a JWT — shows claims, delegation chain, expiry status."""
    claims = _decode_jwt_claims(token)
    if claims is None:
        err_console.print("[bold red]✗[/] Invalid JWT — could not decode payload")
        raise typer.Exit(1)

    # Header
    console.print(Panel("[bold]JWT Token Inspection[/]", border_style="cyan", expand=False))
    console.print()

    # Claims table
    table = Table(title="Claims", show_lines=True)
    table.add_column("Claim", style="bold cyan", min_width=12)
    table.add_column("Value")

    # Standard claims in a nice order
    ordered_keys = ["iss", "sub", "aud", "scope", "client_id", "jti", "iat", "exp"]
    shown = set()

    for key in ordered_keys:
        if key in claims:
            val = claims[key]
            if key in ("iat", "exp") and isinstance(val, (int, float)):
                dt = datetime.fromtimestamp(val, tz=UTC)
                time_str = dt.strftime("%Y-%m-%d %H:%M:%S UTC")
                if key == "exp":
                    now = datetime.now(UTC)
                    if dt < now:
                        time_str += " [bold red](EXPIRED)[/]"
                    else:
                        remaining = int((dt - now).total_seconds())
                        if remaining < 60:
                            time_str += f" [green]({remaining}s remaining)[/]"
                        elif remaining < 3600:
                            time_str += f" [green]({remaining // 60}m remaining)[/]"
                        else:
                            time_str += f" [green]({remaining // 3600}h remaining)[/]"
                table.add_row(key, time_str)
            else:
                table.add_row(key, str(val))
            shown.add(key)

    # Non-standard claims (skip act — handled separately)
    for key, val in claims.items():
        if key not in shown and key != "act":
            table.add_row(key, str(val))

    console.print(table)

    # DPoP binding
    cnf = claims.get("cnf")
    if cnf and isinstance(cnf, dict):
        jkt = cnf.get("jkt", "")
        console.print()
        console.print(f"[bold green]🔒 DPoP-bound[/] — jkt: [dim]{jkt}[/]")

    # Delegation chain
    act = claims.get("act")
    if act and isinstance(act, dict):
        console.print()
        console.print("[bold]Delegation Chain[/]")

        # Build tree: subject at top, then act chain
        root_label = f"[bold green]◉[/] [bold]{claims.get('sub', '?')}[/] [dim](token subject)[/]"
        root_tree = Tree(root_label)

        scope_str = claims.get("scope", "")
        root_tree.add(f"[dim]scope:[/] {scope_str or '(none)'}")

        _build_delegation_tree(act, root_tree)

        console.print(root_tree)

        # Count hops
        depth = 0
        a = act
        while a and isinstance(a, dict):
            depth += 1
            a = a.get("act")
        suffix = "s" if depth != 1 else ""
        console.print(f"\n[dim]Delegation depth:[/] [bold]{depth}[/] hop{suffix}")
    else:
        console.print("\n[dim]No delegation chain (direct token)[/]")

    # JSON dump
    console.print()
    console.print("[dim]Raw claims (JSON):[/]")
    console.print(json.dumps(claims, indent=2, default=str))


# ── Audit ────────────────────────────────────────────────────────────────


@app.command()
def audit(
    last: int = typer.Option(20, help="Number of recent events to show"),
    action: str = typer.Option("", help="Filter by action (e.g. token.issued)"),
    client_id: str = typer.Option("", help="Filter by client_id"),
    json_output: bool = typer.Option(False, "--json", help="Output as JSON"),
) -> None:
    """Show recent audit log events."""

    async def _audit() -> None:
        from sqlalchemy import func, select

        from authgent_server.models.audit_log import AuditLog

        settings, engine, session_factory = _get_db_bits()

        async with session_factory() as session:
            stmt = select(AuditLog)
            count_stmt = select(func.count()).select_from(AuditLog)

            if action:
                stmt = stmt.where(AuditLog.action == action)
                count_stmt = count_stmt.where(AuditLog.action == action)
            if client_id:
                stmt = stmt.where(AuditLog.client_id == client_id)
                count_stmt = count_stmt.where(AuditLog.client_id == client_id)

            stmt = stmt.order_by(AuditLog.timestamp.desc()).limit(last)

            result = await session.execute(stmt)
            logs = list(result.scalars().all())

            count_result = await session.execute(count_stmt)
            total = count_result.scalar() or 0

            if not logs:
                console.print("[dim]No audit events found.[/]")
                return

            if json_output:
                entries = []
                for log in logs:
                    entries.append(
                        {
                            "id": log.id,
                            "timestamp": log.timestamp.isoformat(),
                            "action": log.action,
                            "actor": log.actor,
                            "subject": log.subject,
                            "client_id": log.client_id,
                            "ip_address": log.ip_address,
                            "metadata": log.metadata_,
                        }
                    )
                typer.echo(json.dumps(entries, indent=2))
                return

            table = Table(
                title=f"Audit Log (showing {len(logs)} of {total})",
                title_style="bold",
            )
            table.add_column("Time", style="dim", min_width=10)
            table.add_column("Action", style="bold")
            table.add_column("Actor")
            table.add_column("Client")
            table.add_column("Details", style="dim")

            # Action color mapping
            action_colors = {
                "token.issued": "green",
                "token.exchanged": "cyan",
                "token.revoked": "red",
                "token.replay_detected": "bold red",
                "agent.created": "green",
                "agent.deactivated": "yellow",
                "stepup.approved": "green",
                "stepup.denied": "red",
                "key.rotated": "yellow",
            }

            for log in logs:
                color = action_colors.get(log.action, "white")
                action_display = f"[{color}]{log.action}[/]"

                # Extract useful info from metadata
                details = ""
                if log.metadata_:
                    meta = log.metadata_
                    if "jti" in meta:
                        details = f"jti={meta['jti'][:16]}…"
                    if "grant_type" in meta:
                        gt = meta["grant_type"]
                        details = f"{gt}" + (f" {details}" if details else "")
                    if "audience" in meta:
                        details += f" → {meta['audience']}"

                table.add_row(
                    _relative_time(log.timestamp),
                    action_display,
                    log.actor or "[dim]—[/]",
                    log.client_id or "[dim]—[/]",
                    details or "[dim]—[/]",
                )

            console.print(table)

        await engine.dispose()

    _run_async(_audit())


# ── Status ───────────────────────────────────────────────────────────────


@app.command()
def status() -> None:
    """Show server status — database, agents, keys, config summary."""

    async def _status() -> None:
        from sqlalchemy import func, select, text

        from authgent_server.models.agent import Agent
        from authgent_server.models.audit_log import AuditLog
        from authgent_server.models.signing_key import SigningKey

        settings, engine, session_factory = _get_db_bits()

        async with session_factory() as session:
            # DB check
            db_ok = True
            try:
                await session.execute(text("SELECT 1"))
            except Exception:
                db_ok = False

            # Counts
            agent_result = await session.execute(select(func.count()).select_from(Agent))
            agent_count = agent_result.scalar() or 0

            active_agents_result = await session.execute(
                select(func.count()).select_from(Agent).where(Agent.status == "active")
            )
            active_count = active_agents_result.scalar() or 0

            audit_result = await session.execute(select(func.count()).select_from(AuditLog))
            audit_count = audit_result.scalar() or 0

            # Active signing key
            key_result = await session.execute(
                select(SigningKey).where(SigningKey.status == "active").limit(1)
            )
            active_key = key_result.scalar_one_or_none()

            # Build output
            console.print(
                Panel(
                    "[bold cyan]authgent[/] server status",
                    border_style="cyan",
                    expand=False,
                )
            )
            console.print()

            # Server info
            info_table = Table(show_header=False, box=None, padding=(0, 2))
            info_table.add_column(style="dim", min_width=20)
            info_table.add_column(style="bold")

            info_table.add_row("Server URL", settings.server_url)
            info_table.add_row(
                "Database",
                settings.database_url.split("://")[0] + " [green]✓ connected[/]"
                if db_ok
                else settings.database_url.split("://")[0] + " [red]✗ unreachable[/]",
            )
            info_table.add_row(
                "Signing Key",
                f"{active_key.kid} ({active_key.algorithm})" if active_key else "[red]NONE[/]",
            )
            if active_key:
                info_table.add_row(
                    "Key Age", _relative_time(active_key.created_at).replace(" ago", "")
                )

            info_table.add_row("", "")  # spacer
            info_table.add_row("Agents", f"{active_count} active / {agent_count} total")
            info_table.add_row("Audit Events", str(audit_count))

            info_table.add_row("", "")  # spacer
            info_table.add_row("Registration", settings.registration_policy)
            info_table.add_row("Consent Mode", settings.consent_mode)
            info_table.add_row("Max Delegation Depth", str(settings.max_delegation_depth))
            scope_val = "enforced" if settings.delegation_scope_reduction else "disabled"
            info_table.add_row("Scope Reduction", scope_val)
            dpop_val = "[green]yes[/]" if settings.require_dpop else "[dim]no[/]"
            info_table.add_row("DPoP Required", dpop_val)
            info_table.add_row("Access Token TTL", f"{settings.access_token_ttl}s")
            info_table.add_row("Exchange Token TTL", f"{settings.exchange_token_ttl}s")
            info_table.add_row("Refresh Token TTL", f"{settings.refresh_token_ttl}s")

            console.print(info_table)

        await engine.dispose()

    _run_async(_status())


# ── Rotate Keys ──────────────────────────────────────────────────────────


@app.command()
def rotate_keys() -> None:
    """Rotate the signing key. Old key remains in JWKS for TTL."""

    async def _rotate() -> None:
        from authgent_server.services.jwks_service import JWKSService

        settings, engine, session_factory = _get_db_bits()

        jwks = JWKSService(settings)
        async with session_factory() as session:
            new_key = await jwks.rotate_key(session)
            console.print(f"[bold green]✓[/] Key rotated — new kid: [bold]{new_key.kid}[/]")

        await engine.dispose()

    _run_async(_rotate())


# ── Create User ──────────────────────────────────────────────────────────


@app.command()
def create_user(
    username: str = typer.Option(..., help="Username"),
    password: str = typer.Option(..., prompt=True, hide_input=True, help="Password"),
    email: str = typer.Option("", help="Email address"),
) -> None:
    """Create a human user (for builtin auth mode)."""

    async def _create() -> None:
        import bcrypt

        from authgent_server.models.user import User

        settings, engine, session_factory = _get_db_bits()

        password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12)).decode()

        async with session_factory() as session:
            user = User(
                username=username,
                password_hash=password_hash,
                email=email or None,
            )
            session.add(user)
            await session.commit()
            console.print(f"[bold green]✓[/] User [bold]{username}[/] created (id: {user.id})")

        await engine.dispose()

    _run_async(_create())


# ── OpenAPI ──────────────────────────────────────────────────────────────


@app.command()
def openapi(
    output: str = typer.Option("openapi.json", help="Output file path"),
    fmt: str = typer.Option("json", help="Output format: json or yaml"),
) -> None:
    """Export the OpenAPI spec for SDK generation."""

    from authgent_server.app import create_app

    fastapi_app = create_app()
    spec = fastapi_app.openapi()

    if fmt == "yaml":
        try:
            import yaml

            content = yaml.dump(spec, default_flow_style=False, sort_keys=False)
        except ImportError:
            err_console.print(
                "[bold red]✗[/] PyYAML not installed. Install with: pip install pyyaml"
            )
            raise typer.Exit(1)
    else:
        content = json.dumps(spec, indent=2)

    if output == "-":
        typer.echo(content)
    else:
        with open(output, "w") as f:
            f.write(content)
        console.print(f"[bold green]✓[/] OpenAPI spec written to [bold]{output}[/]")


# ── Migrate ──────────────────────────────────────────────────────────────


@app.command()
def migrate(
    dry_run: bool = typer.Option(False, "--dry-run", help="Show SQL without executing"),
) -> None:
    """Run database migrations (alembic upgrade head)."""
    import subprocess

    migrations_dir = os.path.join(os.path.dirname(__file__), "..", "migrations")
    alembic_ini = os.path.join(migrations_dir, "alembic.ini")

    if not os.path.exists(alembic_ini):
        err_console.print("[bold red]✗[/] alembic.ini not found. Run from the server root.")
        raise typer.Exit(1)

    cmd = ["alembic", "-c", alembic_ini]
    if dry_run:
        cmd += ["upgrade", "head", "--sql"]
        console.print("[dim]Dry run — showing SQL that would be executed:[/]")
    else:
        cmd += ["upgrade", "head"]

    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.stdout:
        typer.echo(result.stdout)
    if result.stderr:
        typer.echo(result.stderr)

    if result.returncode == 0:
        if not dry_run:
            console.print("[bold green]✓[/] Migrations applied successfully.")
    else:
        err_console.print(f"[bold red]✗[/] Migration failed (exit code {result.returncode})")
        raise typer.Exit(result.returncode)


# ── Quickstart ───────────────────────────────────────────────────────────


@app.command()
def quickstart() -> None:
    """Interactive guided setup — creates server, agent, and gets first token."""
    console.print(
        Panel(
            "[bold cyan]authgent[/] quickstart\n\n"
            "This will walk you through setting up your first agent\n"
            "and getting an access token in under 60 seconds.",
            border_style="cyan",
            expand=False,
        )
    )
    console.print()

    # Step 1: Check if .env exists
    env_exists = os.path.exists(".env")
    if env_exists:
        console.print("[bold green]✓[/] Server already initialized (.env exists)")
    else:
        console.print("[bold yellow]→[/] Initializing server...")
        init(database_url="sqlite+aiosqlite:///./authgent.db", force=False)

    console.print()

    # Step 2: Create a demo agent
    agent_name = typer.prompt(
        "Agent name",
        default="my-first-agent",
    )
    scopes_input = typer.prompt(
        "Scopes (comma-separated)",
        default="read,write",
    )

    console.print()
    console.print(f"[bold yellow]→[/] Creating agent [bold]{agent_name}[/]...")

    async def _quickstart_create() -> tuple[str, str]:
        from authgent_server.schemas.agent import AgentCreate
        from authgent_server.services.agent_service import AgentService
        from authgent_server.services.client_service import ClientService

        settings, engine, session_factory = _get_db_bits()
        scope_list = [s.strip() for s in scopes_input.split(",") if s.strip()]

        async with session_factory() as session:
            client_svc = ClientService(settings)
            agent_svc = AgentService(settings, client_svc)
            agent, cid, csec = await agent_svc.create_agent(
                session,
                AgentCreate(name=agent_name, allowed_scopes=scope_list),
            )
            console.print(f"[bold green]✓[/] Agent created — client_id: [bold]{cid}[/]")
            return cid, csec

    cid, csec = _run_async(_quickstart_create())

    console.print()
    console.print("[bold yellow]→[/] Getting access token...")

    async def _quickstart_token() -> str:
        from authgent_server.services.audit_service import AuditService
        from authgent_server.services.client_service import ClientService
        from authgent_server.services.delegation_service import DelegationService
        from authgent_server.services.external_oidc import ExternalIDTokenVerifier
        from authgent_server.services.jwks_service import JWKSService
        from authgent_server.services.token_service import TokenService

        settings, engine, session_factory = _get_db_bits()
        client_svc = ClientService(settings)
        jwks = JWKSService(settings)
        delegation = DelegationService(settings)
        audit = AuditService()
        external_oidc = ExternalIDTokenVerifier(settings)
        token_svc = TokenService(
            settings=settings,
            jwks=jwks,
            delegation=delegation,
            audit=audit,
            external_oidc=external_oidc,
        )

        async with session_factory() as session:
            await client_svc.authenticate_client(session, cid, csec)
            scope_list = [s.strip() for s in scopes_input.split(",") if s.strip()]
            resp = await token_svc.issue_token(
                db=session,
                grant_type="client_credentials",
                client_id=cid,
                scope=" ".join(scope_list),
            )
            return resp.access_token

    token = _run_async(_quickstart_token())
    claims = _decode_jwt_claims(token)

    console.print("[bold green]✓[/] Token issued!\n")

    if claims:
        table = Table(show_header=False, box=None, padding=(0, 2))
        table.add_column(style="dim")
        table.add_column(style="bold")
        table.add_row("Subject", claims.get("sub", ""))
        table.add_row("Scope", claims.get("scope", ""))
        table.add_row("JTI", claims.get("jti", ""))
        console.print(table)

    console.print()
    console.print(
        Panel(
            "[bold green]You're all set![/]\n\n"
            "[dim]Start server:[/]    authgent-server run\n"
            "[dim]List agents:[/]     authgent-server list-agents\n"
            "[dim]Inspect token:[/]   authgent-server inspect-token <token>\n"
            "[dim]View audit:[/]      authgent-server audit\n"
            "[dim]Server status:[/]   authgent-server status\n"
            "[dim]API docs:[/]        http://localhost:8000/docs",
            title="[bold]Next Steps[/]",
            border_style="green",
            expand=False,
        )
    )


if __name__ == "__main__":
    app()
