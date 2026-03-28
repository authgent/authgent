#!/usr/bin/env python3
"""authgent Showcase Demo — Cinematic terminal experience for recording.

Usage:
    1. Start server:  cd server && authgent-server run
    2. Run demo:      python demo_showcase.py

Requires: pip install rich httpx
"""

from __future__ import annotations

import base64
import json
import sys
import time

import httpx
from rich import box
from rich.align import Align
from rich.console import Console
from rich.panel import Panel
from rich.rule import Rule
from rich.syntax import Syntax
from rich.table import Table
from rich.text import Text
from rich.tree import Tree

console = Console(width=100)
BASE = "http://localhost:8000"


# ─── Helpers ────────────────────────────────────────────────────────────────

def typewrite(text: str, style: str = "", delay: float = 0.03):
    """Print text character by character for a natural typing feel."""
    for char in text:
        console.print(char, end="", style=style, highlight=False)
        time.sleep(delay)
    console.print()


def narrate(text: str, delay: float = 0.025):
    """Type out a narration line with dim style."""
    typewrite(text, style="dim", delay=delay)


def announce(text: str, delay: float = 0.02):
    """Type out a key announcement in bold."""
    typewrite(text, style="bold bright_white", delay=delay)


def pause(seconds: float = 2.0):
    time.sleep(seconds)


def enter():
    console.print()
    console.input("  [dim italic]▸ Press Enter to continue…[/]")


def decode_jwt(token: str) -> dict:
    payload = token.split(".")[1]
    payload += "=" * (4 - len(payload) % 4)
    return json.loads(base64.urlsafe_b64decode(payload))


def show_claims(title: str, token: str, border: str = "bright_cyan",
                callouts: dict[str, str] | None = None):
    """Show JWT claims as a pretty panel, with optional callout annotations."""
    claims = decode_jwt(token)
    # Only show the interesting claims
    keep = ["sub", "scope", "aud", "act"]
    filtered = {k: v for k, v in claims.items() if k in keep}
    code = json.dumps(filtered, indent=2)
    syn = Syntax(code, "json", theme="monokai", line_numbers=False, word_wrap=True)
    console.print(Panel(syn, title=f"[bold]{title}[/]", border_style=border, padding=(1, 2)))
    if callouts:
        for field, explanation in callouts.items():
            console.print(f"     [bright_cyan]↑ {field}[/]  —  {explanation}")
        console.print()


def scene_header(num: int, title: str):
    console.clear()
    console.print()
    console.print(Rule(style="bright_blue"))
    t = Text()
    t.append(f"  SCENE {num}  ", style="bold white on blue")
    t.append(f"  {title}", style="bold bright_white")
    console.print(t)
    console.print(Rule(style="bright_blue"))
    console.print()


# ═════════════════════════════════════════════════════════════════════════════
def main():
    console.clear()

    # ════════════════════════════════════════════════════════════════════════
    # INTRO
    # ════════════════════════════════════════════════════════════════════════
    console.print()
    console.print()
    console.print(Align.center(Text("🔐  authgent", style="bold bright_cyan")))
    console.print()
    pause(1.0)

    typewrite("  OAuth 2.1 authorization server for AI agents.", style="bright_white", delay=0.03)
    pause(0.5)
    typewrite("  Tracks who delegated what to whom — across every hop.", style="bright_white", delay=0.03)
    pause(1.5)
    console.print()

    narrate("  Let me show you a problem first.")
    pause(1.5)
    console.print()

    typewrite("  Your AI assistant delegates to a search agent.", delay=0.03)
    pause(0.8)
    typewrite("  The search agent delegates to a database agent.", delay=0.03)
    pause(0.8)
    typewrite("  The database agent deletes your production data.", style="bright_red", delay=0.04)
    pause(1.5)
    console.print()

    announce("  Who authorized that?")
    pause(2.0)
    console.print()

    narrate("  With normal bearer tokens: nobody knows.")
    narrate("  Tokens get copied. Scopes escalate. No audit trail.")
    pause(2.0)
    console.print()

    typewrite("  authgent fixes this. Let me show you — live.", style="bold bright_green", delay=0.03)
    pause(1.0)

    # Health check
    console.print()
    try:
        r = httpx.get(f"{BASE}/health", timeout=3)
        assert r.status_code == 200
        console.print(f"  [green bold]✓[/] Connected to live server at {BASE}")
    except Exception:
        console.print(f"\n  [red bold]✗[/] Cannot connect to server at {BASE}")
        console.print(f"  [dim]Start it with: cd server && authgent-server run[/]")
        sys.exit(1)

    enter()

    # ════════════════════════════════════════════════════════════════════════
    # SCENE 1: Register three agents
    # ════════════════════════════════════════════════════════════════════════
    scene_header(1, "Register Three Agents")

    narrate("  First, we create three agents with different permissions.")
    pause(1.0)
    console.print()

    agents: dict[str, dict] = {}
    cfgs = [
        ("Orchestrator", "search:execute db:read db:write", "Plans and delegates work"),
        ("Search Agent", "search:execute",                  "Can ONLY search — nothing else"),
        ("DB Agent",     "db:read db:write",                "Can ONLY access the database"),
    ]

    tbl = Table(box=box.ROUNDED, border_style="bright_green", show_lines=True)
    tbl.add_column("Agent", style="bold", width=18)
    tbl.add_column("Allowed Scopes", width=34)
    tbl.add_column("What It Can Do", style="dim", width=34)
    console.print(tbl)
    console.print()

    for name, scope, role in cfgs:
        key = name.lower().replace(" ", "-")
        with console.status(f"[bold cyan]  Registering {name}…[/]"):
            r = httpx.post(f"{BASE}/register", json={
                "client_name": key,
                "grant_types": ["client_credentials",
                                "urn:ietf:params:oauth:grant-type:token-exchange"],
                "scope": scope,
            })
            time.sleep(1.2)

        d = r.json()
        agents[key] = {"client_id": d["client_id"], "client_secret": d["client_secret"]}

        console.print(f"  [green bold]✓[/] {name}")
        narrate(f"    Scopes: {scope}")
        narrate(f"    Role:   {role}")
        console.print()
        pause(0.5)

    typewrite("  Three agents, each with different permissions.", style="bright_white", delay=0.03)
    narrate("  The key rule: agents can only delegate scopes they already have.")
    pause(1.0)

    enter()

    # ════════════════════════════════════════════════════════════════════════
    # SCENE 2: Happy path — Orchestrator gets a token
    # ════════════════════════════════════════════════════════════════════════
    scene_header(2, "Orchestrator Gets a Token")

    narrate("  The Orchestrator authenticates and gets its own token.")
    console.print()

    with console.status("[bold cyan]  Authenticating Orchestrator…[/]"):
        r = httpx.post(f"{BASE}/token", data={
            "grant_type": "client_credentials",
            "client_id": agents["orchestrator"]["client_id"],
            "client_secret": agents["orchestrator"]["client_secret"],
            "scope": "search:execute db:read",
        })
        time.sleep(1.5)

    orch_token = r.json()["access_token"]
    console.print(f"  [green bold]✓[/] Token issued\n")
    pause(0.5)

    show_claims("🎯 Orchestrator's Token", orch_token, border="bright_cyan", callouts={
        "sub": "This is the Orchestrator's identity",
        "scope": "It has search:execute AND db:read",
    })
    pause(1.5)

    narrate("  No 'act' claim — this is a first-party token.")
    narrate("  The Orchestrator got this token directly, not via delegation.")
    pause(1.5)

    enter()

    # ════════════════════════════════════════════════════════════════════════
    # SCENE 3: Happy path — Delegate to Search Agent
    # ════════════════════════════════════════════════════════════════════════
    scene_header(3, "Orchestrator Delegates to Search Agent")

    typewrite("  Now the Orchestrator needs the Search Agent to do some work.", style="bright_white", delay=0.03)
    pause(0.5)
    typewrite("  But it only gives it 'search:execute' — NOT 'db:read'.", style="bright_white", delay=0.03)
    pause(1.0)
    console.print()

    narrate("  This is called Token Exchange (RFC 8693).")
    narrate("  The Orchestrator trades its token for a narrower one.")
    console.print()
    pause(1.0)

    with console.status("[bold yellow]  Exchanging token…[/]"):
        r = httpx.post(f"{BASE}/token", data={
            "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
            "client_id": agents["orchestrator"]["client_id"],
            "client_secret": agents["orchestrator"]["client_secret"],
            "subject_token": orch_token,
            "audience": "agent:search-agent",
            "scope": "search:execute",
        })
        time.sleep(1.5)

    search_token = r.json()["access_token"]
    console.print(f"  [green bold]✓[/] Delegated token issued\n")
    pause(0.5)

    show_claims("🔍 Search Agent's Delegated Token", search_token,
                border="bright_magenta", callouts={
        "scope": "NARROWED — only 'search:execute' (db:read was removed)",
        "act":   "NEW — proves the Orchestrator delegated this token",
    })
    pause(2.0)

    console.print(Panel(
        "[bright_white]Two important things happened:[/]\n\n"
        "  [bold]1.[/] The scope shrank:  [dim]search:execute db:read[/]  →  "
        "[bold bright_magenta]search:execute[/]\n"
        "     [dim]The Search Agent cannot touch the database.[/]\n\n"
        "  [bold]2.[/] An [bold cyan]act[/] claim appeared.\n"
        "     [dim]This is cryptographic proof of who created this token.[/]\n"
        "     [dim]It can't be faked or removed.[/]",
        border_style="green", padding=(1, 2),
    ))
    pause(2.0)

    enter()

    # ════════════════════════════════════════════════════════════════════════
    # SCENE 4: Happy path — Delegate to DB Agent (multi-hop)
    # ════════════════════════════════════════════════════════════════════════
    scene_header(4, "Orchestrator Delegates to DB Agent")

    narrate("  The Orchestrator also needs the DB Agent to read some data.")
    narrate("  It delegates 'db:read' directly to the DB Agent.")
    console.print()
    pause(1.0)

    with console.status("[bold yellow]  Exchanging token…[/]"):
        r = httpx.post(f"{BASE}/token", data={
            "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
            "client_id": agents["orchestrator"]["client_id"],
            "client_secret": agents["orchestrator"]["client_secret"],
            "subject_token": orch_token,
            "audience": "agent:db-agent",
            "scope": "db:read",
        })
        time.sleep(1.5)

    db_token = r.json()["access_token"]
    console.print(f"  [green bold]✓[/] Delegated token issued\n")
    pause(0.5)

    show_claims("🗄️  DB Agent's Delegated Token", db_token,
                border="bright_yellow", callouts={
        "scope": "Only 'db:read' — db:write was NOT delegated",
        "act":   "Proves the Orchestrator delegated this",
    })
    pause(2.0)

    # Show the full delegation tree
    console.print()
    announce("  Here's the full picture:")
    console.print()
    pause(0.5)

    tree = Tree("[bold bright_white]🔐 authgent[/]  [dim](issuer)[/]")
    o_node = tree.add("[bold bright_cyan]🎯 Orchestrator[/]  —  scope: search:execute db:read")
    s_node = o_node.add("[bold bright_magenta]🔍 Search Agent[/]  —  scope: [green]search:execute[/]  [dim](narrowed)[/]")
    d_node = o_node.add("[bold bright_yellow]🗄️  DB Agent[/]  —  scope: [green]db:read[/]  [dim](narrowed)[/]")

    console.print(Panel(tree, title="[bold]Delegation Tree[/]",
                        border_style="bright_green", padding=(1, 2)))
    pause(2.0)

    narrate("  Each agent got exactly the permissions it needs — nothing more.")
    pause(1.5)

    enter()

    # ════════════════════════════════════════════════════════════════════════
    # SCENE 5: Security — Scope escalation blocked
    # ════════════════════════════════════════════════════════════════════════
    scene_header(5, "What Happens When an Agent Tries to Cheat?")

    typewrite("  The Search Agent only has 'search:execute'.", style="bright_white", delay=0.03)
    pause(0.5)
    typewrite("  But what if it tries to access the database anyway?", style="bright_white", delay=0.03)
    pause(1.0)
    console.print()

    narrate("  Let's try: Search Agent requests 'db:read' for the DB Agent.")
    console.print()
    pause(1.0)

    # Show what Search Agent has vs what it's requesting
    tbl = Table(box=box.ROUNDED, border_style="bright_red")
    tbl.add_column("", width=24, style="bold")
    tbl.add_column("Value", width=40)
    tbl.add_row("Search Agent has", "[magenta]search:execute[/]")
    tbl.add_row("Search Agent requests", "[bold red]db:read[/]")
    tbl.add_row("Is db:read ⊆ search:execute?", "[bold red]NO[/]")
    console.print(tbl)
    console.print()
    pause(1.5)

    with console.status("[bold red]  Attempting token exchange…[/]"):
        r = httpx.post(f"{BASE}/token", data={
            "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
            "client_id": agents["search-agent"]["client_id"],
            "client_secret": agents["search-agent"]["client_secret"],
            "subject_token": search_token,
            "audience": "agent:db-agent",
            "scope": "db:read",
        })
        time.sleep(2.0)

    err = r.json()

    console.print(Panel(
        f"[red bold]🛡️  BLOCKED[/]\n\n"
        f"  Error:  [bold]{err.get('error', '?')}[/]\n"
        f"  Reason: [dim]{err.get('error_description', '?')}[/]\n",
        border_style="red", padding=(1, 2),
    ))
    pause(2.0)

    announce("  Rule: An agent can never create permissions it doesn't have.")
    pause(1.0)
    narrate("  Scopes can only shrink at each delegation hop — never grow.")
    narrate("  This is enforced by the server, not by the agents themselves.")
    pause(2.0)

    enter()

    # ════════════════════════════════════════════════════════════════════════
    # SCENE 6: Token introspection — look inside a token
    # ════════════════════════════════════════════════════════════════════════
    scene_header(6, "Token Introspection — Who Holds What?")

    narrate("  At any time, you can ask the server: is this token valid?")
    narrate("  And if so: who does it belong to, what can they do?")
    console.print()
    pause(1.0)

    typewrite("  Let's introspect all three tokens:", style="bright_white", delay=0.03)
    console.print()
    pause(0.5)

    tbl = Table(box=box.ROUNDED, border_style="bright_cyan", show_lines=True,
                title="[bold cyan]Token Introspection (POST /introspect)[/]")
    tbl.add_column("Token Owner", width=18, style="bold")
    tbl.add_column("Active?", justify="center", width=10)
    tbl.add_column("Scope", width=22)
    tbl.add_column("Delegated By", width=30)

    for label, tok, color in [
        ("🎯 Orchestrator", orch_token, "cyan"),
        ("🔍 Search Agent", search_token, "magenta"),
        ("🗄️  DB Agent", db_token, "yellow"),
    ]:
        r = httpx.post(f"{BASE}/introspect", data={"token": tok})
        d = r.json()
        active = d.get("active", False)
        scope = d.get("scope", "—")
        act = d.get("act", {})
        delegator = act.get("sub", "— (first-party token)") if act else "— (first-party token)"
        tbl.add_row(
            f"[{color}]{label}[/]",
            "[green bold]✓ active[/]" if active else "[red]✗ dead[/]",
            scope,
            delegator[:28],
        )
        time.sleep(0.8)

    console.print(tbl)
    pause(2.0)
    console.print()

    narrate("  All three tokens are alive and valid.")
    narrate("  You can see exactly who delegated each one.")
    pause(1.5)

    enter()

    # ════════════════════════════════════════════════════════════════════════
    # SCENE 7: Revocation — kill a token
    # ════════════════════════════════════════════════════════════════════════
    scene_header(7, "Revocation — Kill a Token Instantly")

    typewrite("  Now imagine something went wrong.", style="bright_white", delay=0.03)
    pause(0.5)
    typewrite("  Maybe the Orchestrator was compromised.", style="bright_white", delay=0.03)
    pause(0.5)
    typewrite("  We need to kill its token immediately.", style="bright_red", delay=0.03)
    console.print()
    pause(1.5)

    narrate("  One API call to POST /revoke:")
    console.print()
    pause(0.5)

    with console.status("[bold red]  Revoking Orchestrator's token…[/]"):
        httpx.post(f"{BASE}/revoke", data={
            "token": orch_token,
            "client_id": agents["orchestrator"]["client_id"],
        })
        time.sleep(2.0)

    console.print(f"  [red bold]✗[/] Orchestrator's token has been revoked.")
    console.print()
    pause(1.5)

    typewrite("  Let's verify — introspect all tokens again:", style="bright_white", delay=0.03)
    console.print()
    pause(0.5)

    tbl = Table(box=box.ROUNDED, border_style="dim", show_lines=True,
                title="[bold]After Revocation[/]")
    tbl.add_column("Token Owner", width=18, style="bold")
    tbl.add_column("Before", justify="center", width=14)
    tbl.add_column("After", justify="center", width=14)
    tbl.add_column("Why", width=36)

    checks = [
        ("🎯 Orchestrator", orch_token, "cyan", "We just revoked it"),
        ("🔍 Search Agent", search_token, "magenta", "Independent token — still valid"),
        ("🗄️  DB Agent", db_token, "yellow", "Independent token — still valid"),
    ]

    for label, tok, color, reason in checks:
        r = httpx.post(f"{BASE}/introspect", data={"token": tok})
        active = r.json().get("active", False)
        tbl.add_row(
            f"[{color}]{label}[/]",
            "[green]✓ active[/]",
            "[green bold]✓ active[/]" if active else "[red bold]✗ REVOKED[/]",
            f"[dim]{reason}[/]",
        )
        time.sleep(1.0)

    console.print(tbl)
    console.print()
    pause(2.0)

    typewrite("  The Orchestrator's token is dead.", style="bright_white", delay=0.03)
    pause(0.5)
    typewrite("  It can never be used again — not for API calls, not for delegation.", style="bright_white", delay=0.03)
    pause(1.0)
    console.print()
    narrate("  The delegated tokens are still alive because they are separate JWTs.")
    narrate("  In production, you can cascade-revoke an entire delegation family.")
    pause(2.0)

    enter()

    # ════════════════════════════════════════════════════════════════════════
    # SCENE 8: Human-in-the-Loop
    # ════════════════════════════════════════════════════════════════════════
    scene_header(8, "Human-in-the-Loop — Agent Asks for Permission")

    typewrite("  Sometimes an agent hits a sensitive operation.", style="bright_white", delay=0.03)
    pause(0.5)
    typewrite("  Before proceeding, a human must approve.", style="bright_white", delay=0.03)
    console.print()
    pause(1.0)

    narrate("  The Search Agent found customer PII in its results.")
    narrate("  authgent requires human approval before it can access that data.")
    console.print()
    pause(1.0)

    # Agent submits step-up request
    typewrite("  Step 1: Agent submits a step-up request", style="bold bright_magenta", delay=0.03)
    console.print()

    r = httpx.post(f"{BASE}/stepup", json={
        "agent_id": f"agent:{agents['search-agent']['client_id']}",
        "action": "access_pii_data",
        "scope": "pii:read",
        "resource": "user_profiles",
        "metadata": {"reason": "Search results contain personal data"},
    })
    su = r.json()
    su_id = su["id"]

    tbl = Table(box=box.ROUNDED, border_style="bright_yellow")
    tbl.add_column("", style="dim", width=14)
    tbl.add_column("", width=50)
    tbl.add_row("Action", "[bold]access_pii_data[/]")
    tbl.add_row("Resource", "user_profiles")
    tbl.add_row("Reason", "[italic]Search results contain personal data[/]")
    tbl.add_row("Status", "[bold yellow]⏳ PENDING[/]")
    console.print(tbl)
    pause(2.0)
    console.print()

    # Agent polls
    typewrite("  Step 2: Agent polls, waiting for human decision…", style="bold bright_magenta", delay=0.03)
    console.print()

    for i in range(3):
        r = httpx.get(f"{BASE}/stepup/{su_id}")
        status = r.json()["status"]
        console.print(f"    [dim]Poll {i+1}:[/] status = [yellow]{status}[/]")
        time.sleep(1.0)

    console.print()
    pause(0.5)

    # Human approves
    typewrite("  Step 3: Alice reviews on her phone and approves ✅", style="bold bright_blue", delay=0.03)
    console.print()

    httpx.post(f"{BASE}/stepup/{su_id}/approve",
               json={"approved_by": "alice@company.com"})
    time.sleep(1.0)

    r = httpx.get(f"{BASE}/stepup/{su_id}")
    final = r.json()

    tbl = Table(box=box.ROUNDED, border_style="green",
                title="[bold green]Audit Record[/]")
    tbl.add_column("", style="dim", width=14)
    tbl.add_column("", width=50)
    tbl.add_row("Agent", "[magenta]🔍 search-agent[/]")
    tbl.add_row("Action", "[bold]access_pii_data[/]")
    tbl.add_row("Approved by", "[bold blue]alice@company.com[/]")
    tbl.add_row("Status", "[green bold]✓ APPROVED[/]")
    console.print(tbl)
    pause(2.0)
    console.print()

    narrate("  Six months from now, compliance asks:")
    narrate('  "Who accessed customer PII on this date?"')
    pause(1.0)
    typewrite("  authgent has the complete answer.", style="bright_white", delay=0.03)
    narrate("  Which agent, which action, who approved, when.")
    pause(2.0)

    enter()

    # ════════════════════════════════════════════════════════════════════════
    # FINALE
    # ════════════════════════════════════════════════════════════════════════
    console.clear()
    console.print()
    console.print(Rule("[bold bright_green]Demo Complete[/]", style="bright_green"))
    console.print()
    pause(1.0)

    typewrite("  Here's what you just saw:", style="bold bright_white", delay=0.03)
    console.print()
    pause(0.5)

    recap = Table(box=box.ROUNDED, border_style="bright_cyan", show_lines=True)
    recap.add_column("", justify="center", width=4)
    recap.add_column("What happened", width=50, style="bright_white")
    recap.add_column("", justify="center", width=14)
    recap.add_row("1", "Three agents registered with different scopes", "[green]✓[/]")
    recap.add_row("2", "Orchestrator got a token", "[green]✓[/]")
    recap.add_row("3", "Orchestrator delegated to Search Agent (scope narrowed)", "[green]✓[/]")
    recap.add_row("4", "Orchestrator delegated to DB Agent (scope narrowed)", "[green]✓[/]")
    recap.add_row("5", "Search Agent tried to escalate scope", "[red bold]BLOCKED[/]")
    recap.add_row("6", "All tokens introspected — full visibility", "[green]✓[/]")
    recap.add_row("7", "Orchestrator's token revoked and verified dead", "[green]✓[/]")
    recap.add_row("8", "Human-in-the-loop approval with audit trail", "[green]✓[/]")
    console.print(recap)
    console.print()
    pause(3.0)

    console.print(Panel(
        "[bold bright_white]pip install authgent-server\n"
        "authgent-server init && authgent-server run[/]\n\n"
        "[bold bright_blue]github.com/authgent/authgent[/]",
        title="[bold bright_cyan]🔐 authgent[/]",
        border_style="bright_cyan",
        padding=(1, 3),
    ))
    console.print()


if __name__ == "__main__":
    main()
