#!/usr/bin/env python3
"""authgent CLI helper for OpenClaw skills.

A thin wrapper that OpenClaw agents call via bash/process tools to interact
with authgent-server. Each subcommand prints JSON to stdout.

Usage (from OpenClaw skill):
    python3 scripts/authgent_helper.py register --name "research-agent" --scopes "search db:read"
    python3 scripts/authgent_helper.py authenticate --client-id ID --client-secret SECRET --scope "search"
    python3 scripts/authgent_helper.py delegate --subject-token TOKEN --client-id ID --client-secret SECRET --audience "research-agent" --scope "search"
    python3 scripts/authgent_helper.py verify --token TOKEN
    python3 scripts/authgent_helper.py introspect --token TOKEN
    python3 scripts/authgent_helper.py revoke --token TOKEN --client-id ID --client-secret SECRET
    python3 scripts/authgent_helper.py audit --limit 20
    python3 scripts/authgent_helper.py stepup-request --agent-id ID --action "delete records" --scope "admin:delete"
    python3 scripts/authgent_helper.py stepup-check --request-id ID

Requires: pip install httpx  (or use the authgent SDK which includes it)
Server:   AUTHGENT_URL env var or defaults to http://localhost:8000
"""

import argparse
import json
import os
import sys

import httpx

SERVER = os.environ.get("AUTHGENT_URL", "http://localhost:8000")


def _post(path: str, *, data: dict | None = None, json_body: dict | None = None) -> dict:
    with httpx.Client(base_url=SERVER, timeout=15) as c:
        if json_body:
            r = c.post(path, json=json_body)
        else:
            r = c.post(path, data=data or {})
        try:
            return {"status": r.status_code, **r.json()}
        except Exception:
            return {"status": r.status_code, "raw": r.text}


def _get(path: str, params: dict | None = None) -> dict:
    with httpx.Client(base_url=SERVER, timeout=15) as c:
        r = c.get(path, params=params or {})
        try:
            return {"status": r.status_code, **r.json()}
        except Exception:
            return {"status": r.status_code, "raw": r.text}


def cmd_register(args: argparse.Namespace) -> None:
    """Register a new agent with authgent-server."""
    payload: dict = {
        "name": args.name,
        "allowed_scopes": args.scopes.split() if args.scopes else [],
    }
    if args.owner:
        payload["owner"] = args.owner
    result = _post("/agents", json_body=payload)
    print(json.dumps(result, indent=2))


def cmd_authenticate(args: argparse.Namespace) -> None:
    """Get an access token via client_credentials grant."""
    data = {
        "grant_type": "client_credentials",
        "client_id": args.client_id,
        "client_secret": args.client_secret,
    }
    if args.scope:
        data["scope"] = args.scope
    result = _post("/token", data=data)
    print(json.dumps(result, indent=2))


def cmd_delegate(args: argparse.Namespace) -> None:
    """Exchange a token for a scoped downstream token (RFC 8693)."""
    data = {
        "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
        "subject_token": args.subject_token,
        "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
        "client_id": args.client_id,
        "client_secret": args.client_secret,
        "audience": args.audience,
    }
    if args.scope:
        data["scope"] = args.scope
    result = _post("/token", data=data)
    print(json.dumps(result, indent=2))


def cmd_verify(args: argparse.Namespace) -> None:
    """Verify a token is active and return its claims."""
    result = _post("/introspect", data={"token": args.token})
    active = result.get("active", False)
    if not active:
        result["_verdict"] = "REJECTED — token is invalid, expired, or revoked"
    else:
        scopes = result.get("scope", "")
        if args.require_scope:
            required = set(args.require_scope.split())
            granted = set(scopes.split()) if scopes else set()
            missing = required - granted
            if missing:
                result["_verdict"] = f"REJECTED — missing scopes: {' '.join(sorted(missing))}"
            else:
                result["_verdict"] = "APPROVED — token valid, scopes sufficient"
        else:
            result["_verdict"] = "APPROVED — token valid"
    print(json.dumps(result, indent=2))


def cmd_introspect(args: argparse.Namespace) -> None:
    """Introspect a token (same as verify but without scope check)."""
    result = _post("/introspect", data={"token": args.token})
    print(json.dumps(result, indent=2))


def cmd_revoke(args: argparse.Namespace) -> None:
    """Revoke a token (kill switch)."""
    data = {
        "token": args.token,
        "client_id": args.client_id,
        "client_secret": args.client_secret,
    }
    result = _post("/revoke", data=data)
    result["_action"] = "Token revoked — no new requests or delegations possible. Existing child tokens expire per TTL."
    print(json.dumps(result, indent=2))


def cmd_audit(args: argparse.Namespace) -> None:
    """Query the audit trail."""
    params: dict = {"limit": str(args.limit)}
    if args.client_id:
        params["client_id"] = args.client_id
    result = _get("/audit", params=params)
    print(json.dumps(result, indent=2))


def cmd_stepup_request(args: argparse.Namespace) -> None:
    """Request human-in-the-loop approval for a dangerous action."""
    payload = {
        "agent_id": args.agent_id,
        "action": args.action,
        "scope": args.scope,
    }
    if args.resource:
        payload["resource"] = args.resource
    result = _post("/stepup", json_body=payload)
    print(json.dumps(result, indent=2))


def cmd_stepup_check(args: argparse.Namespace) -> None:
    """Check if a step-up request has been approved."""
    result = _get(f"/stepup/{args.request_id}")
    print(json.dumps(result, indent=2))


def cmd_inspect(args: argparse.Namespace) -> None:
    """Decode a JWT and show delegation chain (no verification)."""
    result = _get("/tokens/inspect", params={"token": args.token})
    print(json.dumps(result, indent=2))


def main() -> None:
    parser = argparse.ArgumentParser(description="authgent helper for OpenClaw skills")
    sub = parser.add_subparsers(dest="command", required=True)

    # register
    p = sub.add_parser("register", help="Register a new agent")
    p.add_argument("--name", required=True)
    p.add_argument("--scopes", default="")
    p.add_argument("--owner", default=None)

    # authenticate
    p = sub.add_parser("authenticate", help="Get access token")
    p.add_argument("--client-id", required=True)
    p.add_argument("--client-secret", required=True)
    p.add_argument("--scope", default=None)

    # delegate
    p = sub.add_parser("delegate", help="Token exchange (delegation)")
    p.add_argument("--subject-token", required=True)
    p.add_argument("--client-id", required=True)
    p.add_argument("--client-secret", required=True)
    p.add_argument("--audience", required=True)
    p.add_argument("--scope", default=None)

    # verify
    p = sub.add_parser("verify", help="Verify + scope-check a token")
    p.add_argument("--token", required=True)
    p.add_argument("--require-scope", default=None)

    # introspect
    p = sub.add_parser("introspect", help="Introspect a token")
    p.add_argument("--token", required=True)

    # revoke
    p = sub.add_parser("revoke", help="Revoke a token")
    p.add_argument("--token", required=True)
    p.add_argument("--client-id", required=True)
    p.add_argument("--client-secret", required=True)

    # audit
    p = sub.add_parser("audit", help="Query audit trail")
    p.add_argument("--limit", type=int, default=20)
    p.add_argument("--client-id", default=None)

    # stepup-request
    p = sub.add_parser("stepup-request", help="Request HITL approval")
    p.add_argument("--agent-id", required=True)
    p.add_argument("--action", required=True)
    p.add_argument("--scope", required=True)
    p.add_argument("--resource", default=None)

    # stepup-check
    p = sub.add_parser("stepup-check", help="Check step-up status")
    p.add_argument("--request-id", required=True)

    # inspect
    p = sub.add_parser("inspect", help="Decode JWT + delegation chain")
    p.add_argument("--token", required=True)

    args = parser.parse_args()
    commands = {
        "register": cmd_register,
        "authenticate": cmd_authenticate,
        "delegate": cmd_delegate,
        "verify": cmd_verify,
        "introspect": cmd_introspect,
        "revoke": cmd_revoke,
        "audit": cmd_audit,
        "stepup-request": cmd_stepup_request,
        "stepup-check": cmd_stepup_check,
        "inspect": cmd_inspect,
    }
    commands[args.command](args)


if __name__ == "__main__":
    main()
