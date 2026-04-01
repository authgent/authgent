"""Flask middleware — AgentAuthMiddleware + require_agent_auth (sync wrappers)."""

from __future__ import annotations

import asyncio
from functools import wraps
from typing import Any, Callable

from authgent.errors import AuthgentError
from authgent.models import AgentIdentity
from authgent.verify import verify_token

_IDENTITY_KEY = "authgent_identity"


def _run_async(coro: Any) -> Any:
    """Run an async coroutine synchronously."""
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None

    if loop and loop.is_running():
        import concurrent.futures

        with concurrent.futures.ThreadPoolExecutor() as pool:
            return pool.submit(asyncio.run, coro).result()
    else:
        return asyncio.run(coro)


class AgentAuthMiddleware:
    """Flask middleware that verifies tokens on every request.

    Usage:
        AgentAuthMiddleware(app, issuer="http://localhost:8000")
    """

    _class_issuer: str | None = None

    def __init__(self, app: Any, issuer: str, audience: str | None = None):
        self._issuer = issuer
        self._audience = audience
        AgentAuthMiddleware._class_issuer = issuer
        app.before_request(self._before_request)

    def _before_request(self) -> None:
        from flask import g, request

        auth_header = request.headers.get("Authorization", "")
        token = ""
        if auth_header.startswith("Bearer "):
            token = auth_header[7:]
        elif auth_header.startswith("DPoP "):
            token = auth_header[5:]

        if not token:
            return

        try:
            identity = _run_async(
                verify_token(
                    token=token,
                    issuer=self._issuer,
                    audience=self._audience,
                )
            )
            g.authgent_identity = identity
        except AuthgentError:
            pass


def _www_authenticate_header(
    error: str = "invalid_token", scope: str | None = None
) -> str:
    """Build RFC 6750 §3 WWW-Authenticate value with discovery URIs."""
    base = (AgentAuthMiddleware._class_issuer or "").rstrip("/")
    parts = ['Bearer realm="authgent"']
    if base:
        parts.append(f'authorization_uri="{base}/token"')
        parts.append(f'resource_metadata="{base}/.well-known/oauth-protected-resource"')
    if scope:
        parts.append(f'scope="{scope}"')
    parts.append(f'error="{error}"')
    return ", ".join(parts)


def get_agent_identity() -> AgentIdentity:
    """Get the verified AgentIdentity from Flask's g context."""
    from flask import g

    identity = getattr(g, "authgent_identity", None)
    if identity is None:
        from flask import abort

        abort(401, description="No valid agent identity")
    return identity  # type: ignore[return-value]


def require_agent_auth(scopes: list[str] | None = None) -> Callable:
    """Decorator for Flask routes requiring agent authentication."""

    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            from flask import g

            identity = getattr(g, "authgent_identity", None)
            if identity is None:
                from flask import make_response

                resp = make_response({"error": "Authentication required"}, 401)
                resp.headers["WWW-Authenticate"] = _www_authenticate_header()
                return resp

            if scopes:
                missing = [s for s in scopes if s not in identity.scopes]
                if missing:
                    from flask import make_response

                    resp = make_response(
                        {"error": f"Insufficient scope. Missing: {', '.join(missing)}"}, 403
                    )
                    resp.headers["WWW-Authenticate"] = _www_authenticate_header(
                        error="insufficient_scope", scope=" ".join(scopes)
                    )
                    return resp

            return func(*args, **kwargs)

        return wrapper

    return decorator
