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

    def __init__(self, app: Any, issuer: str, audience: str | None = None):
        self._issuer = issuer
        self._audience = audience
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
            from flask import abort, g

            identity = getattr(g, "authgent_identity", None)
            if identity is None:
                abort(401, description="Authentication required")

            if scopes:
                missing = [s for s in scopes if s not in identity.scopes]
                if missing:
                    abort(403, description=f"Insufficient scope. Missing: {', '.join(missing)}")

            return func(*args, **kwargs)

        return wrapper

    return decorator
