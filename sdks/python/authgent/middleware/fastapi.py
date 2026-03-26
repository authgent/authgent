"""FastAPI middleware — AgentAuthMiddleware + require_agent_auth + get_agent_identity."""

from __future__ import annotations

from functools import wraps
from typing import Any, Callable

from fastapi import Depends, HTTPException, Request

from authgent.errors import AuthgentError, InsufficientScopeError
from authgent.models import AgentIdentity
from authgent.verify import verify_token

_IDENTITY_KEY = "authgent_identity"


class AgentAuthMiddleware:
    """FastAPI middleware that verifies tokens on every request.

    Usage:
        app.add_middleware(AgentAuthMiddleware, issuer="http://localhost:8000")
    """

    def __init__(self, app: Any, issuer: str, audience: str | None = None):
        self.app = app
        self._issuer = issuer
        self._audience = audience

    async def __call__(self, scope: dict, receive: Callable, send: Callable) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        # Skip health/discovery endpoints
        path = scope.get("path", "")
        if path in ("/health", "/ready") or path.startswith("/.well-known"):
            await self.app(scope, receive, send)
            return

        # Extract token from Authorization header
        headers = dict(scope.get("headers", []))
        auth_header = b""
        for key, value in scope.get("headers", []):
            if key == b"authorization":
                auth_header = value
                break

        if not auth_header:
            await self.app(scope, receive, send)
            return

        auth_str = auth_header.decode()
        token = ""
        if auth_str.startswith("Bearer "):
            token = auth_str[7:]
        elif auth_str.startswith("DPoP "):
            token = auth_str[5:]

        if not token:
            await self.app(scope, receive, send)
            return

        try:
            identity = await verify_token(
                token=token,
                issuer=self._issuer,
                audience=self._audience,
            )
            # Store identity in ASGI scope state
            if "state" not in scope:
                scope["state"] = {}
            scope["state"][_IDENTITY_KEY] = identity
        except AuthgentError:
            # Let the request through — endpoint decorators handle enforcement
            pass

        await self.app(scope, receive, send)


def get_agent_identity(request: Request) -> AgentIdentity:
    """FastAPI dependency — extract verified AgentIdentity from request.

    Usage:
        @app.post("/tools/search")
        async def search(identity: AgentIdentity = Depends(get_agent_identity)):
            ...
    """
    identity = getattr(request.state, _IDENTITY_KEY, None)
    if identity is None:
        raise HTTPException(status_code=401, detail="No valid agent identity")
    return identity


def require_agent_auth(scopes: list[str] | None = None) -> Callable:
    """Decorator that enforces authentication and optional scope requirements.

    Usage:
        @app.post("/tools/search")
        @require_agent_auth(scopes=["search:execute"])
        async def search(identity=Depends(get_agent_identity)):
            ...
    """

    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def wrapper(*args: Any, **kwargs: Any) -> Any:
            # Find the request object in kwargs
            request = kwargs.get("request")
            if request is None:
                for arg in args:
                    if isinstance(arg, Request):
                        request = arg
                        break

            if request is None:
                raise HTTPException(status_code=500, detail="Request not available")

            identity = getattr(request.state, _IDENTITY_KEY, None)
            if identity is None:
                raise HTTPException(
                    status_code=401,
                    detail="Authentication required",
                    headers={"WWW-Authenticate": "Bearer"},
                )

            if scopes:
                missing = [s for s in scopes if s not in identity.scopes]
                if missing:
                    raise HTTPException(
                        status_code=403,
                        detail=f"Insufficient scope. Missing: {', '.join(missing)}",
                        headers={
                            "WWW-Authenticate": f'Bearer scope="{" ".join(scopes)}" error="insufficient_scope"'
                        },
                    )

            return await func(*args, **kwargs)

        return wrapper

    return decorator
