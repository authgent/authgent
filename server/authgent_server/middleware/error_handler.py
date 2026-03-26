"""RFC 9457 Problem Details error handler middleware."""

from __future__ import annotations

import traceback

import structlog
from fastapi import Request
from fastapi.responses import JSONResponse

from authgent_server.errors import AuthgentError, UseDPoPNonce

logger = structlog.get_logger()

# OAuth endpoints that use RFC 6749 §5.2 error format
_OAUTH_ERROR_PATHS = {"/token", "/revoke", "/register"}


def _build_response_headers(exc: AuthgentError) -> dict[str, str]:
    """Build RFC-required response headers based on error type."""
    headers: dict[str, str] = {}

    # DPoP-Nonce header is REQUIRED when returning use_dpop_nonce error (RFC 9449 §8)
    if isinstance(exc, UseDPoPNonce):
        headers["DPoP-Nonce"] = exc.dpop_nonce

    # WWW-Authenticate header for 401 responses (RFC 6750 §3)
    if exc.status_code == 401:
        scheme = "DPoP" if isinstance(exc, UseDPoPNonce) else "Bearer"
        auth_value = f'{scheme} error="{exc.error_code}"'
        if exc.detail:
            auth_value += f', error_description="{exc.detail}"'
        headers["WWW-Authenticate"] = auth_value

    return headers


async def authgent_error_handler(request: Request, exc: AuthgentError) -> JSONResponse:
    """Convert AuthgentError to RFC 9457 Problem Details or OAuth error response."""
    headers = _build_response_headers(exc)

    # Use OAuth error format for token-related endpoints
    if request.url.path in _OAUTH_ERROR_PATHS:
        return JSONResponse(
            status_code=exc.status_code,
            content=exc.to_oauth_error(),
            headers=headers,
        )

    return JSONResponse(
        status_code=exc.status_code,
        content=exc.to_problem_detail(instance=request.url.path),
        headers={"Content-Type": "application/problem+json", **headers},
    )


async def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    """Catch-all for unhandled exceptions — never leak stack traces."""
    logger.error(
        "unhandled_exception",
        path=request.url.path,
        method=request.method,
        error_type=type(exc).__name__,
        error=str(exc),
        traceback=traceback.format_exc(),
    )
    return JSONResponse(
        status_code=500,
        content={
            "type": "https://authgent.dev/errors/server-error",
            "title": "Internal Server Error",
            "status": 500,
            "detail": "An unexpected error occurred",
            "instance": request.url.path,
        },
        headers={"Content-Type": "application/problem+json"},
    )
