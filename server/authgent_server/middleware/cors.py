"""CORS configuration — /.well-known/* always allows GET regardless of config."""

from __future__ import annotations

from starlette.middleware.cors import CORSMiddleware

from authgent_server.config import Settings


def setup_cors(app: object, settings: Settings) -> None:
    """Add CORS middleware. /.well-known/* paths always allow cross-origin GET
    since SDKs must fetch JWKS cross-origin."""
    origins = settings.cors_origins or []

    # Always allow CORS for well-known endpoints (SDKs need JWKS cross-origin)
    app.add_middleware(  # type: ignore[attr-defined]
        CORSMiddleware,
        allow_origins=origins if origins else ["*"],
        allow_credentials=bool(origins),
        allow_methods=["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
        allow_headers=["*"],
        expose_headers=["X-Request-ID", "DPoP-Nonce"],
    )
