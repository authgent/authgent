"""Well-known discovery endpoints — OAuth Server Metadata, JWKS, OIDC, PRM."""

from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from authgent_server.config import Settings, get_settings
from authgent_server.dependencies import get_db_session, get_jwks_service
from authgent_server.models.oauth_client import OAuthClient
from authgent_server.services.jwks_service import JWKSService

router = APIRouter(tags=["discovery"])


async def _resolve_scopes(settings: Settings, db: AsyncSession) -> list[str]:
    """Return advertised scopes — from config if set, else aggregated from registered clients."""
    if settings.scopes_supported:
        return settings.scopes_supported
    result = await db.execute(select(OAuthClient.scope).where(OAuthClient.scope.isnot(None)))
    all_scopes: set[str] = set()
    for (scope_str,) in result:
        if scope_str:
            all_scopes.update(scope_str.split())
    return sorted(all_scopes)


@router.get("/.well-known/oauth-authorization-server")
async def oauth_server_metadata(
    settings: Settings = Depends(get_settings),
    db: AsyncSession = Depends(get_db_session),
) -> dict:
    """RFC 8414 — OAuth 2.0 Authorization Server Metadata. MCP auto-discovery."""
    base = settings.server_url.rstrip("/")
    scopes = await _resolve_scopes(settings, db)
    return {
        "issuer": base,
        "authorization_endpoint": f"{base}/authorize",
        "token_endpoint": f"{base}/token",
        "registration_endpoint": f"{base}/register",
        "revocation_endpoint": f"{base}/revoke",
        "introspection_endpoint": f"{base}/introspect",
        "jwks_uri": f"{base}/.well-known/jwks.json",
        "device_authorization_endpoint": f"{base}/device/authorize",
        "response_types_supported": ["code"],
        "grant_types_supported": [
            "authorization_code",
            "client_credentials",
            "refresh_token",
            "urn:ietf:params:oauth:grant-type:token-exchange",
            "urn:ietf:params:oauth:grant-type:device_code",
        ],
        "token_endpoint_auth_methods_supported": [
            "client_secret_post",
            "client_secret_basic",
            "none",
        ],
        "code_challenge_methods_supported": ["S256"],
        "scopes_supported": scopes,
        "resource_indicators_supported": True,
        "dpop_signing_alg_values_supported": ["ES256"],
        "service_documentation": "https://authgent.dev/docs",
    }


@router.get("/.well-known/openid-configuration")
async def openid_configuration(
    settings: Settings = Depends(get_settings),
    db: AsyncSession = Depends(get_db_session),
) -> dict:
    """OIDC Discovery alias — same metadata as RFC 8414 + OIDC fields."""
    base_meta = await oauth_server_metadata(settings, db)
    base = settings.server_url.rstrip("/")
    base_meta.update(
        {
            "userinfo_endpoint": f"{base}/userinfo",
            "id_token_signing_alg_values_supported": ["ES256"],
            "subject_types_supported": ["public"],
        }
    )
    return base_meta


@router.get("/.well-known/jwks.json")
async def jwks_document(
    db: AsyncSession = Depends(get_db_session),
    jwks: JWKSService = Depends(get_jwks_service),
) -> dict:
    """RFC 7517 — JSON Web Key Set. Public signing keys."""
    return await jwks.get_jwks_document(db)


@router.get("/.well-known/oauth-protected-resource")
async def protected_resource_metadata(
    settings: Settings = Depends(get_settings),
    db: AsyncSession = Depends(get_db_session),
) -> dict:
    """RFC 9728 — Protected Resource Metadata. MCP servers serve this."""
    base = settings.server_url.rstrip("/")
    scopes = await _resolve_scopes(settings, db)
    return {
        "resource": base,
        "authorization_servers": [base],
        "scopes_supported": scopes,
        "bearer_methods_supported": ["header"],
    }
