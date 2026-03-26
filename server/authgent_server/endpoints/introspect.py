"""POST /introspect — Token Introspection (RFC 7662)."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from sqlalchemy.ext.asyncio import AsyncSession

from authgent_server.dependencies import get_db_session, get_token_service
from authgent_server.errors import InvalidRequest
from authgent_server.schemas.token import TokenIntrospectionResponse
from authgent_server.services.token_service import TokenService

router = APIRouter(tags=["introspection"])


@router.post("/introspect", response_model=TokenIntrospectionResponse)
async def introspect_token(
    request: Request,
    db: AsyncSession = Depends(get_db_session),
    token_service: TokenService = Depends(get_token_service),
) -> TokenIntrospectionResponse:
    """Introspect a token to determine its state and claims (RFC 7662).

    Returns active=false for expired, revoked, or malformed tokens.
    """
    form = await request.form()
    token = form.get("token")

    if not token:
        raise InvalidRequest("token parameter is required")

    try:
        claims = await token_service.verify_and_check_blocklist(db, str(token))
    except Exception:
        return TokenIntrospectionResponse(active=False)

    return TokenIntrospectionResponse(
        active=True,
        scope=claims.get("scope"),
        client_id=claims.get("client_id"),
        token_type="Bearer" if "cnf" not in claims else "DPoP",
        exp=claims.get("exp"),
        iat=claims.get("iat"),
        sub=claims.get("sub"),
        aud=claims.get("aud") if isinstance(claims.get("aud"), str) else None,
        iss=claims.get("iss"),
        jti=claims.get("jti"),
        act=claims.get("act"),
    )
