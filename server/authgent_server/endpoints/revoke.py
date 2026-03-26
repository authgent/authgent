"""POST /revoke — Token Revocation (RFC 7009)."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from sqlalchemy.ext.asyncio import AsyncSession

from authgent_server.dependencies import get_db_session, get_token_service
from authgent_server.errors import InvalidRequest
from authgent_server.services.token_service import TokenService

router = APIRouter(tags=["revocation"])


@router.post("/revoke", status_code=200)
async def revoke_token(
    request: Request,
    db: AsyncSession = Depends(get_db_session),
    token_service: TokenService = Depends(get_token_service),
) -> dict:
    """Revoke an access or refresh token (RFC 7009).

    Per RFC 7009, this endpoint always returns 200 even if the token is invalid.
    """
    form = await request.form()
    token = form.get("token")
    client_id = str(form.get("client_id", ""))

    if not token:
        raise InvalidRequest("token parameter is required")

    await token_service.revoke_token(db, str(token), client_id)
    return {}
