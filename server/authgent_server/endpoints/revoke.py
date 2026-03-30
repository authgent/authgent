"""POST /revoke — Token Revocation (RFC 7009)."""

from __future__ import annotations

import base64

from fastapi import APIRouter, Depends, Request
from sqlalchemy.ext.asyncio import AsyncSession

from authgent_server.dependencies import (
    get_client_service,
    get_db_session,
    get_token_service,
)
from authgent_server.errors import InvalidClient, InvalidRequest
from authgent_server.services.client_service import ClientService
from authgent_server.services.token_service import TokenService

router = APIRouter(tags=["revocation"])


@router.post("/revoke", status_code=200)
async def revoke_token(
    request: Request,
    db: AsyncSession = Depends(get_db_session),
    token_service: TokenService = Depends(get_token_service),
    client_service: ClientService = Depends(get_client_service),
) -> dict:
    """Revoke an access or refresh token (RFC 7009).

    Requires client authentication (client_id + client_secret).
    Per RFC 7009, returns 200 even if the token is invalid or already revoked.
    """
    form = await request.form()
    token = form.get("token")
    client_id = str(form.get("client_id", ""))
    client_secret = str(form.get("client_secret", ""))

    # Support HTTP Basic auth
    if not client_id:
        auth = request.headers.get("authorization", "")
        if auth.startswith("Basic "):
            decoded = base64.b64decode(auth[6:]).decode()
            client_id, client_secret = decoded.split(":", 1)

    if not token:
        raise InvalidRequest("token parameter is required")

    if not client_id or not client_secret:
        raise InvalidClient("Client authentication required for revocation")

    # Authenticate the requesting client
    client = await client_service.authenticate_client(db, client_id, client_secret)
    if not client:
        raise InvalidClient("Invalid client credentials")

    await token_service.revoke_token(db, str(token), client_id)
    return {}
