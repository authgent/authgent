"""POST /token — OAuth 2.1 Token Endpoint (all grant types)."""

from __future__ import annotations

import base64

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse
from sqlalchemy.ext.asyncio import AsyncSession

from authgent_server.config import Settings, get_settings
from authgent_server.dependencies import (
    get_client_service,
    get_db_session,
    get_dpop_service,
    get_token_service,
)
from authgent_server.errors import AuthgentError, InvalidClient, InvalidRequest
from authgent_server.schemas.token import TokenResponse
from authgent_server.services.client_service import ClientService
from authgent_server.services.dpop_service import DPoPService
from authgent_server.services.token_service import TokenService

router = APIRouter(tags=["token"])


@router.post("/token")
async def token_endpoint(
    request: Request,
    db: AsyncSession = Depends(get_db_session),
    token_service: TokenService = Depends(get_token_service),
    client_service: ClientService = Depends(get_client_service),
    dpop_service: DPoPService = Depends(get_dpop_service),
    settings: Settings = Depends(get_settings),
) -> TokenResponse:
    """OAuth 2.1 Token Endpoint — handles all grant types.

    Enforces Content-Type: application/x-www-form-urlencoded per OAuth 2.1 spec.
    """
    content_type = request.headers.get("content-type", "")
    if "application/x-www-form-urlencoded" not in content_type:
        raise InvalidRequest(
            "Content-Type must be application/x-www-form-urlencoded"
        )

    form = await request.form()
    grant_type = form.get("grant_type")
    if not grant_type:
        raise InvalidRequest("grant_type is required")

    client_id = str(form.get("client_id", ""))
    client_secret = str(form.get("client_secret", ""))

    # Client authentication
    if not client_id:
        # Try HTTP Basic auth
        auth = request.headers.get("authorization", "")
        if auth.startswith("Basic "):
            decoded = base64.b64decode(auth[6:]).decode()
            client_id, client_secret = decoded.split(":", 1)

    if not client_id:
        raise InvalidClient("client_id is required")

    # Authenticate client (skip for public clients using PKCE)
    client = None
    if client_secret:
        client = await client_service.authenticate_client(db, client_id, client_secret)
    else:
        client = await client_service.get_client(db, client_id)
        if not client:
            raise InvalidClient(f"Client not found: {client_id}")

    # Validate grant type is allowed for this client
    if client.grant_types and str(grant_type) not in client.grant_types:
        raise InvalidRequest(
            f"Grant type '{grant_type}' not allowed for this client"
        )

    # Validate resource (RFC 8707)
    resource = form.get("resource")
    await client_service.validate_resource(client, str(resource) if resource else None)

    # Validate scopes
    scope = form.get("scope")
    effective_scope = await client_service.validate_scopes(
        client, str(scope) if scope else None
    )

    # Handle DPoP proof if present
    dpop_jkt = None
    dpop_proof = request.headers.get("dpop")
    if dpop_proof:
        dpop_result = dpop_service.verify_dpop_proof(
            proof_jwt=dpop_proof,
            access_token=None,
            http_method="POST",
            http_uri=str(request.url).split("?")[0],
            require_nonce=settings.require_dpop,
        )
        dpop_jkt = dpop_result.get("jkt")

    # Check DPoP requirement
    if settings.require_dpop and not dpop_jkt:
        raise InvalidRequest("DPoP proof required")

    ip_address = request.client.host if request.client else None

    return await token_service.issue_token(
        db=db,
        grant_type=str(grant_type),
        client_id=client_id,
        scope=effective_scope,
        resource=str(resource) if resource else None,
        subject=str(form.get("subject", "")),
        code=str(form.get("code", "")),
        code_verifier=str(form.get("code_verifier", "")),
        redirect_uri=str(form.get("redirect_uri", "")),
        refresh_token_value=str(form.get("refresh_token", "")),
        subject_token=str(form.get("subject_token", "")),
        audience=str(form.get("audience", "")),
        device_code=str(form.get("device_code", "")),
        dpop_jkt=dpop_jkt,
        ip_address=ip_address,
    )
