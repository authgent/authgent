"""Device Authorization Grant endpoints (RFC 8628).

Allows input-constrained agents to authenticate by having a human
approve the request on a separate device.
"""

from __future__ import annotations

import secrets
from datetime import timedelta

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from authgent_server.config import Settings, get_settings
from authgent_server.dependencies import (
    get_client_service,
    get_db_session,
    get_token_service,
)
from authgent_server.errors import InvalidGrant, InvalidRequest
from authgent_server.models.device_code import DeviceCode
from authgent_server.services.client_service import ClientService
from authgent_server.services.token_service import TokenService
from authgent_server.utils import is_expired, utcnow

router = APIRouter(tags=["device"])

DEVICE_CODE_TTL = 600  # 10 minutes
POLLING_INTERVAL = 5  # seconds


class DeviceAuthResponse(BaseModel):
    device_code: str
    user_code: str
    verification_uri: str
    verification_uri_complete: str
    expires_in: int
    interval: int


def _generate_user_code() -> str:
    """Generate a short, human-readable user code (8 chars, uppercase + digits)."""
    alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"  # no I/O/0/1 for clarity
    return "".join(secrets.choice(alphabet) for _ in range(8))


@router.post("/device/authorize", response_model=DeviceAuthResponse)
async def device_authorization(
    request: Request,
    db: AsyncSession = Depends(get_db_session),
    client_service: ClientService = Depends(get_client_service),
    settings: Settings = Depends(get_settings),
) -> DeviceAuthResponse:
    """RFC 8628 §3.1 — Device Authorization Request.

    Agent requests a device code; human approves on a separate device.
    """
    form = await request.form()
    client_id = str(form.get("client_id", ""))
    scope = str(form.get("scope", ""))

    if not client_id:
        raise InvalidRequest("client_id is required")

    client = await client_service.get_client(db, client_id)
    if not client:
        raise InvalidRequest(f"Client not found: {client_id}")

    device_code_value = secrets.token_urlsafe(32)
    user_code = _generate_user_code()

    record = DeviceCode(
        device_code=device_code_value,
        user_code=user_code,
        client_id=client_id,
        scope=scope,
        expires_at=utcnow() + timedelta(seconds=DEVICE_CODE_TTL),
    )
    db.add(record)
    await db.commit()

    verification_uri = f"{settings.server_url}/device"
    return DeviceAuthResponse(
        device_code=device_code_value,
        user_code=user_code,
        verification_uri=verification_uri,
        verification_uri_complete=f"{verification_uri}?user_code={user_code}",
        expires_in=DEVICE_CODE_TTL,
        interval=POLLING_INTERVAL,
    )


@router.post("/device/token")
async def device_token_poll(
    request: Request,
    db: AsyncSession = Depends(get_db_session),
    token_service: TokenService = Depends(get_token_service),
    settings: Settings = Depends(get_settings),
) -> Response:
    """RFC 8628 §3.4 — Device Access Token Request (polling endpoint).

    Agent polls this until the human approves or the code expires.
    """
    form = await request.form()
    device_code_value = str(form.get("device_code", ""))
    client_id = str(form.get("client_id", ""))

    if not device_code_value or not client_id:
        raise InvalidRequest("device_code and client_id are required")

    stmt = select(DeviceCode).where(
        DeviceCode.device_code == device_code_value,
        DeviceCode.client_id == client_id,
    )
    result = await db.execute(stmt)
    record = result.scalar_one_or_none()

    if not record:
        raise InvalidGrant("Unknown device code")

    if is_expired(record.expires_at):
        raise InvalidGrant("Device code expired")

    if record.status == "approved":
        # Atomic CAS: mark as consumed
        cas = (
            update(DeviceCode)
            .where(
                DeviceCode.device_code == device_code_value,
                DeviceCode.status == "approved",
            )
            .values(status="consumed")
        )
        cas_result = await db.execute(cas)
        if cas_result.rowcount == 0:
            raise InvalidGrant("Device code already consumed")
        await db.commit()

        # Issue token via client_credentials-like flow
        token_resp = await token_service.issue_token(
            db=db,
            grant_type="client_credentials",
            client_id=client_id,
            scope=record.scope,
            subject=record.subject,
        )
        return JSONResponse(content=token_resp.model_dump(exclude_none=True))

    if record.status == "denied":
        raise InvalidGrant("Device authorization request was denied")

    # Still pending — return authorization_pending
    return JSONResponse(
        status_code=400,
        content={
            "error": "authorization_pending",
            "error_description": "The user has not yet approved the request",
        },
    )


class DeviceApproveRequest(BaseModel):
    user_code: str
    subject: str
    action: str = "approve"  # approve | deny


@router.post("/device/complete")
async def device_complete(
    body: DeviceApproveRequest,
    db: AsyncSession = Depends(get_db_session),
) -> dict:
    """Human approval endpoint — approve or deny a device authorization request.

    In production, this would be behind human authentication.
    """
    stmt = select(DeviceCode).where(
        DeviceCode.user_code == body.user_code,
        DeviceCode.status == "pending",
    )
    result = await db.execute(stmt)
    record = result.scalar_one_or_none()

    if not record:
        raise InvalidRequest("Invalid or already-used user code")

    if is_expired(record.expires_at):
        record.status = "expired"
        await db.commit()
        raise InvalidGrant("Device code expired")

    if body.action == "deny":
        record.status = "denied"
        await db.commit()
        return {"status": "denied"}

    record.status = "approved"
    record.subject = body.subject
    await db.commit()
    return {"status": "approved"}
