"""POST /security/tokens/compromise — operator/detector-triggered compromise flagging.

Distinct from POST /revoke (RFC 7009, client self-revocation). See
TokenService.flag_compromised for why these are two separate paths rather
than one action with a flag.

Auth model: this is NOT gated by registration_policy (which only controls
who may register a new agent). It requires a valid authgent-issued bearer
token carrying `caep_operator_scope` (default: "admin:security"), checked
unconditionally — there is no "open" mode for this endpoint, because it
both mutates revocation state for a token that is not the caller's own AND
transmits an external network signal.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from authgent_server.config import Settings, get_settings
from authgent_server.dependencies import get_db_session, get_jwks_service, get_token_service
from authgent_server.errors import AccessDenied, InvalidClient, InvalidRequest
from authgent_server.services.jwks_service import JWKSService
from authgent_server.services.token_service import TokenService

router = APIRouter(prefix="/security", tags=["security"])


class CompromiseFlagRequest(BaseModel):
    jti: str = Field(description="The JTI of the compromised token")
    reason: str = Field(default="operator_flagged", max_length=255)


class DeliveryResultResponse(BaseModel):
    receiver_url: str
    delivered: bool
    status_code: int | None
    attempts: int
    error: str | None = None
    elapsed_seconds: float


class CompromiseFlagResponse(BaseModel):
    jti: str
    blocklisted: bool = True
    caep_deliveries: list[DeliveryResultResponse]


async def _require_operator_scope(
    request: Request,
    db: AsyncSession,
    jwks: JWKSService,
    settings: Settings,
) -> dict:
    """Validate the caller's bearer token carries caep_operator_scope.

    Returns the decoded claims (used to populate the audit trail's actor).
    """
    auth = request.headers.get("authorization", "")
    if not auth.startswith("Bearer "):
        raise InvalidClient("Compromise-flagging requires a bearer token")
    bearer_token = auth[7:]

    try:
        claims = await jwks.verify_jwt(db, bearer_token)
    except Exception as exc:
        raise InvalidClient(f"Invalid bearer token: {exc}") from exc

    scopes = set(claims.get("scope", "").split())
    if settings.caep_operator_scope not in scopes:
        raise AccessDenied(
            f"Compromise-flagging requires scope '{settings.caep_operator_scope}'"
        )
    return claims


@router.post("/tokens/compromise", response_model=CompromiseFlagResponse)
async def flag_token_compromised(
    body: CompromiseFlagRequest,
    request: Request,
    db: AsyncSession = Depends(get_db_session),
    token_service: TokenService = Depends(get_token_service),
    jwks: JWKSService = Depends(get_jwks_service),
    settings: Settings = Depends(get_settings),
) -> CompromiseFlagResponse:
    """Flag a token as compromised: blocklist + cascade-revoke + CAEP push.

    See TokenService.flag_compromised for the full design rationale on why
    this is a separate trigger path from POST /revoke.
    """
    if not body.jti:
        raise InvalidRequest("jti is required")

    claims = await _require_operator_scope(request, db, jwks, settings)
    operator = str(claims.get("client_id") or claims.get("sub") or "unknown")

    results = await token_service.flag_compromised(
        db,
        body.jti,
        body.reason,
        client_id=operator,
        actor_id=operator,
    )

    return CompromiseFlagResponse(
        jti=body.jti,
        caep_deliveries=[
            DeliveryResultResponse(
                receiver_url=r.receiver_url,
                delivered=r.delivered,
                status_code=r.status_code,
                attempts=r.attempts,
                error=r.error,
                elapsed_seconds=r.elapsed_seconds,
            )
            for r in results
        ],
    )
