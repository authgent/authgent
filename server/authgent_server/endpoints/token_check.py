"""POST /token/check — dry-run permission pre-check for token exchange.

Allows agents to verify whether a delegation would succeed before attempting it.
Returns the effective scopes, delegation depth, and any policy violations —
without actually issuing a token.
"""

from __future__ import annotations

from pydantic import BaseModel, Field
from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from authgent_server.config import Settings, get_settings
from authgent_server.dependencies import (
    get_client_service,
    get_db_session,
    get_delegation_service,
    get_token_service,
)
from authgent_server.errors import AuthgentError, InvalidClient, InvalidRequest
from authgent_server.services.client_service import ClientService
from authgent_server.services.delegation_service import DelegationService
from authgent_server.services.external_oidc import ACCESS_TOKEN_TYPE
from authgent_server.services.token_service import TokenService

router = APIRouter(tags=["token"])


class TokenCheckRequest(BaseModel):
    subject_token: str = Field(..., description="Parent access token to check")
    audience: str = Field(..., description="Target audience for delegation")
    client_id: str = Field(..., description="Requesting client ID")
    scope: str = Field(default="", description="Space-separated requested scopes")


class TokenCheckResponse(BaseModel):
    allowed: bool
    effective_scopes: list[str] = Field(default_factory=list)
    delegation_depth: int = 0
    max_delegation_depth: int = 5
    reasons: list[str] = Field(default_factory=list)


@router.post("/token/check", response_model=TokenCheckResponse)
async def token_check(
    request: TokenCheckRequest,
    db: AsyncSession = Depends(get_db_session),
    token_service: TokenService = Depends(get_token_service),
    client_service: ClientService = Depends(get_client_service),
    delegation_service: DelegationService = Depends(get_delegation_service),
    settings: Settings = Depends(get_settings),
) -> TokenCheckResponse:
    """Dry-run pre-check: will this token exchange succeed?

    Does NOT issue a token. Validates:
    - Subject token is valid and not revoked
    - Client exists and has token-exchange grant
    - Audience is in allowed_exchange_targets (if configured)
    - Requested scopes are a subset of parent scopes
    - Delegation depth is within limits
    """
    reasons: list[str] = []
    effective_scopes: list[str] = []
    delegation_depth = 0

    # 1. Validate the client exists
    try:
        client = await client_service.get_client(db, request.client_id)
        if not client:
            return TokenCheckResponse(
                allowed=False,
                reasons=[f"Client not found: {request.client_id}"],
                max_delegation_depth=settings.max_delegation_depth,
            )
    except InvalidClient as e:
        return TokenCheckResponse(
            allowed=False,
            reasons=[str(e)],
            max_delegation_depth=settings.max_delegation_depth,
        )

    # 2. Check grant type is allowed
    exchange_grant = "urn:ietf:params:oauth:grant-type:token-exchange"
    if client.grant_types and exchange_grant not in client.grant_types:
        reasons.append(f"Client does not have {exchange_grant} grant type")

    # 3. Check allowed_exchange_targets
    if client.agent and client.agent.allowed_exchange_targets:
        if request.audience not in client.agent.allowed_exchange_targets:
            reasons.append(
                f"Audience '{request.audience}' not in allowed_exchange_targets: "
                f"{client.agent.allowed_exchange_targets}"
            )

    # 4. Verify subject token
    try:
        parent_claims = await token_service.verify_and_check_blocklist(
            db, request.subject_token
        )
    except AuthgentError as e:
        return TokenCheckResponse(
            allowed=False,
            reasons=[f"Subject token invalid: {e.detail}"],
            max_delegation_depth=settings.max_delegation_depth,
        )
    except Exception as e:
        return TokenCheckResponse(
            allowed=False,
            reasons=[f"Subject token invalid: {e}"],
            max_delegation_depth=settings.max_delegation_depth,
        )

    # 5. Check delegation depth
    delegation_depth = delegation_service._get_chain_depth(parent_claims)
    if delegation_depth >= settings.max_delegation_depth:
        reasons.append(
            f"Delegation depth {delegation_depth + 1} would exceed "
            f"max {settings.max_delegation_depth}"
        )

    # 6. Check scope reduction
    requested_scopes = request.scope.split() if request.scope else []
    parent_scopes = set(parent_claims.get("scope", "").split())

    if settings.delegation_scope_reduction and parent_scopes and requested_scopes:
        requested_set = set(requested_scopes)
        if not requested_set.issubset(parent_scopes):
            escalated = requested_set - parent_scopes
            reasons.append(f"Scope escalation: {', '.join(escalated)} not in parent scopes")
        effective_scopes = sorted(requested_set & parent_scopes)
    elif requested_scopes:
        effective_scopes = requested_scopes
    else:
        effective_scopes = sorted(parent_scopes) if parent_scopes else []

    # 7. Check may_act
    may_act = parent_claims.get("may_act")
    if may_act and isinstance(may_act, dict):
        allowed_subs = may_act.get("sub", [])
        actor_id = f"client:{request.client_id}"
        if isinstance(allowed_subs, list) and actor_id not in allowed_subs:
            reasons.append(f"Actor '{actor_id}' not in may_act.sub: {allowed_subs}")

    return TokenCheckResponse(
        allowed=len(reasons) == 0,
        effective_scopes=effective_scopes,
        delegation_depth=delegation_depth,
        max_delegation_depth=settings.max_delegation_depth,
        reasons=reasons,
    )
