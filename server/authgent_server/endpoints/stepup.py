"""HITL Step-Up Authorization endpoints — request, poll, approve/deny."""

from __future__ import annotations

from datetime import datetime

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from authgent_server.dependencies import get_db_session, get_stepup_service
from authgent_server.services.stepup_service import StepUpService

router = APIRouter(prefix="/stepup", tags=["stepup"])


class StepUpCreateRequest(BaseModel):
    agent_id: str
    action: str = Field(max_length=255)
    scope: str = Field(max_length=1024)
    resource: str | None = None
    delegation_chain: dict | None = None
    metadata: dict | None = None


class StepUpResponse(BaseModel):
    id: str
    agent_id: str
    action: str
    scope: str
    resource: str | None = None
    status: str
    approved_by: str | None = None
    approved_at: datetime | None = None
    expires_at: datetime
    created_at: datetime

    model_config = {"from_attributes": True}


class StepUpDecisionRequest(BaseModel):
    approved_by: str | None = None


@router.post("", response_model=StepUpResponse, status_code=202)
async def create_stepup_request(
    request: StepUpCreateRequest,
    db: AsyncSession = Depends(get_db_session),
    stepup_service: StepUpService = Depends(get_stepup_service),
) -> StepUpResponse:
    """Create a step-up authorization request for HITL approval."""
    req = await stepup_service.create_request(
        db,
        agent_id=request.agent_id,
        action=request.action,
        scope=request.scope,
        resource=request.resource,
        delegation_chain=request.delegation_chain,
        metadata=request.metadata,
    )
    return StepUpResponse.model_validate(req)


@router.get("/{request_id}", response_model=StepUpResponse)
async def get_stepup_request(
    request_id: str,
    db: AsyncSession = Depends(get_db_session),
    stepup_service: StepUpService = Depends(get_stepup_service),
) -> StepUpResponse:
    """Poll the status of a step-up request."""
    req = await stepup_service.get_request(db, request_id)
    return StepUpResponse.model_validate(req)


@router.post("/{request_id}/approve", response_model=StepUpResponse)
async def approve_stepup_request(
    request_id: str,
    body: StepUpDecisionRequest,
    db: AsyncSession = Depends(get_db_session),
    stepup_service: StepUpService = Depends(get_stepup_service),
) -> StepUpResponse:
    """Approve a pending step-up request (human reviewer action)."""
    req = await stepup_service.approve_request(
        db, request_id, approved_by=body.approved_by or "unknown"
    )
    return StepUpResponse.model_validate(req)


@router.post("/{request_id}/deny", response_model=StepUpResponse)
async def deny_stepup_request(
    request_id: str,
    db: AsyncSession = Depends(get_db_session),
    stepup_service: StepUpService = Depends(get_stepup_service),
) -> StepUpResponse:
    """Deny a pending step-up request."""
    req = await stepup_service.deny_request(db, request_id)
    return StepUpResponse.model_validate(req)
