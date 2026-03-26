"""Step-up service — HITL step-up authorization flow orchestration."""

from __future__ import annotations

from datetime import timedelta

import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from authgent_server.config import Settings
from authgent_server.errors import InvalidRequest
from authgent_server.models.stepup_request import StepUpRequest
from authgent_server.utils import is_expired, utcnow

logger = structlog.get_logger()


class StepUpService:
    def __init__(self, settings: Settings):
        self._settings = settings

    async def create_request(
        self,
        db: AsyncSession,
        agent_id: str,
        action: str,
        scope: str,
        resource: str | None = None,
        delegation_chain: dict | None = None,
        metadata: dict | None = None,
    ) -> StepUpRequest:
        """Create a step-up authorization request."""
        request = StepUpRequest(
            agent_id=agent_id,
            action=action,
            scope=scope,
            resource=resource,
            delegation_chain_snapshot=delegation_chain,
            expires_at=utcnow() + timedelta(seconds=self._settings.hitl_timeout),
            metadata_=metadata,
        )
        db.add(request)
        await db.commit()
        await db.refresh(request)

        logger.info("stepup_request_created", request_id=request.id, agent_id=agent_id)
        return request

    async def get_request(self, db: AsyncSession, request_id: str) -> StepUpRequest:
        stmt = select(StepUpRequest).where(StepUpRequest.id == request_id)
        result = await db.execute(stmt)
        req = result.scalar_one_or_none()
        if not req:
            raise InvalidRequest(f"Step-up request not found: {request_id}")

        # Check expiration
        if req.status == "pending" and is_expired(req.expires_at):
            req.status = "expired"
            await db.commit()

        return req

    async def approve_request(
        self, db: AsyncSession, request_id: str, approved_by: str
    ) -> StepUpRequest:
        req = await self.get_request(db, request_id)
        if req.status != "pending":
            raise InvalidRequest(f"Request is not pending: {req.status}")

        req.status = "approved"
        req.approved_by = approved_by
        req.approved_at = utcnow()
        await db.commit()
        await db.refresh(req)

        logger.info("stepup_approved", request_id=request_id, approved_by=approved_by)
        return req

    async def deny_request(self, db: AsyncSession, request_id: str) -> StepUpRequest:
        req = await self.get_request(db, request_id)
        if req.status != "pending":
            raise InvalidRequest(f"Request is not pending: {req.status}")

        req.status = "denied"
        await db.commit()
        await db.refresh(req)

        logger.info("stepup_denied", request_id=request_id)
        return req
