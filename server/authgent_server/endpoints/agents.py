"""CRUD /agents — Agent Identity Registry endpoints."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession

from authgent_server.dependencies import get_agent_service, get_db_session
from authgent_server.schemas.agent import (
    AgentCreate,
    AgentResponse,
    AgentUpdate,
    AgentWithCredentials,
)
from authgent_server.services.agent_service import AgentService

router = APIRouter(prefix="/agents", tags=["agents"])


@router.post("", response_model=AgentWithCredentials, status_code=201)
async def create_agent(
    request: AgentCreate,
    db: AsyncSession = Depends(get_db_session),
    agent_service: AgentService = Depends(get_agent_service),
) -> AgentWithCredentials:
    """Register a new agent with name, owner, scopes, capabilities."""
    agent, client_id, client_secret = await agent_service.create_agent(db, request)
    resp = AgentService.to_response(agent)
    return AgentWithCredentials(
        **resp.model_dump(),
        client_id=client_id,
        client_secret=client_secret,
    )


@router.get("", response_model=dict)
async def list_agents(
    offset: int = Query(default=0, ge=0),
    limit: int = Query(default=20, ge=1, le=100),
    status: str | None = None,
    owner: str | None = None,
    db: AsyncSession = Depends(get_db_session),
    agent_service: AgentService = Depends(get_agent_service),
) -> dict:
    """List agents with pagination and optional filters."""
    agents, total = await agent_service.list_agents(
        db, offset=offset, limit=limit, status=status, owner=owner
    )
    return {
        "items": [AgentService.to_response(a).model_dump() for a in agents],
        "total": total,
        "offset": offset,
        "limit": limit,
    }


@router.get("/{agent_id}", response_model=AgentResponse)
async def get_agent(
    agent_id: str,
    db: AsyncSession = Depends(get_db_session),
    agent_service: AgentService = Depends(get_agent_service),
) -> AgentResponse:
    """Get agent details by ID."""
    agent = await agent_service.get_agent(db, agent_id)
    return AgentService.to_response(agent)


@router.patch("/{agent_id}", response_model=AgentResponse)
async def update_agent(
    agent_id: str,
    request: AgentUpdate,
    db: AsyncSession = Depends(get_db_session),
    agent_service: AgentService = Depends(get_agent_service),
) -> AgentResponse:
    """Update agent scopes, metadata, or status."""
    agent = await agent_service.update_agent(db, agent_id, request)
    return AgentService.to_response(agent)


@router.delete("/{agent_id}", response_model=AgentResponse)
async def deactivate_agent(
    agent_id: str,
    db: AsyncSession = Depends(get_db_session),
    agent_service: AgentService = Depends(get_agent_service),
) -> AgentResponse:
    """Soft deactivate agent — sets status to 'inactive', revokes tokens."""
    agent = await agent_service.deactivate_agent(db, agent_id)
    return AgentService.to_response(agent)
