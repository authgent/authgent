"""Agent service — CRUD + lifecycle management."""

from __future__ import annotations

import structlog
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from authgent_server.config import Settings
from authgent_server.errors import AgentNotFound
from authgent_server.models.agent import Agent
from authgent_server.models.oauth_client import OAuthClient
from authgent_server.schemas.agent import AgentCreate, AgentResponse, AgentUpdate
from authgent_server.schemas.client import RegisterRequest
from authgent_server.services.client_service import ClientService

logger = structlog.get_logger()


class AgentService:
    def __init__(self, settings: Settings, client_service: ClientService):
        self._settings = settings
        self._client_service = client_service

    async def create_agent(self, db: AsyncSession, request: AgentCreate) -> tuple[Agent, str, str]:
        """Create an agent + linked OAuth client. Returns (agent, client_id, client_secret)."""
        # Create the agent record
        agent = Agent(
            name=request.name,
            description=request.description,
            owner=request.owner,
            allowed_scopes=request.allowed_scopes,
            capabilities=request.capabilities,
            allowed_exchange_targets=request.allowed_exchange_targets,
            metadata_=request.metadata,
            agent_type=request.agent_type,
            agent_model=request.agent_model,
            agent_version=request.agent_version,
            agent_provider=request.agent_provider,
        )
        db.add(agent)
        await db.flush()

        # Create linked OAuth client — include token-exchange so agents can delegate
        scope = " ".join(request.allowed_scopes) if request.allowed_scopes else ""
        reg = RegisterRequest(
            client_name=request.name,
            grant_types=[
                "client_credentials",
                "urn:ietf:params:oauth:grant-type:token-exchange",
            ],
            scope=scope,
        )
        client_resp = await self._client_service.register_client(db, reg, agent_id=agent.id)

        agent.oauth_client_id = client_resp.client_id
        await db.commit()
        await db.refresh(agent)

        logger.info("agent_created", agent_id=agent.id, name=agent.name)
        return agent, client_resp.client_id, client_resp.client_secret

    async def get_agent(self, db: AsyncSession, agent_id: str) -> Agent:
        stmt = select(Agent).where(Agent.id == agent_id)
        result = await db.execute(stmt)
        agent = result.scalar_one_or_none()
        if not agent:
            raise AgentNotFound(f"Agent not found: {agent_id}")
        return agent

    async def list_agents(
        self,
        db: AsyncSession,
        offset: int = 0,
        limit: int = 20,
        status: str | None = None,
        owner: str | None = None,
    ) -> tuple[list[Agent], int]:
        """List agents with pagination and optional filters."""
        stmt = select(Agent)
        count_stmt = select(func.count()).select_from(Agent)

        if status:
            stmt = stmt.where(Agent.status == status)
            count_stmt = count_stmt.where(Agent.status == status)
        if owner:
            stmt = stmt.where(Agent.owner == owner)
            count_stmt = count_stmt.where(Agent.owner == owner)

        stmt = stmt.offset(offset).limit(limit).order_by(Agent.created_at.desc())

        result = await db.execute(stmt)
        agents = list(result.scalars().all())

        count_result = await db.execute(count_stmt)
        total = count_result.scalar() or 0

        return agents, total

    async def update_agent(self, db: AsyncSession, agent_id: str, request: AgentUpdate) -> Agent:
        agent = await self.get_agent(db, agent_id)

        update_data = request.model_dump(exclude_unset=True)
        for field, value in update_data.items():
            if field == "metadata":
                setattr(agent, "metadata_", value)
            else:
                setattr(agent, field, value)

        # Propagate allowed_scopes changes to the linked OAuthClient.scope
        # so that token issuance enforces the updated scopes.
        if "allowed_scopes" in update_data and agent.oauth_client_id:
            new_scope = (
                " ".join(update_data["allowed_scopes"])
                if update_data["allowed_scopes"]
                else ""
            )
            stmt = select(OAuthClient).where(
                OAuthClient.client_id == agent.oauth_client_id
            )
            result = await db.execute(stmt)
            oauth_client = result.scalar_one_or_none()
            if oauth_client:
                oauth_client.scope = new_scope
                logger.info(
                    "agent_scopes_propagated",
                    agent_id=agent_id,
                    client_id=agent.oauth_client_id,
                    new_scope=new_scope,
                )

        await db.commit()
        await db.refresh(agent)
        logger.info("agent_updated", agent_id=agent_id, fields=list(update_data.keys()))
        return agent

    async def deactivate_agent(self, db: AsyncSession, agent_id: str) -> Agent:
        """Soft deactivate: set status to 'inactive'."""
        agent = await self.get_agent(db, agent_id)
        agent.status = "inactive"
        await db.commit()
        await db.refresh(agent)
        logger.info("agent_deactivated", agent_id=agent_id)
        return agent

    @staticmethod
    def to_response(agent: Agent) -> AgentResponse:
        return AgentResponse(
            id=agent.id,
            oauth_client_id=agent.oauth_client_id,
            name=agent.name,
            description=agent.description,
            owner=agent.owner,
            allowed_scopes=agent.allowed_scopes,
            capabilities=agent.capabilities,
            allowed_exchange_targets=agent.allowed_exchange_targets,
            status=agent.status,
            metadata=agent.metadata_,
            agent_type=agent.agent_type,
            agent_model=agent.agent_model,
            agent_version=agent.agent_version,
            agent_provider=agent.agent_provider,
            attestation_level=agent.attestation_level,
            created_at=agent.created_at,
            updated_at=agent.updated_at,
        )
