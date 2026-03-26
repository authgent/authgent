"""Agent identity schemas."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field


class AgentCreate(BaseModel):
    name: str = Field(max_length=255)
    description: str | None = None
    owner: str | None = None
    allowed_scopes: list[str] = Field(default_factory=list)
    capabilities: list[str] = Field(default_factory=list)
    allowed_exchange_targets: list[str] = Field(default_factory=list)
    metadata: dict | None = None
    agent_type: str | None = None
    agent_model: str | None = None
    agent_version: str | None = None
    agent_provider: str | None = None


class AgentUpdate(BaseModel):
    name: str | None = None
    description: str | None = None
    owner: str | None = None
    allowed_scopes: list[str] | None = None
    capabilities: list[str] | None = None
    allowed_exchange_targets: list[str] | None = None
    status: str | None = None
    metadata: dict | None = None
    agent_type: str | None = None
    agent_model: str | None = None
    agent_version: str | None = None
    agent_provider: str | None = None


class AgentResponse(BaseModel):
    id: str
    oauth_client_id: str | None = None
    name: str
    description: str | None = None
    owner: str | None = None
    allowed_scopes: list[str] | None = None
    capabilities: list[str] | None = None
    allowed_exchange_targets: list[str] | None = None
    status: str
    metadata: dict | None = None
    agent_type: str | None = None
    agent_model: str | None = None
    agent_version: str | None = None
    agent_provider: str | None = None
    attestation_level: str | None = None
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class AgentWithCredentials(AgentResponse):
    """Returned on agent creation — includes client_id and client_secret."""

    client_id: str
    client_secret: str
