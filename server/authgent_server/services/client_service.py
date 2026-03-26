"""Client service — OAuth client registration and authentication."""

from __future__ import annotations

import secrets
from datetime import UTC, datetime
from urllib.parse import urlparse

import bcrypt
import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from authgent_server.config import Settings
from authgent_server.errors import InsufficientScope, InvalidClient, InvalidRequest
from authgent_server.models.oauth_client import OAuthClient
from authgent_server.schemas.client import RegisterRequest, RegisterResponse

logger = structlog.get_logger()


def _generate_client_id() -> str:
    return f"agnt_{secrets.token_urlsafe(16)}"


def _generate_client_secret() -> str:
    return f"sec_{secrets.token_urlsafe(32)}"


def _hash_secret(secret: str) -> str:
    return bcrypt.hashpw(secret.encode(), bcrypt.gensalt(rounds=12)).decode()


def _verify_secret(secret: str, hashed: str) -> bool:
    return bcrypt.checkpw(secret.encode(), hashed.encode())


class ClientService:
    def __init__(self, settings: Settings):
        self._settings = settings

    async def register_client(
        self, db: AsyncSession, request: RegisterRequest, agent_id: str | None = None
    ) -> RegisterResponse:
        """Register a new OAuth client (RFC 7591 Dynamic Client Registration)."""
        client_id = _generate_client_id()
        client_secret = _generate_client_secret()
        secret_hash = _hash_secret(client_secret)

        client = OAuthClient(
            client_id=client_id,
            client_secret_hash=secret_hash,
            client_name=request.client_name,
            grant_types=request.grant_types,
            redirect_uris=request.redirect_uris,
            scope=request.scope,
            allowed_resources=request.allowed_resources,
            token_endpoint_auth_method=request.token_endpoint_auth_method,
            dpop_bound_access_tokens=request.dpop_bound_access_tokens,
            agent_id=agent_id,
        )
        db.add(client)
        await db.commit()

        logger.info("client_registered", client_id=client_id, client_name=request.client_name)

        return RegisterResponse(
            client_id=client_id,
            client_secret=client_secret,
            client_name=request.client_name,
            grant_types=request.grant_types,
            redirect_uris=request.redirect_uris,
            scope=request.scope,
            token_endpoint_auth_method=request.token_endpoint_auth_method,
            dpop_bound_access_tokens=request.dpop_bound_access_tokens,
        )

    async def authenticate_client(
        self, db: AsyncSession, client_id: str, client_secret: str
    ) -> OAuthClient:
        """Authenticate a client by client_id + client_secret. Timing-safe."""
        stmt = (
            select(OAuthClient)
            .where(OAuthClient.client_id == client_id)
            .options(selectinload(OAuthClient.agent))
        )
        result = await db.execute(stmt)
        client = result.scalar_one_or_none()

        if client is None:
            # Timing-safe: always hash even if client not found
            _hash_secret("dummy_secret_for_timing_safety")
            raise InvalidClient(f"Client not found: {client_id}")

        # Check if linked agent is deactivated
        if client.agent and client.agent.status == "inactive":
            raise InvalidClient("Agent has been deactivated")

        # Check current secret
        if _verify_secret(client_secret, client.client_secret_hash):
            return client

        # Check previous secret (rotation grace period)
        if client.previous_secret_hash and client.previous_secret_expires:
            if datetime.now(UTC) < client.previous_secret_expires:
                if _verify_secret(client_secret, client.previous_secret_hash):
                    return client

        raise InvalidClient("Invalid client credentials")

    async def get_client(self, db: AsyncSession, client_id: str) -> OAuthClient | None:
        """Look up a client by client_id."""
        stmt = (
            select(OAuthClient)
            .where(OAuthClient.client_id == client_id)
            .options(selectinload(OAuthClient.agent))
        )
        result = await db.execute(stmt)
        client = result.scalar_one_or_none()

        # Reject deactivated agents
        if client and client.agent and client.agent.status == "inactive":
            raise InvalidClient("Agent has been deactivated")

        return client

    async def validate_resource(self, client: OAuthClient, resource: str | None) -> None:
        """Validate that the requested resource is in the client's allowed_resources."""
        if not resource:
            return
        if not client.allowed_resources:
            return  # no restrictions
        if self._settings.resource_match == "exact":
            if resource not in client.allowed_resources:
                raise InvalidRequest(f"Resource '{resource}' not in client's allowed_resources")
        elif self._settings.resource_match == "origin":
            req_parsed = urlparse(resource)
            req_origin = f"{req_parsed.scheme}://{req_parsed.netloc}"
            if not any(
                urlparse(r).scheme + "://" + urlparse(r).netloc == req_origin
                for r in client.allowed_resources
            ):
                raise InvalidRequest(
                    f"Resource origin '{req_origin}' not in client's allowed_resources"
                )

    async def validate_scopes(self, client: OAuthClient, requested_scope: str | None) -> str:
        """Validate and return the effective scope."""
        if not requested_scope:
            return client.scope or ""

        client_scopes = set((client.scope or "").split())
        requested = set(requested_scope.split())

        if client_scopes and not requested.issubset(client_scopes):
            invalid = requested - client_scopes
            raise InsufficientScope(
                f"Requested scopes not in client registration: {', '.join(invalid)}"
            )

        return requested_scope
