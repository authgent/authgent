"""MCP Auth Provider adapter — plug authgent into FastMCP servers."""

from __future__ import annotations

from authgent.client import AgentAuthClient
from authgent.verify import verify_token
from authgent.models import AgentIdentity


class AgentAuthProvider:
    """Auth provider adapter for FastMCP servers.

    Usage:
        from authgent.adapters.mcp import AgentAuthProvider
        mcp = FastMCP("my-server")
        mcp.auth_provider = AgentAuthProvider(server_url="http://localhost:8000")
    """

    def __init__(self, server_url: str, audience: str | None = None):
        self._server_url = server_url.rstrip("/")
        self._audience = audience
        self._client = AgentAuthClient(server_url)

    async def verify(self, token: str) -> AgentIdentity:
        """Verify an access token and return the agent identity."""
        return await verify_token(
            token=token,
            issuer=self._server_url,
            audience=self._audience,
        )

    @property
    def metadata_url(self) -> str:
        """URL for OAuth server metadata discovery."""
        return f"{self._server_url}/.well-known/oauth-authorization-server"

    @property
    def jwks_url(self) -> str:
        """URL for JWKS endpoint."""
        return f"{self._server_url}/.well-known/jwks.json"
