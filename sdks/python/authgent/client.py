"""AgentAuthClient — server API wrapper for token operations."""

from __future__ import annotations

from dataclasses import dataclass

import httpx

from authgent.errors import ServerError


@dataclass
class TokenResult:
    access_token: str
    token_type: str
    expires_in: int
    scope: str | None = None
    refresh_token: str | None = None


@dataclass
class AgentResult:
    id: str
    client_id: str
    client_secret: str
    name: str


class AgentAuthClient:
    """Client for the authgent-server API."""

    def __init__(self, server_url: str, timeout: float = 30.0):
        self._base = server_url.rstrip("/")
        self._timeout = timeout

    async def register_agent(
        self,
        name: str,
        scopes: list[str] | None = None,
        owner: str | None = None,
        capabilities: list[str] | None = None,
    ) -> AgentResult:
        """Register a new agent — returns agent with credentials."""
        payload: dict = {"name": name}
        if scopes:
            payload["allowed_scopes"] = scopes
        if owner:
            payload["owner"] = owner
        if capabilities:
            payload["capabilities"] = capabilities

        async with httpx.AsyncClient(timeout=self._timeout) as client:
            resp = await client.post(f"{self._base}/agents", json=payload)
            if resp.status_code != 201:
                raise ServerError(f"Agent registration failed: {resp.text}")
            data = resp.json()

        return AgentResult(
            id=data["id"],
            client_id=data["client_id"],
            client_secret=data["client_secret"],
            name=data["name"],
        )

    async def get_token(
        self,
        client_id: str,
        client_secret: str,
        scope: str | None = None,
        resource: str | None = None,
    ) -> TokenResult:
        """Get an access token via client_credentials grant."""
        data: dict = {
            "grant_type": "client_credentials",
            "client_id": client_id,
            "client_secret": client_secret,
        }
        if scope:
            data["scope"] = scope
        if resource:
            data["resource"] = resource

        async with httpx.AsyncClient(timeout=self._timeout) as client:
            resp = await client.post(
                f"{self._base}/token",
                data=data,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
            if resp.status_code != 200:
                raise ServerError(f"Token request failed: {resp.text}")
            result = resp.json()

        return TokenResult(
            access_token=result["access_token"],
            token_type=result["token_type"],
            expires_in=result["expires_in"],
            scope=result.get("scope"),
            refresh_token=result.get("refresh_token"),
        )

    async def exchange_token(
        self,
        subject_token: str,
        audience: str,
        scopes: list[str] | None = None,
        client_id: str | None = None,
        client_secret: str | None = None,
    ) -> TokenResult:
        """Exchange a token for a downstream delegated token (RFC 8693)."""
        data: dict = {
            "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
            "subject_token": subject_token,
            "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
            "audience": audience,
        }
        if scopes:
            data["scope"] = " ".join(scopes)
        if client_id:
            data["client_id"] = client_id
        if client_secret:
            data["client_secret"] = client_secret

        async with httpx.AsyncClient(timeout=self._timeout) as client:
            resp = await client.post(
                f"{self._base}/token",
                data=data,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
            if resp.status_code != 200:
                raise ServerError(f"Token exchange failed: {resp.text}")
            result = resp.json()

        return TokenResult(
            access_token=result["access_token"],
            token_type=result["token_type"],
            expires_in=result["expires_in"],
            scope=result.get("scope"),
        )

    async def revoke_token(
        self,
        token: str,
        client_id: str | None = None,
    ) -> None:
        """Revoke an access or refresh token."""
        data: dict = {"token": token}
        if client_id:
            data["client_id"] = client_id

        async with httpx.AsyncClient(timeout=self._timeout) as client:
            resp = await client.post(
                f"{self._base}/revoke",
                data=data,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
            if resp.status_code not in (200, 204):
                raise ServerError(f"Token revocation failed: {resp.text}")
