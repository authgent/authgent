"""AgentAuthClient — server API wrapper for token operations."""

from __future__ import annotations

from dataclasses import dataclass

import base64
import json

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

    async def refresh_token(
        self,
        refresh_token_value: str,
        client_id: str,
        client_secret: str,
    ) -> TokenResult:
        """Refresh an access token using a refresh_token grant."""
        data: dict = {
            "grant_type": "refresh_token",
            "refresh_token": refresh_token_value,
            "client_id": client_id,
            "client_secret": client_secret,
        }

        async with httpx.AsyncClient(timeout=self._timeout) as client:
            resp = await client.post(
                f"{self._base}/token",
                data=data,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
            if resp.status_code != 200:
                raise ServerError(f"Token refresh failed: {resp.text}")
            result = resp.json()

        return TokenResult(
            access_token=result["access_token"],
            token_type=result["token_type"],
            expires_in=result["expires_in"],
            scope=result.get("scope"),
            refresh_token=result.get("refresh_token"),
        )

    async def introspect_token(
        self,
        token: str,
        client_id: str | None = None,
        client_secret: str | None = None,
    ) -> dict:
        """Introspect a token — returns claims if active, {'active': False} otherwise."""
        data: dict = {"token": token}
        if client_id:
            data["client_id"] = client_id
        if client_secret:
            data["client_secret"] = client_secret

        async with httpx.AsyncClient(timeout=self._timeout) as client:
            resp = await client.post(
                f"{self._base}/introspect",
                data=data,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
            if resp.status_code != 200:
                raise ServerError(f"Token introspection failed: {resp.text}")
            return resp.json()

    async def request_stepup(
        self,
        agent_id: str,
        action: str,
        scope: str,
        resource: str | None = None,
        delegation_chain: dict | None = None,
        metadata: dict | None = None,
    ) -> dict:
        """Request human-in-the-loop step-up authorization.

        Args:
            agent_id: The agent requesting elevated privileges.
            action: Description of the action requiring approval.
            scope: Space-separated scopes being requested.
            resource: Optional target resource URI.
            delegation_chain: Optional delegation chain snapshot.
            metadata: Optional extra context for the reviewer.

        Returns the step-up request object with 'id' and 'status' fields.
        Poll check_stepup() with the returned id to wait for approval.
        """
        payload: dict = {
            "agent_id": agent_id,
            "action": action,
            "scope": scope,
        }
        if resource:
            payload["resource"] = resource
        if delegation_chain:
            payload["delegation_chain"] = delegation_chain
        if metadata:
            payload["metadata"] = metadata

        async with httpx.AsyncClient(timeout=self._timeout) as client:
            resp = await client.post(
                f"{self._base}/stepup",
                json=payload,
            )
            if resp.status_code not in (200, 201, 202):
                raise ServerError(f"Step-up request failed: {resp.text}")
            return resp.json()

    async def request_stepup_for_token(
        self,
        token: str,
        action: str,
        scope: str,
        resource: str | None = None,
    ) -> dict:
        """Convenience: extract agent_id from a JWT and create a step-up request.

        The token's 'sub' claim (e.g. 'client:agnt_xxx') is mapped to the agent_id.
        """
        claims = self._decode_jwt_claims(token)
        sub = claims.get("sub", "")
        # sub is typically "client:<client_id>" — extract client_id as agent identifier
        agent_id = claims.get("client_id") or sub
        return await self.request_stepup(
            agent_id=agent_id,
            action=action,
            scope=scope,
            resource=resource,
        )

    async def check_stepup(self, request_id: str) -> dict:
        """Check the status of a step-up request. Returns {'status': 'pending'|'approved'|'denied'}."""
        async with httpx.AsyncClient(timeout=self._timeout) as client:
            resp = await client.get(f"{self._base}/stepup/{request_id}")
            if resp.status_code != 200:
                raise ServerError(f"Step-up status check failed: {resp.text}")
            return resp.json()

    async def check_exchange(
        self,
        subject_token: str,
        audience: str,
        client_id: str,
        scope: str = "",
    ) -> dict:
        """Dry-run pre-check: will a token exchange succeed?

        Returns {allowed, effective_scopes, delegation_depth, max_delegation_depth, reasons}.
        """
        payload = {
            "subject_token": subject_token,
            "audience": audience,
            "client_id": client_id,
            "scope": scope,
        }
        async with httpx.AsyncClient(timeout=self._timeout) as client:
            resp = await client.post(
                f"{self._base}/token/check",
                json=payload,
            )
            if resp.status_code != 200:
                raise ServerError(f"Token check failed: {resp.text}")
            return resp.json()

    @staticmethod
    def _decode_jwt_claims(token: str) -> dict:
        """Decode JWT payload without verification (for extracting claims like sub)."""
        try:
            parts = token.split(".")
            if len(parts) != 3:
                return {}
            payload = parts[1]
            # Add padding
            payload += "=" * (4 - len(payload) % 4)
            decoded = base64.urlsafe_b64decode(payload)
            return json.loads(decoded)
        except Exception:
            return {}

    async def revoke_token(
        self,
        token: str,
        client_id: str,
        client_secret: str,
    ) -> None:
        """Revoke an access or refresh token.

        Requires client authentication (client_id + client_secret).
        Only the token's owning client can revoke it.
        """
        data: dict = {
            "token": token,
            "client_id": client_id,
            "client_secret": client_secret,
        }

        async with httpx.AsyncClient(timeout=self._timeout) as client:
            resp = await client.post(
                f"{self._base}/revoke",
                data=data,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
            if resp.status_code not in (200, 204):
                raise ServerError(f"Token revocation failed: {resp.text}")
