"""MCP scope challenge auto-detection + HITL step-up trigger.

When an MCP server returns 403 with WWW-Authenticate containing
insufficient_scope, this module automatically:
1. Detects the missing scope from the challenge
2. Checks if the scope is in the HITL_SCOPES list
3. If so, initiates a step-up request via POST /stepup
4. Polls for approval
5. Returns the step-up token for retry

Architecture ref: §4.6, §11.1 step 6
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass

import httpx

from authgent.errors import AuthgentError


class StepUpDeniedError(AuthgentError):
    """Step-up request was denied by the human approver."""

    error_code = "step_up_denied"


class StepUpTimeoutError(AuthgentError):
    """Step-up request timed out waiting for human approval."""

    error_code = "step_up_timeout"


@dataclass
class ScopeChallenge:
    """Parsed WWW-Authenticate scope challenge."""

    required_scope: str
    error: str = "insufficient_scope"
    realm: str = ""


@dataclass
class StepUpResult:
    """Result of a step-up flow."""

    stepup_id: str
    status: str  # approved | denied | expired
    step_up_token: str | None = None


def parse_scope_challenge(www_authenticate: str) -> ScopeChallenge | None:
    """Parse a WWW-Authenticate header for scope challenge info.

    Example header:
        Bearer scope="db:delete" error="insufficient_scope"
    """
    if "insufficient_scope" not in www_authenticate:
        return None

    scope = ""
    error = "insufficient_scope"
    realm = ""

    # Parse key="value" pairs
    parts = www_authenticate.split()
    for part in parts:
        if "=" in part:
            key, _, value = part.partition("=")
            key = key.strip().rstrip(",")
            value = value.strip().strip('"').rstrip(",").strip('"')
            if key == "scope":
                scope = value
            elif key == "error":
                error = value
            elif key == "realm":
                realm = value

    if not scope:
        return None

    return ScopeChallenge(required_scope=scope, error=error, realm=realm)


class ScopeChallengeHandler:
    """Automatic scope challenge detection and step-up flow for MCP clients.

    Usage:
        handler = ScopeChallengeHandler(
            server_url="http://localhost:8000",
            hitl_scopes=["db:delete", "bank:transfer"],
        )

        # After receiving a 403 from an MCP server:
        if handler.is_scope_challenge(response):
            result = await handler.handle_challenge(
                response=response,
                agent_id="agent:my-agent",
                resource="https://mcp-server.example.com",
            )
            if result and result.step_up_token:
                # Retry with step-up token
                ...
    """

    def __init__(
        self,
        server_url: str,
        hitl_scopes: list[str] | None = None,
        *,
        poll_interval: float = 2.0,
        timeout: float = 300.0,
        http_timeout: float = 30.0,
    ):
        self._server_url = server_url.rstrip("/")
        self._hitl_scopes = set(hitl_scopes or [])
        self._poll_interval = poll_interval
        self._timeout = timeout
        self._http_timeout = http_timeout

    def is_scope_challenge(self, response: httpx.Response) -> bool:
        """Check if an HTTP response is a scope challenge requiring step-up."""
        if response.status_code != 403:
            return False
        www_auth = response.headers.get("WWW-Authenticate", "")
        challenge = parse_scope_challenge(www_auth)
        if not challenge:
            return False
        # Only trigger HITL if the scope is in the configured list
        return self._is_hitl_scope(challenge.required_scope)

    def _is_hitl_scope(self, scope: str) -> bool:
        """Check if any of the requested scopes are in the HITL list."""
        if not self._hitl_scopes:
            return False
        for s in scope.split():
            if s in self._hitl_scopes:
                return True
        return False

    async def handle_challenge(
        self,
        response: httpx.Response,
        agent_id: str,
        resource: str | None = None,
        delegation_chain: list[dict] | None = None,
        access_token: str | None = None,
    ) -> StepUpResult | None:
        """Handle a 403 scope challenge by initiating and polling a step-up request.

        Returns StepUpResult with the step_up_token on success.
        Raises StepUpDeniedError if denied, StepUpTimeoutError if timed out.
        Returns None if the response is not a scope challenge.
        """
        www_auth = response.headers.get("WWW-Authenticate", "")
        challenge = parse_scope_challenge(www_auth)
        if not challenge:
            return None

        # 1. POST /stepup to initiate step-up request
        headers: dict[str, str] = {"Content-Type": "application/json"}
        if access_token:
            headers["Authorization"] = f"Bearer {access_token}"

        stepup_payload = {
            "agent_id": agent_id,
            "action": "scope_escalation",
            "scope": challenge.required_scope,
            "resource": resource or "",
        }
        if delegation_chain:
            stepup_payload["delegation_chain_snapshot"] = delegation_chain

        async with httpx.AsyncClient(timeout=self._http_timeout) as client:
            resp = await client.post(
                f"{self._server_url}/stepup",
                json=stepup_payload,
                headers=headers,
            )
            if resp.status_code not in (200, 201, 202):
                raise AuthgentError(
                    f"Step-up request failed: {resp.status_code} {resp.text}"
                )
            data = resp.json()
            stepup_id = data["id"]

        # 2. Poll for approval
        elapsed = 0.0
        while elapsed < self._timeout:
            await asyncio.sleep(self._poll_interval)
            elapsed += self._poll_interval

            async with httpx.AsyncClient(timeout=self._http_timeout) as client:
                poll_resp = await client.get(
                    f"{self._server_url}/stepup/{stepup_id}",
                    headers=headers,
                )
                if poll_resp.status_code != 200:
                    continue
                poll_data = poll_resp.json()

            status = poll_data.get("status", "pending")

            if status == "approved":
                return StepUpResult(
                    stepup_id=stepup_id,
                    status="approved",
                    step_up_token=poll_data.get("step_up_token"),
                )
            elif status == "denied":
                raise StepUpDeniedError(f"Step-up request {stepup_id} was denied")
            elif status == "expired":
                raise StepUpTimeoutError(f"Step-up request {stepup_id} expired")
            # else: still pending, continue polling

        raise StepUpTimeoutError(
            f"Step-up request {stepup_id} timed out after {self._timeout}s"
        )
