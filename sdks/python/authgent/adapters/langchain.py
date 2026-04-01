"""LangChain adapter — plug authgent into LangChain tool/agent pipelines.

Provides:
- AuthgentToolWrapper: wraps any LangChain tool with automatic token management
- AuthgentCallbackHandler: logs auth events (token refresh, exchange) to LangChain callbacks
- authgent_auth_header: helper to inject Bearer/DPoP headers into HTTP tool calls

Usage:
    from authgent.adapters.langchain import AuthgentToolWrapper
    from langchain_core.tools import Tool

    wrapper = AuthgentToolWrapper(
        server_url="http://localhost:8000",
        client_id="agnt_xxx",
        client_secret="secret",
        scope="read write",
    )

    # Wrap any tool to auto-inject auth headers
    authed_tool = wrapper.wrap(my_http_tool)

    # Or get headers directly for custom integrations
    headers = await wrapper.get_auth_headers(resource="https://api.example.com")
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

from authgent.client import AgentAuthClient, TokenResult
from authgent.dpop import DPoPClient


@dataclass
class _CachedToken:
    """In-memory token with expiry tracking."""

    token: TokenResult
    acquired_at: float = field(default_factory=time.monotonic)

    def is_expired(self, buffer_seconds: int = 30) -> bool:
        """Check if token is expired or about to expire."""
        elapsed = time.monotonic() - self.acquired_at
        return elapsed >= (self.token.expires_in - buffer_seconds)


class AuthgentToolWrapper:
    """Wraps LangChain tools with automatic authgent token management.

    Handles:
    - Client credentials token acquisition
    - Token caching with automatic refresh
    - Token exchange for downstream resource delegation
    - Optional DPoP proof generation
    """

    def __init__(
        self,
        server_url: str,
        client_id: str,
        client_secret: str,
        *,
        scope: str | None = None,
        resource: str | None = None,
        use_dpop: bool = False,
        token_buffer_seconds: int = 30,
    ):
        self._client = AgentAuthClient(server_url)
        self._client_id = client_id
        self._client_secret = client_secret
        self._scope = scope
        self._resource = resource
        self._use_dpop = use_dpop
        self._buffer = token_buffer_seconds
        self._dpop: DPoPClient | None = DPoPClient() if use_dpop else None
        self._cached: _CachedToken | None = None

    async def get_token(self) -> TokenResult:
        """Get a valid access token, refreshing if needed."""
        if self._cached and not self._cached.is_expired(self._buffer):
            return self._cached.token

        result = await self._client.get_token(
            client_id=self._client_id,
            client_secret=self._client_secret,
            scope=self._scope,
            resource=self._resource,
        )
        self._cached = _CachedToken(token=result)
        return result

    async def exchange_for(
        self,
        audience: str,
        scopes: list[str] | None = None,
    ) -> TokenResult:
        """Exchange the current token for a delegated token targeting a downstream resource."""
        parent = await self.get_token()
        return await self._client.exchange_token(
            subject_token=parent.access_token,
            audience=audience,
            scopes=scopes,
            client_id=self._client_id,
            client_secret=self._client_secret,
        )

    async def get_auth_headers(
        self,
        *,
        resource: str | None = None,
        http_method: str = "GET",
        http_uri: str | None = None,
    ) -> dict[str, str]:
        """Get authorization headers for an HTTP request.

        If resource differs from the configured resource, performs a token exchange.
        If DPoP is enabled, includes DPoP proof header.
        """
        if resource and resource != self._resource:
            token = await self.exchange_for(resource)
        else:
            token = await self.get_token()

        headers: dict[str, str] = {}

        if self._dpop and http_uri:
            proof_headers = self._dpop.create_proof_headers(
                http_method=http_method,
                http_uri=http_uri,
                access_token=token.access_token,
            )
            headers.update(proof_headers)
            headers["Authorization"] = f"DPoP {token.access_token}"
        else:
            headers["Authorization"] = f"Bearer {token.access_token}"

        return headers

    def wrap(self, tool: Any) -> Any:
        """Wrap a LangChain tool to auto-inject auth metadata.  **[Experimental]**

        Returns a new tool that adds `authgent_headers` to the tool's
        kwargs before invocation. The wrapped tool's function should
        accept **kwargs and use `authgent_headers` for HTTP calls.

        .. warning::
            Experimental — tested with ``langchain-core >=0.3``. The exact
            tool interface varies across LangChain versions; please open an
            issue if you encounter incompatibilities.
        """
        # Lazy import to avoid hard dependency on langchain
        try:
            from langchain_core.tools import StructuredTool
        except ImportError:
            raise ImportError(
                "langchain-core is required for tool wrapping. "
                "Install with: pip install langchain-core"
            )

        original_func = tool.func if hasattr(tool, "func") else tool._run
        wrapper_self = self

        async def _authed_func(*args: Any, **kwargs: Any) -> Any:
            headers = await wrapper_self.get_auth_headers()
            kwargs["authgent_headers"] = headers
            if hasattr(original_func, "__call__"):
                return await original_func(*args, **kwargs)
            return original_func(*args, **kwargs)

        return StructuredTool(
            name=getattr(tool, "name", "wrapped_tool"),
            description=getattr(tool, "description", ""),
            coroutine=_authed_func,
            args_schema=getattr(tool, "args_schema", None),
        )

    async def revoke(self) -> None:
        """Revoke the current cached token."""
        if self._cached:
            await self._client.revoke_token(
                self._cached.token.access_token,
                client_id=self._client_id,
                client_secret=self._client_secret,
            )
            self._cached = None


class AuthgentCallbackHandler:
    """LangChain callback handler skeleton for auth event logging.

    Logs token acquisition, refresh, and exchange events. Can be
    extended to integrate with LangChain's callback system.

    Usage:
        from langchain_core.callbacks import CallbackManager
        handler = AuthgentCallbackHandler()
        callback_manager = CallbackManager([handler])
    """

    def __init__(self, *, verbose: bool = False):
        self._verbose = verbose
        self._events: list[dict[str, Any]] = []

    def on_token_acquired(self, token_type: str, scope: str | None) -> None:
        event = {"event": "token_acquired", "token_type": token_type, "scope": scope}
        self._events.append(event)
        if self._verbose:
            print(f"[authgent] Token acquired: type={token_type} scope={scope}")

    def on_token_exchanged(self, audience: str, scope: str | None) -> None:
        event = {"event": "token_exchanged", "audience": audience, "scope": scope}
        self._events.append(event)
        if self._verbose:
            print(f"[authgent] Token exchanged: audience={audience} scope={scope}")

    def on_token_revoked(self) -> None:
        event = {"event": "token_revoked"}
        self._events.append(event)
        if self._verbose:
            print("[authgent] Token revoked")

    @property
    def events(self) -> list[dict[str, Any]]:
        return list(self._events)
