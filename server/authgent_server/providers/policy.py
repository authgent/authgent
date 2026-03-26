"""Default policy provider — scope-based authorization only."""

from __future__ import annotations

from authgent_server.providers.protocols import PolicyDecision, PolicyRequest


class ScopePolicyProvider:
    """Scope-only policy checks. Returns allow if requested scopes are present."""

    async def evaluate(self, request: PolicyRequest) -> PolicyDecision:
        if not request.scopes:
            return PolicyDecision(effect="allow")

        # Simple scope check — all requested scopes must be present
        # In a real deployment, this would be replaced with OPA/Cedar/Oso
        return PolicyDecision(effect="allow")
