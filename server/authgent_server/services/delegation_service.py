"""Delegation service — act claim nesting, receipts, chain validation."""

from __future__ import annotations

import hashlib
import json

import structlog

from authgent_server.config import Settings
from authgent_server.errors import (
    DelegationDepthExceeded,
    MayActViolation,
    ScopeEscalation,
)
from authgent_server.providers.protocols import DelegationChain

logger = structlog.get_logger()


class DelegationService:
    def __init__(self, settings: Settings):
        self._settings = settings

    def build_delegated_claims(
        self,
        parent_claims: dict,
        actor_id: str,
        target_audience: str,
        requested_scopes: list[str],
    ) -> dict:
        """Build claims for a delegated token.

        Enforces: depth limit, scope reduction, may_act authorization.
        Returns claims dict for the new token.
        """
        # 1. Check delegation depth
        current_depth = self._get_chain_depth(parent_claims)
        if current_depth >= self._settings.max_delegation_depth:
            raise DelegationDepthExceeded(
                f"Delegation depth {current_depth + 1} exceeds "
                f"max {self._settings.max_delegation_depth}"
            )

        # 2. Enforce scope reduction
        if self._settings.delegation_scope_reduction:
            parent_scopes = set((parent_claims.get("scope", "")).split())
            requested = set(requested_scopes)
            if parent_scopes and not requested.issubset(parent_scopes):
                escalated = requested - parent_scopes
                raise ScopeEscalation(
                    f"Downstream scopes exceed parent: {', '.join(escalated)}"
                )

        # 3. Check may_act authorization
        may_act = parent_claims.get("may_act")
        if may_act and isinstance(may_act, dict):
            allowed_subs = may_act.get("sub", [])
            if isinstance(allowed_subs, list) and actor_id not in allowed_subs:
                raise MayActViolation(
                    f"Actor '{actor_id}' not in may_act.sub: {allowed_subs}"
                )

        # 4. Build nested act claims
        new_act = {"sub": actor_id}
        existing_act = parent_claims.get("act")
        if existing_act:
            new_act["act"] = existing_act

        # 5. Build delegation claims
        claims = {
            "sub": parent_claims.get("sub"),
            "aud": target_audience,
            "scope": " ".join(requested_scopes),
            "act": new_act,
        }

        # 6. Carry forward OIDC-A claims from parent
        for key in ("agent_type", "agent_model", "agent_version",
                     "agent_provider", "agent_instance_id"):
            if key in parent_claims:
                claims[key] = parent_claims[key]

        return claims

    def compute_chain_hash(self, claims: dict) -> str:
        """Compute SHA-256 hash of the delegation chain for receipt verification."""
        chain = self._extract_chain(claims)
        canonical = json.dumps(chain, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical.encode()).hexdigest()

    def verify_chain(
        self,
        claims: dict,
        max_depth: int | None = None,
        require_human_root: bool = False,
        allowed_actors: list[str] | None = None,
    ) -> DelegationChain:
        """Parse and validate act claim nesting."""
        if max_depth is None:
            max_depth = self._settings.max_delegation_depth

        chain = self._extract_chain(claims)
        depth = len(chain)

        if depth > max_depth:
            raise DelegationDepthExceeded(
                f"Chain depth {depth} exceeds max {max_depth}"
            )

        human_root = False
        if chain:
            root_sub = chain[-1].get("sub", "")
            human_root = root_sub.startswith("user:")

        if require_human_root and not human_root and depth > 0:
            raise MayActViolation("Delegation chain must have a human root")

        if allowed_actors:
            for actor in chain:
                if actor.get("sub") not in allowed_actors:
                    raise MayActViolation(
                        f"Actor '{actor.get('sub')}' not in allowed actors"
                    )

        return DelegationChain(
            actors=chain,
            depth=depth,
            human_root=human_root,
        )

    @staticmethod
    def _extract_chain(claims: dict) -> list[dict]:
        """Extract flat list of actors from nested act claims."""
        chain = []
        act = claims.get("act")
        while act and isinstance(act, dict):
            chain.append({"sub": act.get("sub", "")})
            act = act.get("act")
        return chain

    @staticmethod
    def _get_chain_depth(claims: dict) -> int:
        """Count the current delegation depth."""
        depth = 0
        act = claims.get("act")
        while act and isinstance(act, dict):
            depth += 1
            act = act.get("act")
        return depth
