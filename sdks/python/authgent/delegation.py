"""Delegation chain parsing and validation."""

from __future__ import annotations

from authgent.errors import DelegationError
from authgent.models import DelegationChain


def verify_delegation_chain(
    chain: DelegationChain,
    max_depth: int = 5,
    allowed_actors: list[str] | None = None,
    require_human_root: bool = False,
) -> DelegationChain:
    """Enforce delegation chain policy.

    Args:
        chain: The delegation chain from a verified token.
        max_depth: Maximum allowed delegation depth.
        allowed_actors: If set, all actors must be in this list.
        require_human_root: If True, the chain root must be a human (user:*).

    Returns:
        The validated DelegationChain.

    Raises:
        DelegationError: If validation fails.
    """
    if chain.depth > max_depth:
        raise DelegationError(
            f"Delegation chain depth {chain.depth} exceeds maximum {max_depth}",
            error_code="delegation_depth_exceeded",
        )

    if require_human_root and chain.depth > 0 and not chain.human_root:
        raise DelegationError(
            "Delegation chain must have a human root",
            error_code="no_human_root",
        )

    if allowed_actors:
        for actor in chain.actors:
            sub = actor.get("sub", "")
            if sub not in allowed_actors:
                raise DelegationError(
                    f"Actor '{sub}' is not in the allowed actors list",
                    error_code="unauthorized_actor",
                )

    return chain
