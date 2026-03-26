"""SDK data models — AgentIdentity, DelegationChain, TokenClaims."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class DelegationChain:
    """Parsed delegation chain from nested act claims."""

    actors: list[dict] = field(default_factory=list)
    depth: int = 0
    human_root: bool = False

    def has_actor(self, sub: str) -> bool:
        return any(a.get("sub") == sub for a in self.actors)


@dataclass
class TokenClaims:
    """Raw token claims wrapper."""

    raw: dict = field(default_factory=dict)

    def get(self, key: str, default: object = None) -> object:
        return self.raw.get(key, default)

    @property
    def jti(self) -> str | None:
        return self.raw.get("jti")

    @property
    def exp(self) -> int | None:
        return self.raw.get("exp")

    @property
    def iat(self) -> int | None:
        return self.raw.get("iat")


@dataclass
class AgentIdentity:
    """Verified agent identity — attached to request context by middleware."""

    subject: str
    scopes: list[str]
    delegation_chain: DelegationChain
    claims: TokenClaims
    client_id: str | None = None
    audience: str | None = None

    # OIDC-A claims (optional)
    agent_type: str | None = None
    agent_model: str | None = None
    agent_version: str | None = None
    agent_provider: str | None = None
    agent_instance_id: str | None = None

    @classmethod
    def from_claims(cls, claims: dict) -> AgentIdentity:
        """Build AgentIdentity from decoded JWT claims."""
        # Parse delegation chain
        chain = _extract_chain(claims)

        scope_str = claims.get("scope", "")
        scopes = scope_str.split() if scope_str else []

        return cls(
            subject=claims.get("sub", ""),
            scopes=scopes,
            delegation_chain=chain,
            claims=TokenClaims(raw=claims),
            client_id=claims.get("client_id"),
            audience=claims.get("aud"),
            agent_type=claims.get("agent_type"),
            agent_model=claims.get("agent_model"),
            agent_version=claims.get("agent_version"),
            agent_provider=claims.get("agent_provider"),
            agent_instance_id=claims.get("agent_instance_id"),
        )


def _extract_chain(claims: dict) -> DelegationChain:
    """Extract flat list of actors from nested act claims."""
    actors: list[dict] = []
    act = claims.get("act")
    while act and isinstance(act, dict):
        actors.append({"sub": act.get("sub", "")})
        act = act.get("act")

    depth = len(actors)
    human_root = False
    if actors:
        root_sub = actors[-1].get("sub", "")
        human_root = root_sub.startswith("user:")

    return DelegationChain(actors=actors, depth=depth, human_root=human_root)
