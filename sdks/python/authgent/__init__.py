"""authgent SDK — token validation, delegation chains, DPoP for AI agents."""

from authgent.verify import verify_token
from authgent.delegation import verify_delegation_chain
from authgent.dpop import verify_dpop_proof, DPoPClient
from authgent.client import AgentAuthClient
from authgent.models import AgentIdentity, DelegationChain, TokenClaims
from authgent.errors import (
    AuthgentError,
    InvalidTokenError,
    DelegationError,
    DPoPError,
    ServerError,
)

__version__ = "0.1.0"

__all__ = [
    "verify_token",
    "verify_delegation_chain",
    "verify_dpop_proof",
    "DPoPClient",
    "AgentAuthClient",
    "AgentIdentity",
    "DelegationChain",
    "TokenClaims",
    "AuthgentError",
    "InvalidTokenError",
    "DelegationError",
    "DPoPError",
    "ServerError",
]
