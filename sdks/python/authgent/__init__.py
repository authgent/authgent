"""authgent SDK — IETF agent-identity reference client.

Implements client helpers for:

- draft-ietf-oauth-identity-chaining-14 (cross-domain delegation):
  ``AgentAuthClient.start_identity_chain``,
  ``AgentAuthClient.consume_identity_chain``.
- draft-ietf-oauth-transaction-tokens-08 (intra-domain transaction
  context propagation): ``AgentAuthClient.issue_transaction_token``.
- RFC 8693 Token Exchange with nested ``act`` chains:
  ``AgentAuthClient.exchange_token``.
- RFC 9449 DPoP: ``DPoPClient`` and ``verify_dpop_proof``.
- Token validation against authgent's JWKS: ``verify_token``,
  ``verify_delegation_chain``.

See <https://github.com/authgent/authgent> and
<https://github.com/authgent/authgent/blob/main/STANDARDS.md>.
"""

from authgent.client import AgentAuthClient
from authgent.delegation import verify_delegation_chain
from authgent.dpop import DPoPClient, verify_dpop_proof
from authgent.errors import (
    AuthgentError,
    DelegationError,
    DPoPError,
    InvalidTokenError,
    ServerError,
)
from authgent.models import AgentIdentity, DelegationChain, TokenClaims
from authgent.verify import verify_token

__version__ = "0.3.4"

__all__ = [
    "AgentAuthClient",
    "AgentIdentity",
    "AuthgentError",
    "DPoPClient",
    "DPoPError",
    "DelegationChain",
    "DelegationError",
    "InvalidTokenError",
    "ServerError",
    "TokenClaims",
    "verify_delegation_chain",
    "verify_dpop_proof",
    "verify_token",
]
