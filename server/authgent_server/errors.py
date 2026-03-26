"""Error hierarchy — RFC 9457 Problem Details + OAuth error codes."""

from __future__ import annotations


class AuthgentError(Exception):
    """Base error for all authgent errors."""

    type_uri: str = "https://authgent.dev/errors/server-error"
    status_code: int = 500
    title: str = "Server Error"
    error_code: str = "server_error"

    def __init__(self, detail: str | None = None, **kwargs: object):
        self.detail = detail or self.title
        self.extra = kwargs
        super().__init__(self.detail)

    def to_problem_detail(self, instance: str = "") -> dict:
        """Return RFC 9457 Problem Details JSON."""
        return {
            "type": self.type_uri,
            "title": self.title,
            "status": self.status_code,
            "detail": self.detail,
            "instance": instance,
            "error_code": self.error_code,
            **self.extra,
        }

    def to_oauth_error(self) -> dict:
        """Return RFC 6749 §5.2 error response for /token endpoint."""
        return {
            "error": self.error_code,
            "error_description": self.detail,
        }


class InvalidGrant(AuthgentError):
    type_uri = "https://authgent.dev/errors/invalid-grant"
    status_code = 400
    title = "Invalid Grant"
    error_code = "invalid_grant"


class InvalidClient(AuthgentError):
    type_uri = "https://authgent.dev/errors/invalid-client"
    status_code = 401
    title = "Invalid Client"
    error_code = "invalid_client"


class InsufficientScope(AuthgentError):
    type_uri = "https://authgent.dev/errors/insufficient-scope"
    status_code = 403
    title = "Insufficient Scope"
    error_code = "insufficient_scope"


class InvalidRequest(AuthgentError):
    type_uri = "https://authgent.dev/errors/invalid-request"
    status_code = 400
    title = "Invalid Request"
    error_code = "invalid_request"


class UnsupportedGrantType(AuthgentError):
    type_uri = "https://authgent.dev/errors/unsupported-grant-type"
    status_code = 400
    title = "Unsupported Grant Type"
    error_code = "unsupported_grant_type"


class InvalidDPoPProof(AuthgentError):
    type_uri = "https://authgent.dev/errors/invalid-dpop-proof"
    status_code = 401
    title = "Invalid DPoP Proof"
    error_code = "invalid_dpop_proof"


class UseDPoPNonce(AuthgentError):
    type_uri = "https://authgent.dev/errors/use-dpop-nonce"
    status_code = 401
    title = "Use DPoP Nonce"
    error_code = "use_dpop_nonce"

    def __init__(self, nonce: str, **kwargs: object):
        self.dpop_nonce = nonce
        super().__init__(detail="DPoP nonce required or expired", **kwargs)


class DelegationDepthExceeded(AuthgentError):
    type_uri = "https://authgent.dev/errors/delegation-depth-exceeded"
    status_code = 403
    title = "Delegation Depth Exceeded"
    error_code = "delegation_depth_exceeded"


class ScopeEscalation(AuthgentError):
    type_uri = "https://authgent.dev/errors/scope-escalation"
    status_code = 403
    title = "Scope Escalation"
    error_code = "scope_escalation"


class MayActViolation(AuthgentError):
    type_uri = "https://authgent.dev/errors/may-act-violation"
    status_code = 403
    title = "May Act Violation"
    error_code = "may_act_violation"


class TokenRevoked(AuthgentError):
    type_uri = "https://authgent.dev/errors/token-revoked"
    status_code = 401
    title = "Token Revoked"
    error_code = "token_revoked"


class StepUpRequired(AuthgentError):
    type_uri = "https://authgent.dev/errors/step-up-required"
    status_code = 403
    title = "Step-Up Required"
    error_code = "step_up_required"


class AgentNotFound(AuthgentError):
    type_uri = "https://authgent.dev/errors/agent-not-found"
    status_code = 404
    title = "Agent Not Found"
    error_code = "agent_not_found"


class AccessDenied(AuthgentError):
    type_uri = "https://authgent.dev/errors/access-denied"
    status_code = 403
    title = "Access Denied"
    error_code = "access_denied"
