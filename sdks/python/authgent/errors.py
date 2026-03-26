"""SDK error hierarchy."""


class AuthgentError(Exception):
    """Base error for all authgent SDK errors."""

    error_code: str = "authgent_error"

    def __init__(self, message: str, error_code: str | None = None):
        self.message = message
        if error_code:
            self.error_code = error_code
        super().__init__(message)


class InvalidTokenError(AuthgentError):
    """Token verification failed."""
    error_code = "invalid_token"


class DelegationError(AuthgentError):
    """Delegation chain validation failed."""
    error_code = "delegation_error"


class DPoPError(AuthgentError):
    """DPoP proof verification failed."""
    error_code = "dpop_error"


class ServerError(AuthgentError):
    """Server communication error."""
    error_code = "server_error"


class InsufficientScopeError(AuthgentError):
    """Required scopes not present in token."""
    error_code = "insufficient_scope"
