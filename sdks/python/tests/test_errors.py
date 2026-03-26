"""Tests for SDK error hierarchy."""

from authgent.errors import (
    AuthgentError,
    DelegationError,
    DPoPError,
    InsufficientScopeError,
    InvalidTokenError,
    ServerError,
)


def test_error_hierarchy():
    assert issubclass(InvalidTokenError, AuthgentError)
    assert issubclass(DelegationError, AuthgentError)
    assert issubclass(DPoPError, AuthgentError)
    assert issubclass(ServerError, AuthgentError)
    assert issubclass(InsufficientScopeError, AuthgentError)


def test_error_codes():
    assert InvalidTokenError("test").error_code == "invalid_token"
    assert DelegationError("test").error_code == "delegation_error"
    assert DPoPError("test").error_code == "dpop_error"
    assert ServerError("test").error_code == "server_error"
    assert InsufficientScopeError("test").error_code == "insufficient_scope"


def test_error_custom_code():
    err = DelegationError("too deep", error_code="delegation_depth_exceeded")
    assert err.error_code == "delegation_depth_exceeded"
    assert str(err) == "too deep"
