"""Tests for SDK delegation chain verification."""

import pytest

from authgent.delegation import verify_delegation_chain
from authgent.errors import DelegationError
from authgent.models import DelegationChain


def test_verify_delegation_chain_valid():
    chain = DelegationChain(actors=[{"sub": "client:agnt_A"}], depth=1)
    result = verify_delegation_chain(chain, max_depth=5)
    assert result.depth == 1


def test_verify_delegation_chain_depth_exceeded():
    chain = DelegationChain(
        actors=[{"sub": f"agent_{i}"} for i in range(6)],
        depth=6,
    )
    with pytest.raises(DelegationError, match="exceeds maximum"):
        verify_delegation_chain(chain, max_depth=5)


def test_verify_delegation_chain_require_human_root():
    chain = DelegationChain(
        actors=[{"sub": "client:agnt_A"}, {"sub": "user:alice"}],
        depth=2,
        human_root=True,
    )
    # Human root present — should pass
    result = verify_delegation_chain(chain, require_human_root=True)
    assert result.human_root is True


def test_verify_delegation_chain_no_human_root():
    chain = DelegationChain(
        actors=[{"sub": "client:agnt_A"}, {"sub": "client:agnt_B"}],
        depth=2,
        human_root=False,
    )
    with pytest.raises(DelegationError, match="human root"):
        verify_delegation_chain(chain, require_human_root=True)


def test_verify_delegation_chain_allowed_actors():
    chain = DelegationChain(
        actors=[{"sub": "client:agnt_A"}, {"sub": "client:agnt_B"}],
        depth=2,
    )
    # All actors allowed
    result = verify_delegation_chain(
        chain, allowed_actors=["client:agnt_A", "client:agnt_B"]
    )
    assert result.depth == 2


def test_verify_delegation_chain_unauthorized_actor():
    chain = DelegationChain(
        actors=[{"sub": "client:agnt_A"}, {"sub": "client:agnt_EVIL"}],
        depth=2,
    )
    with pytest.raises(DelegationError, match="not in the allowed actors"):
        verify_delegation_chain(chain, allowed_actors=["client:agnt_A"])


def test_verify_empty_chain():
    chain = DelegationChain(actors=[], depth=0)
    result = verify_delegation_chain(chain)
    assert result.depth == 0
