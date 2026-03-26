"""Tests for SDK data models."""

from authgent.models import AgentIdentity, DelegationChain, TokenClaims, _extract_chain


def test_agent_identity_from_claims_simple():
    claims = {
        "sub": "client:agnt_abc",
        "scope": "search:execute tools:read",
        "client_id": "agnt_abc",
        "aud": "https://mcp.example.com",
        "iss": "http://localhost:8000",
        "exp": 9999999999,
        "iat": 1000000000,
        "jti": "tok_xyz",
    }
    identity = AgentIdentity.from_claims(claims)
    assert identity.subject == "client:agnt_abc"
    assert identity.scopes == ["search:execute", "tools:read"]
    assert identity.client_id == "agnt_abc"
    assert identity.audience == "https://mcp.example.com"
    assert identity.delegation_chain.depth == 0
    assert identity.delegation_chain.actors == []


def test_agent_identity_from_claims_with_delegation():
    claims = {
        "sub": "user:alice",
        "scope": "read",
        "act": {
            "sub": "client:agnt_A",
            "act": {
                "sub": "client:agnt_B",
            },
        },
    }
    identity = AgentIdentity.from_claims(claims)
    assert identity.delegation_chain.depth == 2
    assert identity.delegation_chain.actors == [
        {"sub": "client:agnt_A"},
        {"sub": "client:agnt_B"},
    ]
    assert identity.delegation_chain.human_root is False  # root is agnt_B (client:)


def test_agent_identity_from_claims_human_root():
    claims = {
        "sub": "user:alice",
        "scope": "read",
        "act": {
            "sub": "client:agnt_A",
            "act": {
                "sub": "user:bob",
            },
        },
    }
    identity = AgentIdentity.from_claims(claims)
    assert identity.delegation_chain.human_root is True


def test_agent_identity_oidc_a_claims():
    claims = {
        "sub": "client:agnt_abc",
        "scope": "read",
        "agent_type": "ai_assistant",
        "agent_model": "gpt-4o",
        "agent_version": "2025-01",
        "agent_provider": "openai",
        "agent_instance_id": "inst_123",
    }
    identity = AgentIdentity.from_claims(claims)
    assert identity.agent_type == "ai_assistant"
    assert identity.agent_model == "gpt-4o"
    assert identity.agent_version == "2025-01"
    assert identity.agent_provider == "openai"
    assert identity.agent_instance_id == "inst_123"


def test_delegation_chain_has_actor():
    chain = DelegationChain(
        actors=[{"sub": "client:agnt_A"}, {"sub": "client:agnt_B"}],
        depth=2,
    )
    assert chain.has_actor("client:agnt_A") is True
    assert chain.has_actor("client:agnt_C") is False


def test_token_claims_wrapper():
    tc = TokenClaims(raw={"jti": "tok_1", "exp": 999, "iat": 100, "foo": "bar"})
    assert tc.jti == "tok_1"
    assert tc.exp == 999
    assert tc.iat == 100
    assert tc.get("foo") == "bar"
    assert tc.get("missing", "default") == "default"


def test_extract_chain_no_act():
    assert _extract_chain({}) == DelegationChain()


def test_extract_chain_deep():
    claims = {
        "act": {
            "sub": "A",
            "act": {"sub": "B", "act": {"sub": "C"}},
        }
    }
    chain = _extract_chain(claims)
    assert chain.depth == 3
    assert [a["sub"] for a in chain.actors] == ["A", "B", "C"]
