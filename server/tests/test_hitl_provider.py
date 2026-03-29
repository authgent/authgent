"""Unit tests for WebhookHITLProvider."""

import pytest


@pytest.mark.asyncio
async def test_webhook_hitl_log_only_mode() -> None:
    """WebhookHITLProvider without URL should work in log-only mode."""
    from authgent_server.providers.hitl import WebhookHITLProvider
    from authgent_server.providers.protocols import DelegationChain

    provider = WebhookHITLProvider()
    request_id = await provider.request_approval(
        agent_id="test-agent",
        action="read_data",
        resource="https://api.example.com/data",
        delegation_chain=DelegationChain(),
        context={"reason": "needs access"},
    )
    assert request_id.startswith("hitl_")


@pytest.mark.asyncio
async def test_webhook_hitl_from_settings() -> None:
    """WebhookHITLProvider.from_settings should pick up config."""
    from authgent_server.providers.hitl import WebhookHITLProvider

    class FakeSettings:
        webhook_url = "https://hooks.example.com/hitl"
        webhook_hmac_secret = "test-secret"
        webhook_retries = 2
        webhook_backoff = "0.1,0.2"
        provider_timeout = 5

    provider = WebhookHITLProvider.from_settings(FakeSettings())
    assert provider._webhook_url == "https://hooks.example.com/hitl"
    assert provider._hmac_secret == "test-secret"
    assert provider._retries == 2


@pytest.mark.asyncio
async def test_webhook_hitl_hmac_signature() -> None:
    """WebhookHITLProvider should compute HMAC-SHA256 signatures."""
    from authgent_server.providers.hitl import WebhookHITLProvider

    provider = WebhookHITLProvider(hmac_secret="my-secret")
    sig = provider._sign_payload(b'{"test": true}')
    assert len(sig) == 64  # SHA-256 hex digest
    assert sig

    # Without secret, signature is empty
    provider2 = WebhookHITLProvider()
    assert provider2._sign_payload(b"anything") == ""
