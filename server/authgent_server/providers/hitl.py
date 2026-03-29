"""Default HITL provider — webhook-based human approval with retry + HMAC signing."""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
from dataclasses import asdict

import httpx
import structlog

from authgent_server.providers.protocols import ApprovalStatus, DelegationChain

logger = structlog.get_logger()


class WebhookHITLProvider:
    """Sends approval requests via HTTP POST webhook with HMAC-SHA256 signing.

    Configuration (via Settings):
      - webhook_url: Target URL for approval requests
      - webhook_hmac_secret: HMAC-SHA256 signing key for payload integrity
      - webhook_retries: Number of retry attempts (default: 3)
      - webhook_backoff: Comma-separated backoff seconds (default: "1,5,30")
    """

    def __init__(
        self,
        webhook_url: str | None = None,
        hmac_secret: str | None = None,
        retries: int = 3,
        backoff: str = "1,5,30",
        timeout: float = 10.0,
    ):
        self._webhook_url = webhook_url
        self._hmac_secret = hmac_secret
        self._retries = retries
        self._backoff = [float(s.strip()) for s in backoff.split(",")]
        self._timeout = timeout

    @classmethod
    def from_settings(cls, settings: object) -> WebhookHITLProvider:
        """Factory used by the provider loader — reads config from Settings."""
        return cls(
            webhook_url=getattr(settings, "webhook_url", None),
            hmac_secret=getattr(settings, "webhook_hmac_secret", None),
            retries=getattr(settings, "webhook_retries", 3),
            backoff=getattr(settings, "webhook_backoff", "1,5,30"),
            timeout=float(getattr(settings, "provider_timeout", 10)),
        )

    def _sign_payload(self, body: bytes) -> str:
        """Compute HMAC-SHA256 signature for webhook payload integrity."""
        if not self._hmac_secret:
            return ""
        return hmac.new(
            self._hmac_secret.encode(),
            body,
            hashlib.sha256,
        ).hexdigest()

    async def request_approval(
        self,
        agent_id: str,
        action: str,
        resource: str,
        delegation_chain: DelegationChain,
        context: dict,
    ) -> str:
        request_id = f"hitl_{secrets.token_urlsafe(16)}"

        payload = {
            "id": request_id,
            "type": "stepup_approval_request",
            "agent_id": agent_id,
            "action": action,
            "resource": resource,
            "delegation_chain": asdict(delegation_chain),
            "context": context,
        }

        # If no webhook URL configured, fall back to log-only mode
        if not self._webhook_url:
            logger.info(
                "hitl_approval_requested",
                request_id=request_id,
                agent_id=agent_id,
                action=action,
                resource=resource,
                mode="log_only",
            )
            return request_id

        # Deliver webhook with retries
        body = json.dumps(payload, separators=(",", ":")).encode()
        signature = self._sign_payload(body)

        headers: dict[str, str] = {
            "Content-Type": "application/json",
            "X-Authgent-Event": "stepup.requested",
            "X-Authgent-Request-ID": request_id,
        }
        if signature:
            headers["X-Authgent-Signature-256"] = f"sha256={signature}"

        delivered = False
        last_error: Exception | None = None

        for attempt in range(self._retries + 1):
            try:
                async with httpx.AsyncClient(timeout=self._timeout) as client:
                    resp = await client.post(
                        self._webhook_url,
                        content=body,
                        headers=headers,
                    )
                    if resp.status_code < 300:
                        delivered = True
                        logger.info(
                            "hitl_webhook_delivered",
                            request_id=request_id,
                            status_code=resp.status_code,
                            attempt=attempt + 1,
                        )
                        break
                    else:
                        last_error = Exception(f"HTTP {resp.status_code}: {resp.text[:200]}")
                        logger.warning(
                            "hitl_webhook_http_error",
                            request_id=request_id,
                            status_code=resp.status_code,
                            attempt=attempt + 1,
                        )
            except Exception as e:
                last_error = e
                logger.warning(
                    "hitl_webhook_failed",
                    request_id=request_id,
                    error=str(e),
                    attempt=attempt + 1,
                )

            # Backoff before retry
            if attempt < self._retries:
                import asyncio

                backoff_secs = (
                    self._backoff[attempt]
                    if attempt < len(self._backoff)
                    else self._backoff[-1]
                )
                await asyncio.sleep(backoff_secs)

        if not delivered:
            logger.error(
                "hitl_webhook_exhausted",
                request_id=request_id,
                retries=self._retries,
                last_error=str(last_error),
            )

        return request_id

    async def check_approval(self, approval_request_id: str) -> ApprovalStatus:
        return ApprovalStatus(status="pending")
