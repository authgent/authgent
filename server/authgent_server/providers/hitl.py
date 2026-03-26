"""Default HITL provider — webhook-based human approval."""

from __future__ import annotations

import structlog

from authgent_server.providers.protocols import ApprovalStatus, DelegationChain

logger = structlog.get_logger()


class WebhookHITLProvider:
    """Sends approval requests via HTTP POST webhook.
    In v1, logs the request. Full webhook delivery ships in Phase 5."""

    async def request_approval(
        self,
        agent_id: str,
        action: str,
        resource: str,
        delegation_chain: DelegationChain,
        context: dict,
    ) -> str:
        # In production, this sends an HTTP POST to the configured webhook URL
        logger.info(
            "hitl_approval_requested",
            agent_id=agent_id,
            action=action,
            resource=resource,
        )
        # Return a placeholder — full implementation in Phase 5
        return "pending"

    async def check_approval(self, approval_request_id: str) -> ApprovalStatus:
        return ApprovalStatus(status="pending")
