"""Default attestation provider — no-op (identity-only, no attestation)."""

from __future__ import annotations

from authgent_server.providers.protocols import AttestationResult


class NullAttestationProvider:
    """No attestation verification. All agents pass with level='none'."""

    async def attest(self, agent_id: str, evidence: dict) -> AttestationResult:
        return AttestationResult(valid=True, level="none", claims={})

    async def get_attestation_claims(self, agent_id: str) -> dict:
        return {}
