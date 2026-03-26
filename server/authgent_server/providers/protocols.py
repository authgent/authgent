"""Protocol definitions for all 5+2 pluggable provider interfaces."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable


@dataclass
class AttestationResult:
    valid: bool
    level: str = "none"  # none|self|verified|hardware
    claims: dict = field(default_factory=dict)


@dataclass
class PolicyRequest:
    agent_id: str
    scopes: list[str]
    action: str
    resource: str
    delegation_chain: list[dict] = field(default_factory=list)
    attestation_claims: dict = field(default_factory=dict)
    context: dict = field(default_factory=dict)


@dataclass
class PolicyDecision:
    effect: str  # allow|deny|step_up
    reason: str = ""


@dataclass
class ApprovalStatus:
    status: str  # pending|approved|denied|expired
    approved_by: str | None = None


@dataclass
class AuditEvent:
    action: str
    actor: str | None = None
    subject: str | None = None
    client_id: str | None = None
    ip_address: str | None = None
    trace_id: str | None = None
    span_id: str | None = None
    metadata: dict = field(default_factory=dict)


@dataclass
class DelegationChain:
    actors: list[dict] = field(default_factory=list)
    depth: int = 0
    human_root: bool = False


@dataclass
class HumanIdentity:
    user_id: str
    username: str
    email: str | None = None


@runtime_checkable
class AttestationProvider(Protocol):
    async def attest(self, agent_id: str, evidence: dict) -> AttestationResult: ...
    async def get_attestation_claims(self, agent_id: str) -> dict: ...


@runtime_checkable
class PolicyProvider(Protocol):
    async def evaluate(self, request: PolicyRequest) -> PolicyDecision: ...


@runtime_checkable
class HITLProvider(Protocol):
    async def request_approval(
        self,
        agent_id: str,
        action: str,
        resource: str,
        delegation_chain: DelegationChain,
        context: dict,
    ) -> str: ...

    async def check_approval(self, approval_request_id: str) -> ApprovalStatus: ...


@runtime_checkable
class KeyProvider(Protocol):
    async def get_signing_key(self) -> dict: ...
    async def get_verification_keys(self) -> list[dict]: ...


@runtime_checkable
class EventEmitter(Protocol):
    async def emit(self, event: AuditEvent) -> None: ...


@runtime_checkable
class ClaimEnricher(Protocol):
    async def enrich(
        self,
        base_claims: dict,
        client_id: str,
        agent_id: str | None,
        grant_type: str,
    ) -> dict: ...


@runtime_checkable
class HumanAuthProvider(Protocol):
    async def authenticate(self, request: object) -> HumanIdentity | None: ...
    async def login_redirect(self, request: object, next_url: str) -> object: ...
    async def handle_callback(self, request: object) -> HumanIdentity: ...
