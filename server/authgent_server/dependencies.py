"""FastAPI Depends() injection — service and provider wiring."""

from __future__ import annotations

import importlib
from collections.abc import AsyncGenerator
from dataclasses import dataclass
from typing import Any

from fastapi import Depends, Request
from sqlalchemy.ext.asyncio import AsyncSession

from authgent_server.config import Settings, get_settings
from authgent_server.db import get_db as _get_db
from authgent_server.providers.attestation import NullAttestationProvider
from authgent_server.providers.events import DatabaseEventEmitter
from authgent_server.providers.hitl import WebhookHITLProvider
from authgent_server.providers.keys import DatabaseKeyProvider
from authgent_server.providers.policy import ScopePolicyProvider
from authgent_server.providers.protocols import (
    AttestationProvider,
    ClaimEnricher,
    EventEmitter,
    HITLProvider,
    KeyProvider,
    PolicyProvider,
)
from authgent_server.services.agent_service import AgentService
from authgent_server.services.audit_service import AuditService
from authgent_server.services.client_service import ClientService
from authgent_server.services.consent_service import ConsentService
from authgent_server.services.delegation_service import DelegationService
from authgent_server.services.dpop_service import DPoPService
from authgent_server.services.jwks_service import JWKSService
from authgent_server.services.stepup_service import StepUpService
from authgent_server.services.token_service import TokenService


@dataclass(frozen=True)
class ProviderSet:
    attestation: AttestationProvider
    policy: PolicyProvider
    hitl: HITLProvider
    keys: KeyProvider
    events: EventEmitter
    claim_enricher: ClaimEnricher | None = None


def _import_class(dotted_path: str) -> type:
    module_path, class_name = dotted_path.rsplit(".", 1)
    module = importlib.import_module(module_path)
    return getattr(module, class_name)


def _load_provider(dotted_path: str | None, default: type, settings: Settings) -> Any:
    cls = default if not dotted_path else _import_class(dotted_path)
    if hasattr(cls, "from_settings"):
        return cls.from_settings(settings)
    try:
        return cls(settings)
    except TypeError:
        return cls()


_providers: ProviderSet | None = None


def get_providers(settings: Settings | None = None) -> ProviderSet:
    global _providers
    if _providers is not None:
        return _providers

    if settings is None:
        settings = get_settings()

    enricher = None
    if settings.claim_enricher:
        enricher = _load_provider(settings.claim_enricher, type(None), settings)

    _providers = ProviderSet(
        attestation=_load_provider(settings.attestation_provider, NullAttestationProvider, settings),
        policy=_load_provider(settings.policy_provider, ScopePolicyProvider, settings),
        hitl=_load_provider(settings.hitl_provider, WebhookHITLProvider, settings),
        keys=_load_provider(settings.key_provider, DatabaseKeyProvider, settings),
        events=_load_provider(settings.event_emitter, DatabaseEventEmitter, settings),
        claim_enricher=enricher,
    )
    return _providers


def reset_providers() -> None:
    global _providers
    _providers = None


# --- FastAPI dependency functions ---

async def get_db_session(request: Request) -> AsyncGenerator[AsyncSession, None]:
    settings = get_settings()
    async for session in _get_db(settings):
        yield session


def get_jwks_service() -> JWKSService:
    return JWKSService(get_settings())


def get_audit_service() -> AuditService:
    providers = get_providers()
    return AuditService(emitter=providers.events)


def get_client_service() -> ClientService:
    return ClientService(get_settings())


def get_consent_service() -> ConsentService:
    return ConsentService()


def get_dpop_service() -> DPoPService:
    return DPoPService(get_settings())


def get_delegation_service() -> DelegationService:
    return DelegationService(get_settings())


def get_agent_service() -> AgentService:
    return AgentService(get_settings(), get_client_service())


def get_stepup_service() -> StepUpService:
    return StepUpService(get_settings())


def get_token_service() -> TokenService:
    providers = get_providers()
    return TokenService(
        settings=get_settings(),
        jwks=get_jwks_service(),
        delegation=get_delegation_service(),
        audit=get_audit_service(),
        claim_enricher=providers.claim_enricher,
    )
