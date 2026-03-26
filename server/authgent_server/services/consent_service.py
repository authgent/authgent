"""Consent service — tracks human consent grants for auth code flow."""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from authgent_server.models.consent import Consent
from authgent_server.utils import is_expired, utcnow


class ConsentService:
    async def check_existing_consent(
        self, db: AsyncSession, subject: str, client_id: str, resource: str | None
    ) -> Consent | None:
        """Check if consent already granted for this subject/client/resource."""
        stmt = select(Consent).where(
            Consent.subject == subject,
            Consent.client_id == client_id,
        )
        if resource:
            stmt = stmt.where(Consent.resource == resource)
        result = await db.execute(stmt)
        consent = result.scalar_one_or_none()

        if consent and consent.expires_at and is_expired(consent.expires_at):
            return None
        return consent

    async def grant_consent(
        self,
        db: AsyncSession,
        subject: str,
        client_id: str,
        scope: str,
        resource: str | None = None,
    ) -> Consent:
        """Upsert consent record."""
        existing = await self.check_existing_consent(db, subject, client_id, resource)

        if existing:
            # Merge scopes
            existing_scopes = set(existing.scope.split())
            new_scopes = set(scope.split())
            merged = " ".join(sorted(existing_scopes | new_scopes))
            existing.scope = merged
            existing.granted_at = utcnow()
            await db.commit()
            return existing

        consent = Consent(
            subject=subject,
            client_id=client_id,
            scope=scope,
            resource=resource,
            granted_at=utcnow(),
        )
        db.add(consent)
        await db.commit()
        return consent
