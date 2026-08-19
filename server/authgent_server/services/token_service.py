"""Token service — grant handlers, token issuance, exchange, refresh."""

from __future__ import annotations

import base64
import hashlib
import secrets
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING

import structlog
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from authgent_server.config import Settings
from authgent_server.errors import (
    AccessDenied,
    InvalidGrant,
    InvalidRequest,
    TokenRevoked,
    UnsupportedGrantType,
)
from authgent_server.models.authorization_code import AuthorizationCode
from authgent_server.models.delegation_receipt import DelegationReceipt
from authgent_server.models.device_code import DeviceCode
from authgent_server.models.refresh_token import RefreshToken
from authgent_server.models.token_blocklist import TokenBlocklist
from authgent_server.providers.protocols import ClaimEnricher
from authgent_server.schemas.token import TokenResponse
from authgent_server.services.audit_service import AuditService
from authgent_server.services.chaining_verifier import ChainingGrantVerifier
from authgent_server.services.claims_transcription import get_transcriber
from authgent_server.services.delegation_service import DelegationService
from authgent_server.services.external_oidc import (
    ACCESS_TOKEN_TYPE,
    ID_TOKEN_TYPE,
    ExternalIDTokenVerifier,
)
from authgent_server.services.jwks_service import JWKSService
from authgent_server.utils import is_expired, utcnow

if TYPE_CHECKING:
    from authgent_server.providers.caep import CAEPTransmitter, DeliveryResult

# RFC 8693 §3 token type identifiers
JWT_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:jwt"
# draft-ietf-oauth-identity-chaining-14 §2.4 grant type
JWT_BEARER_GRANT = "urn:ietf:params:oauth:grant-type:jwt-bearer"
# draft-ietf-oauth-transaction-tokens-08 §3 token type
TXN_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:txn_token"

logger = structlog.get_logger()


def _generate_jti() -> str:
    return f"tok_{secrets.token_urlsafe(24)}"


class TokenService:
    def __init__(
        self,
        settings: Settings,
        jwks: JWKSService,
        delegation: DelegationService,
        audit: AuditService,
        claim_enricher: ClaimEnricher | None = None,
        external_oidc: ExternalIDTokenVerifier | None = None,
        chaining_verifier: ChainingGrantVerifier | None = None,
    ):
        self._settings = settings
        self._jwks = jwks
        self._delegation = delegation
        self._audit = audit
        self._enricher = claim_enricher
        self._external_oidc = external_oidc
        self._chaining = chaining_verifier or ChainingGrantVerifier(settings)

    async def issue_token(
        self,
        db: AsyncSession,
        grant_type: str,
        client_id: str,
        *,
        scope: str | None = None,
        resource: str | None = None,
        subject: str | None = None,
        code: str | None = None,
        code_verifier: str | None = None,
        redirect_uri: str | None = None,
        refresh_token_value: str | None = None,
        subject_token: str | None = None,
        subject_token_type: str | None = None,
        requested_token_type: str | None = None,
        assertion: str | None = None,
        request_context: dict[str, object] | None = None,
        request_details: dict[str, object] | None = None,
        audience: str | None = None,
        device_code: str | None = None,
        dpop_jkt: str | None = None,
        ip_address: str | None = None,
        oauth_client: object | None = None,
    ) -> TokenResponse:
        """Dispatch to the appropriate grant handler."""
        handlers = {
            "client_credentials": self._handle_client_credentials,
            "authorization_code": self._handle_authorization_code,
            "refresh_token": self._handle_refresh_token,
            "urn:ietf:params:oauth:grant-type:token-exchange": self._handle_token_exchange,
            "urn:ietf:params:oauth:grant-type:device_code": self._handle_device_code,
            JWT_BEARER_GRANT: self._handle_jwt_bearer,
        }

        handler = handlers.get(grant_type)
        if not handler:
            raise UnsupportedGrantType(f"Unsupported grant type: {grant_type}")

        return await handler(
            db=db,
            client_id=client_id,
            scope=scope,
            resource=resource,
            subject=subject,
            code=code,
            code_verifier=code_verifier,
            redirect_uri=redirect_uri,
            refresh_token_value=refresh_token_value,
            subject_token=subject_token,
            subject_token_type=subject_token_type,
            requested_token_type=requested_token_type,
            assertion=assertion,
            request_context=request_context,
            request_details=request_details,
            audience=audience,
            device_code=device_code,
            dpop_jkt=dpop_jkt,
            ip_address=ip_address,
            oauth_client=oauth_client,
        )

    async def _handle_client_credentials(
        self, db: AsyncSession, client_id: str, **kwargs: object
    ) -> TokenResponse:
        """client_credentials grant — agent authenticates with client_id/secret."""
        scope = kwargs.get("scope") or ""
        resource = kwargs.get("resource")
        dpop_jkt = kwargs.get("dpop_jkt")

        ttl = self._settings.client_credentials_ttl or self._settings.access_token_ttl
        now = utcnow()
        jti = _generate_jti()

        claims: dict = {
            "iss": self._settings.server_url,
            "sub": f"client:{client_id}",
            "aud": resource or self._settings.server_url,
            "exp": int((now + timedelta(seconds=ttl)).timestamp()),
            "iat": int(now.timestamp()),
            "jti": jti,
            "scope": str(scope),
            "client_id": client_id,
        }

        if dpop_jkt:
            claims["cnf"] = {"jkt": dpop_jkt}

        claims = await self._enrich_claims(claims, client_id, None, "client_credentials")
        access_token = await self._jwks.sign_jwt(db, claims)

        await self._audit.log(
            db,
            "token.issued",
            actor=client_id,
            subject=claims["sub"],
            client_id=client_id,
            ip_address=str(kwargs.get("ip_address", "")),
            metadata={"grant_type": "client_credentials", "jti": jti},
        )
        await db.commit()

        return TokenResponse(
            access_token=access_token,
            token_type="DPoP" if dpop_jkt else "Bearer",
            expires_in=ttl,
            scope=str(scope),
        )

    async def _handle_authorization_code(
        self, db: AsyncSession, client_id: str, **kwargs: object
    ) -> TokenResponse:
        """authorization_code grant — exchange code for tokens."""
        code = kwargs.get("code")
        code_verifier = kwargs.get("code_verifier")
        redirect_uri = kwargs.get("redirect_uri")
        dpop_jkt = kwargs.get("dpop_jkt")

        if not code or not code_verifier:
            raise InvalidRequest("code and code_verifier are required")

        # Atomic CAS: mark code as used
        stmt = (
            update(AuthorizationCode)
            .where(
                AuthorizationCode.code == str(code),
                AuthorizationCode.used == False,  # noqa: E712
                AuthorizationCode.expires_at > datetime.now(UTC),
                AuthorizationCode.client_id == client_id,
            )
            .values(used=True)
            .returning(AuthorizationCode)
        )
        result = await db.execute(stmt)
        auth_code = result.scalar_one_or_none()

        if auth_code is None:
            raise InvalidGrant("Authorization code is invalid, expired, or already used")

        # PKCE verification
        if auth_code.code_challenge_method == "S256":
            challenge = hashlib.sha256(str(code_verifier).encode()).digest()
            expected = base64.urlsafe_b64encode(challenge).rstrip(b"=").decode()
            if expected != auth_code.code_challenge:
                raise InvalidGrant("PKCE code_verifier does not match code_challenge")
        else:
            raise InvalidGrant(
                f"Unsupported code_challenge_method: {auth_code.code_challenge_method}"
            )

        # Verify redirect_uri matches
        if redirect_uri and str(redirect_uri) != auth_code.redirect_uri:
            raise InvalidGrant("redirect_uri does not match")

        # Issue access token
        ttl = self._settings.auth_code_access_ttl or self._settings.access_token_ttl
        now = utcnow()
        jti = _generate_jti()

        claims: dict = {
            "iss": self._settings.server_url,
            "sub": auth_code.subject or f"client:{client_id}",
            "aud": auth_code.resource or self._settings.server_url,
            "exp": int((now + timedelta(seconds=ttl)).timestamp()),
            "iat": int(now.timestamp()),
            "jti": jti,
            "scope": auth_code.scope or "",
            "client_id": client_id,
        }

        if dpop_jkt:
            claims["cnf"] = {"jkt": dpop_jkt}

        claims = await self._enrich_claims(claims, client_id, None, "authorization_code")
        access_token = await self._jwks.sign_jwt(db, claims)

        # Issue refresh token
        refresh_jti = _generate_jti()
        family_id = secrets.token_urlsafe(16)
        refresh_record = RefreshToken(
            jti=refresh_jti,
            client_id=client_id,
            subject=auth_code.subject,
            scope=auth_code.scope,
            resource=auth_code.resource,
            family_id=family_id,
            dpop_jkt=str(dpop_jkt) if dpop_jkt else None,
            expires_at=utcnow() + timedelta(seconds=self._settings.refresh_token_ttl),
        )
        db.add(refresh_record)
        await db.commit()

        await self._audit.log(
            db,
            "token.issued",
            actor=auth_code.subject,
            subject=auth_code.subject,
            client_id=client_id,
            ip_address=str(kwargs.get("ip_address", "")),
            metadata={"grant_type": "authorization_code", "jti": jti},
        )

        return TokenResponse(
            access_token=access_token,
            token_type="DPoP" if dpop_jkt else "Bearer",
            expires_in=ttl,
            scope=auth_code.scope or "",
            refresh_token=refresh_jti,
        )

    async def _handle_refresh_token(
        self, db: AsyncSession, client_id: str, **kwargs: object
    ) -> TokenResponse:
        """refresh_token grant — rotate and reissue."""
        refresh_token_value = kwargs.get("refresh_token_value")
        dpop_jkt = kwargs.get("dpop_jkt")
        resource = kwargs.get("resource")

        if not refresh_token_value:
            raise InvalidRequest("refresh_token is required")

        # Look up refresh token
        stmt = select(RefreshToken).where(
            RefreshToken.jti == str(refresh_token_value),
            RefreshToken.client_id == client_id,
        )
        result = await db.execute(stmt)
        rt = result.scalar_one_or_none()

        if rt is None:
            raise InvalidGrant("Refresh token not found")

        if is_expired(rt.expires_at):
            raise InvalidGrant("Refresh token expired")

        # Check resource binding
        if resource and rt.resource and str(resource) != rt.resource:
            raise InvalidGrant("Resource does not match refresh token binding")

        # REUSE DETECTION: if already used, revoke entire family
        if rt.used:
            logger.warning(
                "refresh_token_reuse_detected",
                jti=rt.jti,
                family_id=rt.family_id,
                client_id=client_id,
            )
            # Revoke all tokens in family
            await db.execute(
                update(RefreshToken).where(RefreshToken.family_id == rt.family_id).values(used=True)
            )
            await db.commit()

            await self._audit.log(
                db,
                "token.replay_detected",
                client_id=client_id,
                metadata={"family_id": rt.family_id, "jti": rt.jti},
            )
            raise InvalidGrant("Refresh token has already been used (replay detected)")

        # Atomic CAS: mark current token as used
        cas_stmt = (
            update(RefreshToken)
            .where(
                RefreshToken.jti == rt.jti,
                RefreshToken.used == False,  # noqa: E712
            )
            .values(used=True)
        )
        cas_result = await db.execute(cas_stmt)
        if cas_result.rowcount == 0:
            raise InvalidGrant("Refresh token race condition — token already consumed")

        # Issue new refresh token in same family
        now = utcnow()
        new_refresh_jti = _generate_jti()
        new_refresh = RefreshToken(
            jti=new_refresh_jti,
            client_id=client_id,
            subject=rt.subject,
            scope=rt.scope,
            resource=rt.resource,
            family_id=rt.family_id,
            dpop_jkt=str(dpop_jkt) if dpop_jkt else rt.dpop_jkt,
            expires_at=utcnow() + timedelta(seconds=self._settings.refresh_token_ttl),
        )
        db.add(new_refresh)

        # Issue new access token
        ttl = self._settings.access_token_ttl
        jti = _generate_jti()

        claims: dict = {
            "iss": self._settings.server_url,
            "sub": rt.subject or f"client:{client_id}",
            "aud": rt.resource or self._settings.server_url,
            "exp": int((now + timedelta(seconds=ttl)).timestamp()),
            "iat": int(now.timestamp()),
            "jti": jti,
            "scope": rt.scope or "",
            "client_id": client_id,
        }

        if dpop_jkt:
            claims["cnf"] = {"jkt": dpop_jkt}

        access_token = await self._jwks.sign_jwt(db, claims)
        await db.commit()

        return TokenResponse(
            access_token=access_token,
            token_type="DPoP" if dpop_jkt else "Bearer",
            expires_in=ttl,
            scope=rt.scope or "",
            refresh_token=new_refresh_jti,
        )

    async def _handle_token_exchange(
        self, db: AsyncSession, client_id: str, **kwargs: object
    ) -> TokenResponse:
        """RFC 8693 token exchange — delegation chain or identity-chaining grant.

        Modes:
        - requested_token_type=jwt → mints a cross-domain JWT authorization grant
          per draft-ietf-oauth-identity-chaining-14 §2.3 (returned to the client
          to be presented to a downstream AS via the jwt-bearer grant).
        - default → builds a nested-act delegation chain access token + receipt
          (authgent's intra-domain agent delegation flow).

        subject_token_type values:
        - access_token (default): exchange an authgent-issued token
        - id_token: exchange an external IdP token (Auth0/Clerk/Okta)
        """
        subject_token = kwargs.get("subject_token")
        subject_token_type = str(kwargs.get("subject_token_type") or ACCESS_TOKEN_TYPE)
        requested_token_type = kwargs.get("requested_token_type")
        audience_target = kwargs.get("audience")
        resource_target = kwargs.get("resource")
        scope = kwargs.get("scope")
        dpop_jkt = kwargs.get("dpop_jkt")

        if not subject_token:
            raise InvalidRequest("subject_token is required for token exchange")
        # §2.3.1: One of resource or audience MUST be present.
        if not audience_target and not resource_target:
            raise InvalidRequest("audience or resource is required for token exchange")
        if not audience_target:
            audience_target = resource_target

        # Identity Chaining branch (draft-ietf-oauth-identity-chaining-14 §2.3)
        if requested_token_type == JWT_TOKEN_TYPE:
            return await self._issue_chaining_grant(
                db=db,
                client_id=client_id,
                subject_token=str(subject_token),
                subject_token_type=subject_token_type,
                audience_target=str(audience_target),
                scope=str(scope) if scope else None,
                ip_address=kwargs.get("ip_address"),
            )

        # Transaction Tokens branch (draft-ietf-oauth-transaction-tokens-08 §3)
        if requested_token_type == TXN_TOKEN_TYPE:
            return await self._issue_transaction_token(
                db=db,
                client_id=client_id,
                subject_token=str(subject_token),
                subject_token_type=subject_token_type,
                audience_target=str(audience_target),
                scope=str(scope) if scope else None,
                request_context=kwargs.get("request_context"),
                request_details=kwargs.get("request_details"),
                ip_address=kwargs.get("ip_address"),
            )

        # Dispatch on subject_token_type (RFC 8693 §2.1)
        try:
            if subject_token_type == ID_TOKEN_TYPE:
                parent_claims = await self._verify_external_id_token(str(subject_token))
            elif subject_token_type == ACCESS_TOKEN_TYPE:
                parent_claims = await self.verify_and_check_blocklist(db, str(subject_token))
            else:
                raise InvalidRequest(f"Unsupported subject_token_type: {subject_token_type}")
        except (InvalidRequest, TokenRevoked):
            raise
        except Exception as e:
            raise InvalidGrant(f"Invalid subject_token: {e}") from e

        # Enforce allowed_exchange_targets from the PARENT agent (source restriction).
        # The parent agent controls which audiences their delegated authority can flow to.
        parent_client_id = parent_claims.get("client_id")
        if parent_client_id:
            from sqlalchemy.orm import selectinload

            from authgent_server.models.oauth_client import OAuthClient

            stmt = (
                select(OAuthClient)
                .where(OAuthClient.client_id == parent_client_id)
                .options(selectinload(OAuthClient.agent))
            )
            result = await db.execute(stmt)
            parent_oauth_client = result.scalar_one_or_none()
            if parent_oauth_client and parent_oauth_client.agent:
                targets = parent_oauth_client.agent.allowed_exchange_targets
                if targets and str(audience_target) not in targets:
                    raise AccessDenied(
                        f"Audience '{audience_target}' not in parent agent's "
                        f"allowed_exchange_targets: {targets}"
                    )

        # Build delegation claims
        requested_scopes = str(scope).split() if scope else []
        delegated_claims = self._delegation.build_delegated_claims(
            parent_claims=parent_claims,
            actor_id=f"client:{client_id}",
            target_audience=str(audience_target),
            requested_scopes=requested_scopes,
        )

        # Issue new token
        ttl = self._settings.exchange_token_ttl
        now = utcnow()
        jti = _generate_jti()

        claims: dict = {
            "iss": self._settings.server_url,
            **delegated_claims,
            "exp": int((now + timedelta(seconds=ttl)).timestamp()),
            "iat": int(now.timestamp()),
            "jti": jti,
            "client_id": client_id,
        }

        if dpop_jkt:
            claims["cnf"] = {"jkt": dpop_jkt}

        claims = await self._enrich_claims(claims, client_id, None, "token_exchange")
        access_token = await self._jwks.sign_jwt(db, claims)

        # Store delegation receipt for chain splicing prevention
        parent_jti = parent_claims.get("jti", "")
        chain_hash = self._delegation.compute_chain_hash(claims)
        receipt_claims = {
            "iss": self._settings.server_url,
            "type": "delegation_receipt",
            "token_jti": jti,
            "parent_jti": parent_jti,
            "actor": f"client:{client_id}",
            "chain_hash": chain_hash,
            "iat": int(now.timestamp()),
        }
        receipt_jwt = await self._jwks.sign_jwt(db, receipt_claims)
        receipt = DelegationReceipt(
            token_jti=jti,
            parent_token_jti=parent_jti,
            actor_id=f"client:{client_id}",
            receipt_jwt=receipt_jwt,
            chain_hash=chain_hash,
            expires_at=claims["exp"] and datetime.fromtimestamp(claims["exp"], tz=UTC),
        )
        db.add(receipt)
        await db.flush()

        await self._audit.log(
            db,
            "token.exchanged",
            actor=f"client:{client_id}",
            subject=claims.get("sub"),
            client_id=client_id,
            metadata={
                "grant_type": "token_exchange",
                "subject_token_type": subject_token_type,
                "jti": jti,
                "parent_jti": parent_jti,
                "audience": str(audience_target),
                "human_root": parent_claims.get("human_root", False),
                "receipt_id": receipt.id,
            },
        )
        await db.commit()

        return TokenResponse(
            access_token=access_token,
            token_type="DPoP" if dpop_jkt else "Bearer",
            expires_in=ttl,
            scope=" ".join(requested_scopes),
            issued_token_type="urn:ietf:params:oauth:token-type:access_token",
        )

    async def _verify_external_id_token(self, token: str) -> dict:
        """Verify an external id_token via the ExternalIDTokenVerifier.

        Returns normalized claims suitable for delegation chain construction.
        The returned claims include 'sub' as 'user:{idp_sub}' and
        'human_root': True so downstream delegation recognizes
        this as a human-rooted chain.
        """
        if self._external_oidc is None:
            raise InvalidRequest(
                "External id_token exchange is not configured. Set AUTHGENT_TRUSTED_OIDC_ISSUERS."
            )
        verified = await self._external_oidc.verify_id_token(token)

        # Build parent_claims compatible with delegation service
        return {
            "sub": verified["sub"],
            "scope": "",  # id_tokens don't carry scopes; client requests scopes
            "idp_iss": verified["idp_iss"],
            "idp_sub": verified["idp_sub"],
            "human_root": True,
        }

    async def _issue_chaining_grant(
        self,
        db: AsyncSession,
        client_id: str,
        subject_token: str,
        subject_token_type: str,
        audience_target: str,
        scope: str | None,
        ip_address: object | None,
    ) -> TokenResponse:
        """Mint a JWT authorization grant per draft-ietf-oauth-identity-chaining-14 §2.3.

        Domain A → Domain B grant. The grant is short-lived, single-use (enforced
        on consumption by the receiver), and audience-bound to the target AS.
        Refresh tokens are NEVER issued for this grant type (§5.4).
        """
        # §2.3.2: enforce policy on the target trust domain.
        if (
            self._settings.trusted_chaining_targets
            and audience_target not in self._settings.trusted_chaining_targets
        ):
            raise AccessDenied(
                f"Target '{audience_target}' is not in AUTHGENT_TRUSTED_CHAINING_TARGETS"
            )

        # Verify subject_token (same dispatch as the delegation flow)
        try:
            if subject_token_type == ID_TOKEN_TYPE:
                parent_claims = await self._verify_external_id_token(subject_token)
            elif subject_token_type == ACCESS_TOKEN_TYPE:
                parent_claims = await self.verify_and_check_blocklist(db, subject_token)
            else:
                raise InvalidRequest(f"Unsupported subject_token_type: {subject_token_type}")
        except (InvalidRequest, TokenRevoked):
            raise
        except Exception as e:
            raise InvalidGrant(f"Invalid subject_token: {e}") from e

        # §2.5: Claims transcription — author may add/remove/change claims.
        transcriber = get_transcriber(self._settings.chaining_claims_policy)
        transcribed = transcriber.transcribe(parent_claims)

        # §2.3.3: aud MUST identify the requested AS in trust domain B.
        # SHOULD be a single AS (single string).
        now = utcnow()
        ttl = self._settings.chaining_grant_ttl
        jti = _generate_jti()

        grant_claims: dict[str, object] = {
            "iss": self._settings.server_url,
            "aud": audience_target,
            "exp": int((now + timedelta(seconds=ttl)).timestamp()),
            "iat": int(now.timestamp()),
            "nbf": int(now.timestamp()),
            "jti": jti,
            "client_id": client_id,
            **transcribed,
        }
        if scope:
            grant_claims["scope"] = scope

        grant_jwt = await self._jwks.sign_jwt(db, grant_claims)

        await self._audit.log(
            db,
            "token.chaining_grant_issued",
            actor=f"client:{client_id}",
            subject=str(grant_claims.get("sub", "")),
            client_id=client_id,
            ip_address=str(ip_address or ""),
            metadata={
                "grant_type": "token_exchange",
                "requested_token_type": JWT_TOKEN_TYPE,
                "audience": audience_target,
                "jti": jti,
                "ttl": ttl,
            },
        )
        await db.commit()

        return TokenResponse(
            access_token=grant_jwt,
            token_type="N_A",
            expires_in=ttl,
            scope=scope,
            issued_token_type=JWT_TOKEN_TYPE,
        )

    async def _issue_transaction_token(
        self,
        db: AsyncSession,
        client_id: str,
        subject_token: str,
        subject_token_type: str,
        audience_target: str,
        scope: str | None,
        request_context: object,
        request_details: object,
        ip_address: object | None,
    ) -> TokenResponse:
        """Issue a Transaction Token per draft-ietf-oauth-transaction-tokens-09.

        A Txn-Token is short-lived, audience-bound to a Trust Domain, and carries
        a unique `txn` identifier plus optional immutable `tctx` (transaction
        context) and mutable `rctx` (requester context) claims. It is NOT an
        access token: `token_type` is "N_A" and refresh tokens are never issued.

        Spec sections enforced here:
        - §3 typ header `txntoken+jwt`, required claims iat/aud/exp/txn/sub/scope/req_wl
        - §7 short-lived (default 120s)
        - §13.6 / §13.14 scope MUST NOT exceed subject_token's scope; if that scope
          cannot be determined, the request MUST be rejected rather than treated
          as unconstrained
        - §7.3 access tokens MUST NOT be embedded
        - §11 no refresh tokens
        """
        # Verify subject_token (RFC 8693 §2.1 dispatch).
        try:
            if subject_token_type == ID_TOKEN_TYPE:
                parent_claims = await self._verify_external_id_token(subject_token)
            elif subject_token_type == ACCESS_TOKEN_TYPE:
                parent_claims = await self.verify_and_check_blocklist(db, subject_token)
            else:
                raise InvalidRequest(f"Unsupported subject_token_type: {subject_token_type}")
        except (InvalidRequest, TokenRevoked):
            raise
        except Exception as e:
            raise InvalidGrant(f"Invalid subject_token: {e}") from e

        # §13.6: TTS MUST ensure requested scope is equal-or-less than subject_token's
        # scope. §13.14: if that scope cannot be determined (absent or empty `scope`
        # claim on the subject_token), the TTS MUST reject the request rather than
        # treat the unknown scope as unconstrained.
        parent_scopes = set((parent_claims.get("scope") or "").split())
        requested = set(scope.split()) if scope else set()
        if requested and not requested.issubset(parent_scopes):
            escalated = requested - parent_scopes
            reason = (
                "subject_token carries no determinable scope"
                if not parent_scopes
                else f"escalated: {sorted(escalated)}"
            )
            raise AccessDenied(f"Txn-Token scope MUST NOT exceed subject_token scope; {reason}")

        trust_domain = self._settings.txn_token_trust_domain or audience_target
        ttl = self._settings.txn_token_ttl
        now = utcnow()
        # §7 unique transaction identifier; uses jti shape for uniqueness.
        txn_id = secrets.token_urlsafe(24)

        sub = parent_claims.get("sub") or f"client:{client_id}"
        if not sub:
            raise InvalidGrant("Subject token has no usable sub claim")

        claims: dict[str, object] = {
            "iss": self._settings.server_url,
            "iat": int(now.timestamp()),
            "aud": trust_domain,
            "exp": int((now + timedelta(seconds=ttl)).timestamp()),
            "txn": txn_id,
            "sub": sub,
            "scope": scope or parent_claims.get("scope", ""),
            "req_wl": f"client:{client_id}",
        }

        # §3 optional `tctx` immutable transaction context (caller-provided).
        if isinstance(request_details, dict):
            claims["tctx"] = request_details

        # §3 optional `rctx` requester context. Compose from request_context plus
        # automatically-derived environmental fields (req_ip, authn).
        rctx: dict[str, object] = {}
        if isinstance(request_context, dict):
            rctx.update(request_context)
        if ip_address:
            rctx.setdefault("req_ip", str(ip_address))
        rctx.setdefault("authn", "urn:ietf:rfc:6749")
        claims["rctx"] = rctx

        # Carry external IdP provenance forward (purely additive; not in §3 schema
        # but useful for audit and downstream attestation).
        for key in ("idp_iss", "idp_sub", "human_root"):
            if key in parent_claims:
                claims[key] = parent_claims[key]

        # §3 RECOMMENDED `typ` header `txntoken+jwt`.
        txn_jwt = await self._jwks.sign_jwt(db, claims, headers={"typ": "txntoken+jwt"})

        await self._audit.log(
            db,
            "token.txn_token_issued",
            actor=f"client:{client_id}",
            subject=str(sub),
            client_id=client_id,
            ip_address=str(ip_address or ""),
            metadata={
                "grant_type": "token_exchange",
                "requested_token_type": TXN_TOKEN_TYPE,
                "txn": txn_id,
                "trust_domain": trust_domain,
                "ttl": ttl,
            },
        )
        await db.commit()

        return TokenResponse(
            access_token=txn_jwt,
            token_type="N_A",
            expires_in=ttl,
            scope=scope,
            issued_token_type=TXN_TOKEN_TYPE,
        )

    async def _handle_jwt_bearer(
        self, db: AsyncSession, client_id: str, **kwargs: object
    ) -> TokenResponse:
        """Consume a JWT authorization grant per identity-chaining §2.4 + RFC 7523.

        Domain B side. Verifies an assertion issued by a trusted Domain A AS,
        checks single-use replay protection on jti, and issues a Domain-B
        access token. Per §5.4 this handler MUST NOT issue a refresh token.
        """
        assertion = kwargs.get("assertion")
        scope = kwargs.get("scope")
        resource = kwargs.get("resource")
        dpop_jkt = kwargs.get("dpop_jkt")
        ip_address = kwargs.get("ip_address")

        if not assertion:
            raise InvalidRequest("assertion is required for jwt-bearer grant")

        try:
            assertion_claims = await self._chaining.verify_assertion(str(assertion), db=db)
        except (InvalidRequest, InvalidGrant):
            raise
        except Exception as e:
            raise InvalidGrant(f"Invalid assertion: {e}") from e

        # §5.5: single-use enforcement on jti — reuse the blocklist.
        assertion_jti = assertion_claims.get("jti")
        if not assertion_jti:
            raise InvalidGrant("Assertion missing jti")

        if await self.is_token_revoked(db, str(assertion_jti)):
            raise InvalidGrant("Assertion has already been consumed (replay detected)")

        consumed = TokenBlocklist(
            jti=str(assertion_jti),
            expires_at=datetime.fromtimestamp(int(assertion_claims["exp"]), tz=UTC),
            reason="chaining_grant_consumed",
        )
        db.add(consumed)
        try:
            await db.flush()
        except Exception as e:
            await db.rollback()
            raise InvalidGrant("Assertion has already been consumed (replay detected)") from e

        # §2.4.2: subject MUST be identifiable.
        subject = assertion_claims.get("sub")
        if not subject:
            raise InvalidGrant("Assertion missing identifiable subject")

        # §2.5: Claims transcription on consumption — copy idp_iss/idp_sub
        # forward so downstream services see the human root if any.
        scopes_from_assertion = assertion_claims.get("scope", "")
        effective_scope = scope or scopes_from_assertion or ""

        # §5.4: SHOULD NOT issue refresh tokens — we don't.
        ttl = self._settings.access_token_ttl
        now = utcnow()
        jti = _generate_jti()

        access_claims: dict[str, object] = {
            "iss": self._settings.server_url,
            "sub": subject,
            "aud": str(resource) if resource else self._settings.server_url,
            "exp": int((now + timedelta(seconds=ttl)).timestamp()),
            "iat": int(now.timestamp()),
            "jti": jti,
            "scope": str(effective_scope),
            "client_id": client_id,
            "chained_from": assertion_claims.get("iss"),
        }
        for k in ("idp_iss", "idp_sub", "human_root", "email", "name"):
            if k in assertion_claims:
                access_claims[k] = assertion_claims[k]

        if dpop_jkt:
            access_claims["cnf"] = {"jkt": dpop_jkt}

        access_claims = await self._enrich_claims(access_claims, client_id, None, "jwt_bearer")
        access_token = await self._jwks.sign_jwt(db, access_claims)

        await self._audit.log(
            db,
            "token.chaining_grant_consumed",
            actor=f"client:{client_id}",
            subject=str(subject),
            client_id=client_id,
            ip_address=str(ip_address or ""),
            metadata={
                "grant_type": JWT_BEARER_GRANT,
                "jti": jti,
                "assertion_jti": str(assertion_jti),
                "assertion_iss": assertion_claims.get("iss"),
            },
        )
        await db.commit()

        return TokenResponse(
            access_token=access_token,
            token_type="DPoP" if dpop_jkt else "Bearer",
            expires_in=ttl,
            scope=str(effective_scope),
        )

    async def _handle_device_code(
        self, db: AsyncSession, client_id: str, **kwargs: object
    ) -> TokenResponse:
        """urn:ietf:params:oauth:grant-type:device_code — RFC 8628 §3.4.

        Polls the device_codes table; issues a token if the code is approved.
        """
        device_code_value = kwargs.get("device_code") or kwargs.get("code")
        if not device_code_value:
            raise InvalidRequest("device_code is required")

        stmt = select(DeviceCode).where(
            DeviceCode.device_code == str(device_code_value),
            DeviceCode.client_id == client_id,
        )
        result = await db.execute(stmt)
        record = result.scalar_one_or_none()

        if not record:
            raise InvalidGrant("Unknown device code")

        if is_expired(record.expires_at):
            raise InvalidGrant("Device code expired")

        if record.status == "denied":
            raise InvalidGrant("Device authorization request was denied")

        if record.status != "approved":
            raise InvalidGrant("authorization_pending")

        # Atomic CAS: mark as consumed
        cas = (
            update(DeviceCode)
            .where(
                DeviceCode.device_code == str(device_code_value),
                DeviceCode.status == "approved",
            )
            .values(status="consumed")
        )
        cas_result = await db.execute(cas)
        if cas_result.rowcount == 0:
            raise InvalidGrant("Device code already consumed")
        await db.commit()

        # Issue token (same as client_credentials but with device subject)
        return await self._handle_client_credentials(
            db=db,
            client_id=client_id,
            scope=record.scope,
            subject=record.subject,
            **{
                k: v
                for k, v in kwargs.items()
                if k not in ("device_code", "code", "scope", "subject")
            },
        )

    async def revoke_token(self, db: AsyncSession, token: str, client_id: str) -> None:
        """Revoke a token by adding its JTI to the blocklist.

        Per RFC 7009 §2.1, the server MUST verify the token was issued to
        the authenticated client. If not, silently ignore the request
        (don't reveal information about other clients' tokens).
        """
        try:
            claims = await self._jwks.verify_jwt(db, token)
        except Exception:
            # RFC 7009: revocation of invalid tokens is not an error
            return

        jti = claims.get("jti")
        if not jti:
            return

        # Ownership check: only the token's client can revoke it
        token_client = claims.get("client_id", "")
        if token_client != client_id:
            # RFC 7009: don't reveal info — silently return 200
            return

        # Add to blocklist
        blocklist_entry = TokenBlocklist(
            jti=jti,
            expires_at=datetime.fromtimestamp(claims.get("exp", 0), tz=UTC),
            reason="user_revoke",
        )
        db.add(blocklist_entry)

        try:
            await db.commit()
        except Exception:
            await db.rollback()
            # Already revoked — idempotent
            return

        await self._audit.log(
            db,
            "token.revoked",
            client_id=client_id,
            metadata={"jti": jti},
        )
        await db.commit()

        await self._cascade_revoke_descendants(db, jti)

    async def _cascade_revoke_descendants(self, db: AsyncSession, root_jti: str) -> None:
        """Blocklist every token delegated (directly or transitively) from root_jti.

        Walks the delegation_receipts graph breadth-first via parent_token_jti.
        A token's authority is entirely derived from its parent in the chain
        (authgent_server.services.delegation_service.build_delegated_claims
        carries forward sub/scope/act from parent_claims); once the root is
        revoked, every descendant's authority is void even though each
        descendant token remains cryptographically valid until it expires.
        """
        frontier = [root_jti]
        visited: set[str] = {root_jti}
        while frontier:
            stmt = select(DelegationReceipt).where(DelegationReceipt.parent_token_jti.in_(frontier))
            result = await db.execute(stmt)
            receipts = result.scalars().all()
            frontier = []
            for receipt in receipts:
                if receipt.token_jti in visited:
                    continue
                visited.add(receipt.token_jti)
                if await self.is_token_revoked(db, receipt.token_jti):
                    continue
                expires_at = receipt.expires_at or datetime.now(UTC) + timedelta(days=1)
                db.add(
                    TokenBlocklist(
                        jti=receipt.token_jti,
                        expires_at=expires_at,
                        reason="ancestor_revoked",
                    )
                )
                frontier.append(receipt.token_jti)
        if visited - {root_jti}:
            await self._audit.log(
                db,
                "token.cascade_revoked",
                metadata={"root_jti": root_jti, "descendant_jtis": sorted(visited - {root_jti})},
            )
        await db.commit()

    async def flag_compromised(
        self,
        db: AsyncSession,
        token: str,
        reason: str,
        *,
        operator_client_id: str,
    ) -> list[DeliveryResult]:
        """Flag a token as compromised: blocklist it, cascade-revoke its
        descendants, AND push a CAEP session-revoked SET to every configured
        receiver.

        Takes the actual signed token, not a bare `jti` string, and verifies
        it exactly as `revoke_token` does (`self._jwks.verify_jwt`) before
        doing anything else. Two things this closes, found by adversarial
        review of an earlier version of this method that accepted a bare
        jti argument supplied directly by the caller: (1) a caller could
        flag an arbitrary, never-issued jti as "compromised," triggering a
        real signed SET push to every receiver for a token that never
        existed; (2) the SET's subject was populated from the *operator's
        own* client_id/actor_id (the caller's identity, passed in as
        arguments), not the compromised agent's, so receivers would have
        been told the operator's own session was revoked instead of the
        flagged agent's. Requiring and verifying the real token fixes both:
        `actor_id`/`client_id`/`jti` in the resulting SET are now read from
        the verified token's own claims (`sub`, `client_id`, `jti`), and an
        unverifiable or fabricated token is rejected before any signing or
        network call happens.

        This is deliberately a separate entry point from `revoke_token`
        (RFC 7009 client self-revocation), not a parameter or side effect
        bolted onto it, for three reasons:

          1. Different caller and different trust level. `revoke_token` is
             called by the token's own client, authenticated with its own
             client_secret, as a routine, expected action (token no longer
             needed, credential rotation, session logout). This method is
             called by an operator or an automated detector acting on a
             third party's token — a fundamentally different, higher-stakes
             action that this codebase gates on `caep_operator_scope`
             (see endpoints/security.py) rather than "does the caller hold
             this token's client_secret".
          2. Different externally-visible effect. Routine revocation is a
             purely local bookkeeping change (a blocklist row); nothing is
             broadcast. Compromise-flagging additionally transmits a signed
             SET to external relying parties over the network — an action
             with cost, latency, and failure modes (partial delivery,
             receiver downtime) that a routine self-revocation call should
             never incur or be delayed by.
          3. Different semantics for the receiving relying party. A CAEP
             session-revoked event tells a relying party "treat this
             session as actively dangerous, right now" — appropriate for a
             detected compromise, not for an agent logging itself out
             normally. Firing that signal on every ordinary revocation
             would make it useless as a compromise signal (alert fatigue,
             and relying parties would have no way to distinguish "routine"
             from "urgent" without a payload field this prototype does not
             define).

        Reuses the existing blocklist + cascade path so a compromised
        token's authority is void for every relying party that checks
        introspection or blocklist state, exactly as revoke_token does.
        CAEP transmission is the additional, distinguishing step.
        """
        try:
            claims = await self._jwks.verify_jwt(db, token)
        except Exception as exc:
            # Unlike revoke_token (RFC 7009 requires silently succeeding on
            # an invalid/already-invalid token so as not to leak
            # information), flag_compromised is an operator-only action
            # where a clean rejection is the correct signal: an operator
            # who submits a bad token needs to know it was rejected, not
            # see it silently no-op.
            raise InvalidRequest(f"Cannot verify token: {exc}") from exc
        jti = claims.get("jti")
        if not jti:
            raise InvalidRequest("Token has no jti; cannot flag as compromised")
        actor_id = str(claims.get("sub", ""))
        client_id = str(claims.get("client_id", ""))

        if await self.is_token_revoked(db, jti):
            logger.info("caep_flag_compromised_already_revoked", jti=jti)
        else:
            db.add(
                TokenBlocklist(
                    jti=jti,
                    expires_at=datetime.now(UTC) + timedelta(days=1),
                    reason="compromised",
                )
            )
            try:
                await db.commit()
            except Exception:
                await db.rollback()

            await self._audit.log(
                db,
                "token.flagged_compromised",
                actor=operator_client_id,
                client_id=client_id,
                subject=actor_id,
                metadata={"jti": jti, "reason": reason, "operator": operator_client_id},
            )
            await db.commit()

            await self._cascade_revoke_descendants(db, jti)

        transmitter = self._get_caep_transmitter()
        results = await transmitter.transmit_session_revoked(
            db,
            actor_id=actor_id,
            client_id=client_id,
            jti=jti,
            reason=reason,
        )

        await self._audit.log(
            db,
            "caep.session_revoked_transmitted",
            actor=operator_client_id,
            client_id=client_id,
            subject=actor_id,
            metadata={
                "jti": jti,
                "receivers_attempted": len(results),
                "receivers_delivered": sum(1 for r in results if r.delivered),
            },
        )
        await db.commit()

        return results

    def _get_caep_transmitter(self) -> CAEPTransmitter:
        """Lazily construct the CAEP transmitter from current settings.

        Constructed here rather than injected in __init__ so tests can
        monkeypatch Settings.caep_receiver_urls without needing to thread a
        new constructor argument through every TokenService call site.
        """
        from authgent_server.providers.caep import CAEPTransmitter

        return CAEPTransmitter(self._jwks, self._settings)

    async def is_token_revoked(self, db: AsyncSession, jti: str) -> bool:
        """Check if a token JTI is in the blocklist."""
        stmt = select(TokenBlocklist).where(TokenBlocklist.jti == jti)
        result = await db.execute(stmt)
        return result.scalar_one_or_none() is not None

    async def _first_revoked_ancestor(self, db: AsyncSession, jti: str) -> str | None:
        """Walk parent_token_jti up from jti, return the first revoked ancestor's jti (or None).

        This closes the TOCTOU race in _cascade_revoke_descendants: that method
        walks the delegation_receipts graph DOWNWARD from a newly-revoked root,
        so a concurrent exchange can mint a fresh descendant receipt after the
        downward walk has already passed that level, permanently escaping the
        cascade. This method instead walks UPWARD from the token being checked,
        on every use (introspection and token exchange), re-deriving revocation
        status from current blocklist state rather than relying on the
        downward cascade having already reached this node. Because the root's
        own blocklist row is committed synchronously in revoke_token before the
        downward cascade even starts, any descendant that walks up to that root
        will see it revoked immediately, independent of cascade progress. This
        is a fencing-token/optimistic-concurrency-control pattern (Kleppmann,
        "How to do Distributed Locking," 2016; Kung and Robinson, "On
        Optimistic Methods for Concurrency Control," ACM TODS, 1981): the
        ancestor lineage is re-validated at the moment of use rather than
        trusted from a point-in-time cache.
        """
        current = jti
        visited: set[str] = set()
        while current and current not in visited:
            visited.add(current)
            stmt = select(DelegationReceipt).where(DelegationReceipt.token_jti == current)
            result = await db.execute(stmt)
            receipt = result.scalar_one_or_none()
            if receipt is None:
                return None
            parent = receipt.parent_token_jti
            if not parent:
                return None
            if await self.is_token_revoked(db, parent):
                return parent
            current = parent
        return None

    async def verify_and_check_blocklist(
        self, db: AsyncSession, token: str, audience: str | None = None
    ) -> dict:
        """Verify a JWT and ensure it hasn't been revoked (including by an ancestor)."""
        claims = await self._jwks.verify_jwt(db, token, audience)
        jti = claims.get("jti")
        if not jti:
            return claims
        if await self.is_token_revoked(db, jti):
            raise TokenRevoked(f"Token {jti} has been revoked")
        revoked_ancestor = await self._first_revoked_ancestor(db, jti)
        if revoked_ancestor:
            raise TokenRevoked(f"Token {jti} descends from revoked ancestor {revoked_ancestor}")
        return claims

    async def _enrich_claims(
        self,
        claims: dict,
        client_id: str,
        agent_id: str | None,
        grant_type: str,
    ) -> dict:
        """Run ClaimEnricher if configured. Fail-open: enricher errors don't block issuance."""
        if self._enricher is None:
            return claims
        try:
            return await self._enricher.enrich(claims, client_id, agent_id, grant_type)
        except Exception as e:
            logger.warning(
                "claim_enricher_failed",
                error=str(e),
                client_id=client_id,
                grant_type=grant_type,
            )
            return claims
