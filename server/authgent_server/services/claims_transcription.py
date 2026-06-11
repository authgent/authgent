"""Claims Transcription — draft-ietf-oauth-identity-chaining-14 §2.5.

When Domain A's authorization server mints a JWT authorization grant for
Domain B, it can add, remove, or change claims. The set of claims that
crosses the trust boundary is governed by a transcription policy.

This module implements the default policies. Custom mappers can be
configured via AUTHGENT_CHAINING_CLAIMS_POLICY in the future; for now
two built-in policies are provided.
"""

from __future__ import annotations

from typing import Literal, Protocol


class ClaimsTranscriber(Protocol):
    def transcribe(self, parent_claims: dict) -> dict:
        """Map Domain-A claims into the JWT authorization grant for Domain B."""
        ...


class PreserveSubjectTranscription:
    """Default policy: carry sub, scope, and external IdP provenance forward.

    Filters out anything domain-internal (jti, exp, iat, client_id, cnf,
    delegation act chain — those belong to Domain A's lifecycle, not the
    cross-domain grant).
    """

    _CARRY = ("sub", "scope", "idp_iss", "idp_sub", "human_root", "email", "name")

    def transcribe(self, parent_claims: dict) -> dict:
        return {k: parent_claims[k] for k in self._CARRY if k in parent_claims}


class MinimizeTranscription:
    """Privacy-preserving policy: carry only stable external identifiers.

    Useful when the upstream subject is sensitive (e.g., personal email)
    and Domain B should reconstruct identity from the IdP-issued claims.
    """

    _CARRY = ("idp_iss", "idp_sub", "human_root")

    def transcribe(self, parent_claims: dict) -> dict:
        return {k: parent_claims[k] for k in self._CARRY if k in parent_claims}


def get_transcriber(policy: Literal["preserve_sub", "minimize"]) -> ClaimsTranscriber:
    if policy == "minimize":
        return MinimizeTranscription()
    return PreserveSubjectTranscription()
