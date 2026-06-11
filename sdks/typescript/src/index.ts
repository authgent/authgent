/**
 * authgent SDK — IETF agent-identity reference client.
 *
 * Implements client helpers for:
 *
 * - **draft-ietf-oauth-identity-chaining-14** (cross-domain delegation):
 *   {@link AgentAuthClient.startIdentityChain},
 *   {@link AgentAuthClient.consumeIdentityChain}.
 * - **draft-ietf-oauth-transaction-tokens-08** (intra-domain transaction
 *   context propagation): {@link AgentAuthClient.issueTransactionToken}.
 * - **RFC 8693 Token Exchange** with nested `act` chains:
 *   {@link AgentAuthClient.exchangeToken}.
 * - **RFC 9449 DPoP**: {@link DPoPClient}, {@link verifyDPoPProof}.
 * - Token validation against authgent's JWKS: {@link verifyToken},
 *   {@link verifyDelegationChain}.
 *
 * See https://github.com/authgent/authgent and
 * https://github.com/authgent/authgent/blob/main/STANDARDS.md.
 *
 * @example
 * ```ts
 * import { AgentAuthClient } from "authgent";
 *
 * // Cross-domain identity chaining (draft-ietf-oauth-identity-chaining-14)
 * const grant = await aClient.startIdentityChain({
 *   subjectToken, targetAuthorizationServer: "https://as.b.example/token",
 *   clientId, clientSecret,
 * });
 * const access = await bClient.consumeIdentityChain({
 *   assertion: grant.accessToken, clientId, clientSecret,
 * });
 *
 * // Transaction Tokens (draft-ietf-oauth-transaction-tokens-08)
 * const txn = await tts.issueTransactionToken({
 *   subjectToken, trustDomain: "https://trust-domain.example/",
 *   scope: "trade.stocks", clientId, clientSecret,
 *   requestDetails: { action: "BUY", ticker: "MSFT" },
 * });
 * ```
 */

// Core verification
export { verifyToken } from "./verify.js";
export type { VerifyTokenOptions } from "./verify.js";

// Models & types
export {
  createAgentIdentity,
  createTokenClaims,
  hasActor,
} from "./models.js";
export type {
  AgentIdentity,
  DelegationChain,
  TokenClaims,
  ActClaim,
  AgentExtensionClaims,
} from "./models.js";

// Delegation chain validation
export { verifyDelegationChain } from "./delegation.js";
export type { VerifyDelegationOptions } from "./delegation.js";

// DPoP
export { verifyDPoPProof, DPoPClient, computeJkt } from "./dpop.js";
export type { VerifyDPoPProofOptions } from "./dpop.js";

// JWKS fetcher
export { JWKSFetcher, getFetcher } from "./jwks.js";

// Server API client
export { AgentAuthClient } from "./client.js";
export type { TokenResult, AgentResult, StepUpRequestResult, TokenCheckResult } from "./client.js";

// Scope challenge handler
export {
  ScopeChallengeHandler,
  parseScopeChallenge,
} from "./scope-challenge.js";
export type {
  ScopeChallenge,
  StepUpResult,
  ScopeChallengeHandlerOptions,
} from "./scope-challenge.js";

// Errors
export {
  AuthgentError,
  InvalidTokenError,
  DelegationError,
  DPoPError,
  ServerError,
  InsufficientScopeError,
  StepUpDeniedError,
  StepUpTimeoutError,
} from "./errors.js";
