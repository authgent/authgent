/**
 * authgent SDK — token verification, delegation chains, DPoP for AI agents.
 *
 * @example
 * ```ts
 * import { verifyToken, verifyDelegationChain, AgentAuthClient } from "authgent";
 *
 * // Verify a token
 * const identity = await verifyToken({ token: "eyJ...", issuer: "http://localhost:8000" });
 *
 * // Validate delegation chain
 * verifyDelegationChain(identity.delegationChain, { maxDepth: 3 });
 *
 * // Get tokens via client
 * const client = new AgentAuthClient("http://localhost:8000");
 * const token = await client.getToken({ clientId: "...", clientSecret: "..." });
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
