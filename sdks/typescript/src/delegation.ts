/**
 * Delegation chain parsing and validation.
 * Enforces depth limits, actor allowlists, and human-root requirements.
 */

import { DelegationError } from "./errors.js";
import type { DelegationChain } from "./models.js";

export interface VerifyDelegationOptions {
  /** Maximum allowed delegation depth. Default: 5. */
  maxDepth?: number;
  /** If set, all actors must be in this list. */
  allowedActors?: string[];
  /** If true, the chain root must be a human (sub starts with "user:"). */
  requireHumanRoot?: boolean;
}

/**
 * Enforce delegation chain policy.
 *
 * @param chain - The delegation chain from a verified token.
 * @param options - Policy constraints.
 * @returns The validated DelegationChain.
 * @throws DelegationError if validation fails.
 *
 * @example
 * ```ts
 * const identity = await verifyToken({ token, issuer });
 * verifyDelegationChain(identity.delegationChain, {
 *   maxDepth: 3,
 *   requireHumanRoot: true,
 * });
 * ```
 */
export function verifyDelegationChain(
  chain: DelegationChain,
  options: VerifyDelegationOptions = {},
): DelegationChain {
  const { maxDepth = 5, allowedActors, requireHumanRoot = false } = options;

  if (chain.depth > maxDepth) {
    throw new DelegationError(
      `Delegation chain depth ${chain.depth} exceeds maximum ${maxDepth}`,
      "delegation_depth_exceeded",
    );
  }

  if (requireHumanRoot && chain.depth > 0 && !chain.humanRoot) {
    throw new DelegationError(
      "Delegation chain must have a human root",
      "no_human_root",
    );
  }

  if (allowedActors) {
    for (const actor of chain.actors) {
      if (!allowedActors.includes(actor.sub)) {
        throw new DelegationError(
          `Actor '${actor.sub}' is not in the allowed actors list`,
          "unauthorized_actor",
        );
      }
    }
  }

  return chain;
}
