/**
 * Core token verification — framework-agnostic.
 * Uses `jose` for JWT verification against the issuer's JWKS.
 */

import * as jose from "jose";
import { InvalidTokenError } from "./errors.js";
import { JWKSFetcher, getFetcher } from "./jwks.js";
import { type AgentIdentity, createAgentIdentity } from "./models.js";

export interface VerifyTokenOptions {
  /** The JWT access token string. */
  token: string;
  /** Expected issuer (authgent server URL). */
  issuer: string;
  /** Expected audience claim. Omit or null to skip audience validation. */
  audience?: string | null;
  /** Optional custom JWKS fetcher. Uses cached fetcher per issuer if omitted. */
  jwksFetcher?: JWKSFetcher;
}

/**
 * Verify a JWT token against the issuer's JWKS.
 *
 * @returns Verified AgentIdentity with parsed claims and delegation chain.
 * @throws InvalidTokenError if verification fails.
 *
 * @example
 * ```ts
 * const identity = await verifyToken({
 *   token: "eyJ...",
 *   issuer: "http://localhost:8000",
 * });
 * console.log(identity.subject);          // "client:agnt_xxx"
 * console.log(identity.scopes);           // ["search:execute"]
 * console.log(identity.delegationChain);  // { depth: 0, actors: [], humanRoot: false }
 * ```
 */
export async function verifyToken(
  options: VerifyTokenOptions,
): Promise<AgentIdentity> {
  const { token, issuer, audience, jwksFetcher } = options;
  const fetcher = jwksFetcher ?? getFetcher(issuer);

  // Decode header to get kid
  let header: jose.ProtectedHeaderParameters;
  try {
    header = jose.decodeProtectedHeader(token);
  } catch {
    throw new InvalidTokenError("Malformed JWT: cannot decode header");
  }

  const kid = header.kid;
  if (!kid) {
    throw new InvalidTokenError("Token missing kid header");
  }

  // Fetch public key
  const jwk = await fetcher.getKey(kid);

  let publicKey: jose.KeyLike | Uint8Array;
  try {
    publicKey = await jose.importJWK(jwk, "ES256");
  } catch {
    throw new InvalidTokenError(`Cannot import JWK for kid=${kid}`);
  }

  // Verify signature + standard claims
  try {
    const verifyOptions: jose.JWTVerifyOptions = {
      issuer,
      algorithms: ["ES256"],
    };

    if (audience) {
      verifyOptions.audience = audience;
    }

    const { payload } = await jose.jwtVerify(token, publicKey, verifyOptions);

    // Warn if token is very large (deep delegation chains)
    if (token.length > 4096) {
      console.warn(
        `[authgent] Token size (${token.length} bytes) exceeds 4KB — ` +
          "may exceed reverse proxy header limits with deep delegation chains",
      );
    }

    return createAgentIdentity(payload as Record<string, unknown>);
  } catch (err) {
    if (err instanceof InvalidTokenError) throw err;

    if (err instanceof jose.errors.JWTExpired) {
      throw new InvalidTokenError("Token has expired");
    }
    if (err instanceof jose.errors.JWTClaimValidationFailed) {
      const msg = (err as Error).message;
      if (msg.includes("iss")) {
        throw new InvalidTokenError(`Invalid issuer: expected ${issuer}`);
      }
      if (msg.includes("aud")) {
        throw new InvalidTokenError(
          `Invalid audience: expected ${audience}`,
        );
      }
      throw new InvalidTokenError(`Claim validation failed: ${msg}`);
    }
    throw new InvalidTokenError(
      `Token verification failed: ${(err as Error).message}`,
    );
  }
}
