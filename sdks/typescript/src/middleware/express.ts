/**
 * Express middleware — AgentAuthMiddleware + requireAgentAuth + getAgentIdentity.
 *
 * @example
 * ```ts
 * import express from "express";
 * import { agentAuth, requireAgentAuth, getAgentIdentity } from "authgent/middleware/express";
 *
 * const app = express();
 * app.use(agentAuth({ issuer: "http://localhost:8000" }));
 *
 * app.post("/tools/search", requireAgentAuth(["search:execute"]), (req, res) => {
 *   const identity = getAgentIdentity(req);
 *   res.json({ agent: identity.subject });
 * });
 * ```
 */

import type { Request, Response, NextFunction, RequestHandler } from "express";
import { verifyToken } from "../verify.js";
import type { AgentIdentity } from "../models.js";
import type { JWKSFetcher } from "../jwks.js";
import { AuthgentError } from "../errors.js";

const IDENTITY_KEY = "__authgent_identity__";

// Extend Express Request type
declare global {
  namespace Express {
    interface Request {
      [IDENTITY_KEY]?: AgentIdentity;
    }
  }
}

export interface AgentAuthOptions {
  /** Issuer URL of the authgent server. */
  issuer: string;
  /** Expected audience. Omit to skip audience validation. */
  audience?: string;
  /** Custom JWKS fetcher. */
  jwksFetcher?: JWKSFetcher;
  /** Paths to skip authentication on. Default: ["/health", "/ready"]. */
  skipPaths?: string[];
}

/**
 * Express middleware that verifies tokens on every request.
 * Stores verified identity on the request object.
 * Does NOT reject unauthenticated requests — use `requireAgentAuth` for that.
 */
export function agentAuth(options: AgentAuthOptions): RequestHandler {
  const {
    issuer,
    audience,
    jwksFetcher,
    skipPaths = ["/health", "/ready"],
  } = options;

  return async (req: Request, _res: Response, next: NextFunction) => {
    // Skip configured paths and well-known endpoints
    if (
      skipPaths.includes(req.path) ||
      req.path.startsWith("/.well-known")
    ) {
      return next();
    }

    // Extract token from Authorization header
    const authHeader = req.headers.authorization ?? "";
    let token = "";
    if (authHeader.startsWith("Bearer ")) {
      token = authHeader.slice(7);
    } else if (authHeader.startsWith("DPoP ")) {
      token = authHeader.slice(5);
    }

    if (!token) {
      return next();
    }

    try {
      const identity = await verifyToken({
        token,
        issuer,
        audience,
        jwksFetcher,
      });
      (req as unknown as Record<string, unknown>)[IDENTITY_KEY] = identity;
    } catch (err) {
      // Let the request through — requireAgentAuth handles enforcement
      if (!(err instanceof AuthgentError)) {
        console.error("[authgent] Unexpected verification error:", err);
      }
    }

    next();
  };
}

/**
 * Extract the verified AgentIdentity from an Express request.
 *
 * @throws Error if no identity is attached (use after agentAuth middleware).
 */
export function getAgentIdentity(req: Request): AgentIdentity {
  const identity = (req as unknown as Record<string, unknown>)[IDENTITY_KEY] as
    | AgentIdentity
    | undefined;
  if (!identity) {
    throw new Error("No valid agent identity on request");
  }
  return identity;
}

/**
 * Express middleware that enforces authentication and optional scope requirements.
 * Returns 401/403 if the request lacks valid credentials or required scopes.
 *
 * @param requiredScopes - Scopes the agent must have. Omit for auth-only check.
 */
export function requireAgentAuth(
  requiredScopes?: string[],
): RequestHandler {
  return (req: Request, res: Response, next: NextFunction) => {
    const identity = (req as unknown as Record<string, unknown>)[IDENTITY_KEY] as
      | AgentIdentity
      | undefined;

    if (!identity) {
      res.status(401).json({
        error: "unauthorized",
        error_description: "Authentication required",
      });
      return;
    }

    if (requiredScopes && requiredScopes.length > 0) {
      const missing = requiredScopes.filter(
        (s) => !identity.scopes.includes(s),
      );
      if (missing.length > 0) {
        res
          .status(403)
          .set(
            "WWW-Authenticate",
            `Bearer scope="${requiredScopes.join(" ")}" error="insufficient_scope"`,
          )
          .json({
            error: "insufficient_scope",
            error_description: `Missing scopes: ${missing.join(", ")}`,
          });
        return;
      }
    }

    next();
  };
}
