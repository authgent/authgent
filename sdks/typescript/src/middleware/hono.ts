/**
 * Hono middleware — agentAuth + requireAgentAuth + getAgentIdentity.
 * Hono is the modern edge-first framework — works on Cloudflare Workers,
 * Deno, Bun, and Node.
 *
 * @example
 * ```ts
 * import { Hono } from "hono";
 * import { agentAuth, requireAgentAuth, getAgentIdentity } from "authgent/middleware/hono";
 *
 * const app = new Hono();
 * app.use("*", agentAuth({ issuer: "http://localhost:8000" }));
 *
 * app.post("/tools/search", requireAgentAuth(["search:execute"]), (c) => {
 *   const identity = getAgentIdentity(c);
 *   return c.json({ agent: identity.subject });
 * });
 * ```
 */

import type { Context, MiddlewareHandler } from "hono";
import { verifyToken } from "../verify.js";
import type { AgentIdentity } from "../models.js";
import type { JWKSFetcher } from "../jwks.js";
import { AuthgentError } from "../errors.js";

const IDENTITY_KEY = "authgent_identity";

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
 * Hono middleware that verifies tokens on every request.
 * Stores verified identity in Hono context variables.
 * Does NOT reject unauthenticated requests — use `requireAgentAuth` for that.
 */
export function agentAuth(options: AgentAuthOptions): MiddlewareHandler {
  const {
    issuer,
    audience,
    jwksFetcher,
    skipPaths = ["/health", "/ready"],
  } = options;

  return async (c, next) => {
    const path = new URL(c.req.url).pathname;

    // Skip configured paths and well-known endpoints
    if (skipPaths.includes(path) || path.startsWith("/.well-known")) {
      return next();
    }

    // Extract token from Authorization header
    const authHeader = c.req.header("Authorization") ?? "";
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
      c.set(IDENTITY_KEY, identity);
    } catch (err) {
      if (!(err instanceof AuthgentError)) {
        console.error("[authgent] Unexpected verification error:", err);
      }
    }

    return next();
  };
}

/**
 * Extract the verified AgentIdentity from Hono context.
 *
 * @throws Error if no identity is attached.
 */
export function getAgentIdentity(c: Context): AgentIdentity {
  const identity = c.get(IDENTITY_KEY) as AgentIdentity | undefined;
  if (!identity) {
    throw new Error("No valid agent identity on request");
  }
  return identity;
}

/**
 * Hono middleware that enforces authentication and optional scope requirements.
 * Returns 401/403 if the request lacks valid credentials or required scopes.
 */
export function requireAgentAuth(
  requiredScopes?: string[],
): MiddlewareHandler {
  return async (c, next) => {
    const identity = c.get(IDENTITY_KEY) as AgentIdentity | undefined;

    if (!identity) {
      return c.json(
        {
          error: "unauthorized",
          error_description: "Authentication required",
        },
        401,
      );
    }

    if (requiredScopes && requiredScopes.length > 0) {
      const missing = requiredScopes.filter(
        (s) => !identity.scopes.includes(s),
      );
      if (missing.length > 0) {
        return c.json(
          {
            error: "insufficient_scope",
            error_description: `Missing scopes: ${missing.join(", ")}`,
          },
          403,
          {
            "WWW-Authenticate": `Bearer scope="${requiredScopes.join(" ")}" error="insufficient_scope"`,
          },
        );
      }
    }

    return next();
  };
}
