/**
 * MCP Auth Provider adapter — plug authgent into MCP servers.
 *
 * @example
 * ```ts
 * import { AgentAuthProvider } from "authgent/adapters/mcp";
 *
 * const authProvider = new AgentAuthProvider({
 *   serverUrl: "http://localhost:8000",
 * });
 *
 * // In your MCP server handler:
 * const identity = await authProvider.verify(token);
 * console.log(identity.subject, identity.scopes);
 * ```
 */

import { verifyToken } from "../verify.js";
import type { AgentIdentity } from "../models.js";
import type { JWKSFetcher } from "../jwks.js";

export interface AgentAuthProviderOptions {
  /** URL of the authgent server. */
  serverUrl: string;
  /** Expected audience. */
  audience?: string;
  /** Custom JWKS fetcher. */
  jwksFetcher?: JWKSFetcher;
}

export class AgentAuthProvider {
  private readonly serverUrl: string;
  private readonly audience?: string;
  private readonly jwksFetcher?: JWKSFetcher;

  constructor(options: AgentAuthProviderOptions) {
    this.serverUrl = options.serverUrl.replace(/\/+$/, "");
    this.audience = options.audience;
    this.jwksFetcher = options.jwksFetcher;
  }

  /** Verify an access token and return the agent identity. */
  async verify(token: string): Promise<AgentIdentity> {
    return verifyToken({
      token,
      issuer: this.serverUrl,
      audience: this.audience,
      jwksFetcher: this.jwksFetcher,
    });
  }

  /** URL for OAuth server metadata discovery. */
  get metadataUrl(): string {
    return `${this.serverUrl}/.well-known/oauth-authorization-server`;
  }

  /** URL for JWKS endpoint. */
  get jwksUrl(): string {
    return `${this.serverUrl}/.well-known/jwks.json`;
  }
}
