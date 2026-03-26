/**
 * RFC 9728 — OAuth 2.0 Protected Resource Metadata generator.
 *
 * Generates the /.well-known/oauth-protected-resource JSON document
 * that MCP servers and API servers should serve to advertise their
 * authorization requirements to clients.
 *
 * @example
 * ```ts
 * import { ProtectedResourceMetadata } from "authgent/adapters/protected-resource";
 *
 * const metadata = new ProtectedResourceMetadata({
 *   resource: "https://mcp-server.example.com",
 *   authorizationServers: ["http://localhost:8000"],
 *   scopesSupported: ["tools:execute", "db:read", "db:write"],
 * });
 *
 * // Express:
 * app.get("/.well-known/oauth-protected-resource", (req, res) => {
 *   res.json(metadata.toJSON());
 * });
 *
 * // Hono:
 * app.get("/.well-known/oauth-protected-resource", (c) => c.json(metadata.toJSON()));
 * ```
 */

export interface ProtectedResourceMetadataOptions {
  /** The protected resource identifier (URL). */
  resource: string;
  /** Authorization server URLs that can issue tokens for this resource. */
  authorizationServers: string[];
  /** Scopes this resource understands. */
  scopesSupported?: string[];
  /** Token presentation methods supported. Default: ["header"]. */
  bearerMethodsSupported?: string[];
  /** Signing algorithms accepted. Default: ["ES256"]. */
  resourceSigningAlgValuesSupported?: string[];
  /** URL to human-readable documentation. */
  resourceDocumentation?: string;
  /** URL to the resource's policy. */
  resourcePolicyUri?: string;
  /** URL to the resource's terms of service. */
  resourceTosUri?: string;
  /** DPoP signing algorithms accepted. */
  dpopSigningAlgValuesSupported?: string[];
}

export class ProtectedResourceMetadata {
  private readonly options: ProtectedResourceMetadataOptions;

  constructor(options: ProtectedResourceMetadataOptions) {
    this.options = options;
  }

  /** Generate the RFC 9728 metadata document. */
  toJSON(): Record<string, unknown> {
    const doc: Record<string, unknown> = {
      resource: this.options.resource,
      authorization_servers: this.options.authorizationServers,
    };

    const scopesSupported = this.options.scopesSupported;
    if (scopesSupported?.length) {
      doc.scopes_supported = scopesSupported;
    }

    const bearerMethods =
      this.options.bearerMethodsSupported ?? ["header"];
    if (bearerMethods.length) {
      doc.bearer_methods_supported = bearerMethods;
    }

    const signingAlgs =
      this.options.resourceSigningAlgValuesSupported ?? ["ES256"];
    if (signingAlgs.length) {
      doc.resource_signing_alg_values_supported = signingAlgs;
    }

    if (this.options.resourceDocumentation) {
      doc.resource_documentation = this.options.resourceDocumentation;
    }
    if (this.options.resourcePolicyUri) {
      doc.resource_policy_uri = this.options.resourcePolicyUri;
    }
    if (this.options.resourceTosUri) {
      doc.resource_tos_uri = this.options.resourceTosUri;
    }
    if (this.options.dpopSigningAlgValuesSupported?.length) {
      doc.dpop_signing_alg_values_supported =
        this.options.dpopSigningAlgValuesSupported;
    }

    return doc;
  }

  /** Serialize to JSON string. */
  toString(indent = 2): string {
    return JSON.stringify(this.toJSON(), null, indent);
  }
}
