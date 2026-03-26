/**
 * AgentAuthClient — server API wrapper for token operations.
 * Uses native fetch — zero HTTP library dependencies.
 */

import { ServerError } from "./errors.js";

/** Token endpoint response. */
export interface TokenResult {
  accessToken: string;
  tokenType: string;
  expiresIn: number;
  scope?: string;
  refreshToken?: string;
}

/** Agent creation response with credentials. */
export interface AgentResult {
  id: string;
  clientId: string;
  clientSecret: string;
  name: string;
}

/**
 * Client for the authgent-server API.
 *
 * @example
 * ```ts
 * const client = new AgentAuthClient("http://localhost:8000");
 *
 * // Register an agent
 * const agent = await client.registerAgent({ name: "search-bot" });
 *
 * // Get a token
 * const token = await client.getToken({
 *   clientId: agent.clientId,
 *   clientSecret: agent.clientSecret,
 *   scope: "search:execute",
 * });
 * ```
 */
export class AgentAuthClient {
  private readonly baseUrl: string;
  private readonly timeout: number;

  constructor(serverUrl: string, timeout = 30_000) {
    this.baseUrl = serverUrl.replace(/\/+$/, "");
    this.timeout = timeout;
  }

  /** Register a new agent — returns agent with credentials. */
  async registerAgent(options: {
    name: string;
    scopes?: string[];
    owner?: string;
    capabilities?: string[];
  }): Promise<AgentResult> {
    const payload: Record<string, unknown> = { name: options.name };
    if (options.scopes) payload.allowed_scopes = options.scopes;
    if (options.owner) payload.owner = options.owner;
    if (options.capabilities) payload.capabilities = options.capabilities;

    const resp = await this.fetchJson("POST", "/agents", payload);
    return {
      id: resp.id as string,
      clientId: resp.client_id as string,
      clientSecret: resp.client_secret as string,
      name: resp.name as string,
    };
  }

  /** Get an access token via client_credentials grant. */
  async getToken(options: {
    clientId: string;
    clientSecret: string;
    scope?: string;
    resource?: string;
  }): Promise<TokenResult> {
    const body = new URLSearchParams({
      grant_type: "client_credentials",
      client_id: options.clientId,
      client_secret: options.clientSecret,
    });
    if (options.scope) body.set("scope", options.scope);
    if (options.resource) body.set("resource", options.resource);

    const resp = await this.fetchForm("POST", "/token", body);
    return this.parseTokenResult(resp);
  }

  /** Exchange a token for a downstream delegated token (RFC 8693). */
  async exchangeToken(options: {
    subjectToken: string;
    audience: string;
    scopes?: string[];
    clientId?: string;
    clientSecret?: string;
  }): Promise<TokenResult> {
    const body = new URLSearchParams({
      grant_type: "urn:ietf:params:oauth:grant-type:token-exchange",
      subject_token: options.subjectToken,
      subject_token_type: "urn:ietf:params:oauth:token-type:access_token",
      audience: options.audience,
    });
    if (options.scopes) body.set("scope", options.scopes.join(" "));
    if (options.clientId) body.set("client_id", options.clientId);
    if (options.clientSecret) body.set("client_secret", options.clientSecret);

    const resp = await this.fetchForm("POST", "/token", body);
    return this.parseTokenResult(resp);
  }

  /** Refresh an access token. */
  async refreshToken(options: {
    refreshToken: string;
    clientId: string;
    clientSecret: string;
  }): Promise<TokenResult> {
    const body = new URLSearchParams({
      grant_type: "refresh_token",
      refresh_token: options.refreshToken,
      client_id: options.clientId,
      client_secret: options.clientSecret,
    });

    const resp = await this.fetchForm("POST", "/token", body);
    return this.parseTokenResult(resp);
  }

  /** Revoke an access or refresh token. */
  async revokeToken(token: string, clientId?: string): Promise<void> {
    const body = new URLSearchParams({ token });
    if (clientId) body.set("client_id", clientId);

    const resp = await fetch(`${this.baseUrl}/revoke`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: body.toString(),
      signal: AbortSignal.timeout(this.timeout),
    });

    if (!resp.ok && resp.status !== 200 && resp.status !== 204) {
      throw new ServerError(`Token revocation failed: ${await resp.text()}`);
    }
  }

  /** Introspect a token. */
  async introspectToken(
    token: string,
    clientId?: string,
    clientSecret?: string,
  ): Promise<Record<string, unknown>> {
    const body = new URLSearchParams({ token });
    if (clientId) body.set("client_id", clientId);
    if (clientSecret) body.set("client_secret", clientSecret);

    return this.fetchForm("POST", "/introspect", body);
  }

  // ── Internal helpers ───────────────────────────────────────────

  private async fetchJson(
    method: string,
    path: string,
    body: unknown,
  ): Promise<Record<string, unknown>> {
    const resp = await fetch(`${this.baseUrl}${path}`, {
      method,
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(this.timeout),
    });

    if (!resp.ok) {
      throw new ServerError(
        `Request ${method} ${path} failed (${resp.status}): ${await resp.text()}`,
      );
    }

    return resp.json() as Promise<Record<string, unknown>>;
  }

  private async fetchForm(
    method: string,
    path: string,
    body: URLSearchParams,
  ): Promise<Record<string, unknown>> {
    const resp = await fetch(`${this.baseUrl}${path}`, {
      method,
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: body.toString(),
      signal: AbortSignal.timeout(this.timeout),
    });

    if (!resp.ok) {
      throw new ServerError(
        `Request ${method} ${path} failed (${resp.status}): ${await resp.text()}`,
      );
    }

    return resp.json() as Promise<Record<string, unknown>>;
  }

  private parseTokenResult(data: Record<string, unknown>): TokenResult {
    return {
      accessToken: data.access_token as string,
      tokenType: data.token_type as string,
      expiresIn: data.expires_in as number,
      scope: data.scope as string | undefined,
      refreshToken: data.refresh_token as string | undefined,
    };
  }
}
