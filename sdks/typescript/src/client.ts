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

/** Step-up request response from POST /stepup and GET /stepup/:id. */
export interface StepUpRequestResult {
  id: string;
  agentId: string;
  action: string;
  scope: string;
  resource?: string;
  status: string;
  approvedBy?: string;
  approvedAt?: string;
  expiresAt: string;
  createdAt: string;
}

/** Token exchange pre-check response. */
export interface TokenCheckResult {
  allowed: boolean;
  effectiveScopes: string[];
  delegationDepth: number;
  maxDelegationDepth: number;
  reasons: string[];
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

  /** Request HITL step-up authorization. */
  async requestStepup(options: {
    agentId: string;
    action: string;
    scope: string;
    resource?: string;
    delegationChain?: Record<string, unknown>;
    metadata?: Record<string, unknown>;
  }): Promise<StepUpRequestResult> {
    const payload: Record<string, unknown> = {
      agent_id: options.agentId,
      action: options.action,
      scope: options.scope,
    };
    if (options.resource) payload.resource = options.resource;
    if (options.delegationChain) payload.delegation_chain = options.delegationChain;
    if (options.metadata) payload.metadata = options.metadata;

    const resp = await this.fetchJson("POST", "/stepup", payload);
    return this.parseStepUpResult(resp);
  }

  /** Convenience: extract agent_id from a JWT and create a step-up request. */
  async requestStepupForToken(options: {
    token: string;
    action: string;
    scope: string;
    resource?: string;
  }): Promise<StepUpRequestResult> {
    const claims = this.decodeJwtClaims(options.token);
    const agentId = (claims.client_id as string) || (claims.sub as string) || "";
    return this.requestStepup({
      agentId,
      action: options.action,
      scope: options.scope,
      resource: options.resource,
    });
  }

  /** Poll the status of a step-up request. */
  async checkStepup(requestId: string): Promise<StepUpRequestResult> {
    const resp = await this.fetchJson("GET", `/stepup/${requestId}`, undefined);
    return this.parseStepUpResult(resp);
  }

  /** Dry-run pre-check: will a token exchange succeed? */
  async checkExchange(options: {
    subjectToken: string;
    audience: string;
    clientId: string;
    scope?: string;
  }): Promise<TokenCheckResult> {
    const payload = {
      subject_token: options.subjectToken,
      audience: options.audience,
      client_id: options.clientId,
      scope: options.scope || "",
    };
    const resp = await this.fetchJson("POST", "/token/check", payload);
    return {
      allowed: resp.allowed as boolean,
      effectiveScopes: resp.effective_scopes as string[],
      delegationDepth: resp.delegation_depth as number,
      maxDelegationDepth: resp.max_delegation_depth as number,
      reasons: resp.reasons as string[],
    };
  }

  // ── Internal helpers ───────────────────────────────────────────

  private async fetchJson(
    method: string,
    path: string,
    body: unknown,
  ): Promise<Record<string, unknown>> {
    const init: RequestInit = {
      method,
      headers: { "Content-Type": "application/json" },
      signal: AbortSignal.timeout(this.timeout),
    };
    if (body !== undefined) {
      init.body = JSON.stringify(body);
    }
    const resp = await fetch(`${this.baseUrl}${path}`, init);

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

  private parseStepUpResult(data: Record<string, unknown>): StepUpRequestResult {
    return {
      id: data.id as string,
      agentId: data.agent_id as string,
      action: data.action as string,
      scope: data.scope as string,
      resource: data.resource as string | undefined,
      status: data.status as string,
      approvedBy: data.approved_by as string | undefined,
      approvedAt: data.approved_at as string | undefined,
      expiresAt: data.expires_at as string,
      createdAt: data.created_at as string,
    };
  }

  private decodeJwtClaims(token: string): Record<string, unknown> {
    try {
      const parts = token.split(".");
      if (parts.length !== 3) return {};
      const payload = parts[1]
        .replace(/-/g, "+")
        .replace(/_/g, "/");
      const padded = payload + "=".repeat((4 - (payload.length % 4)) % 4);
      const decoded = atob(padded);
      return JSON.parse(decoded) as Record<string, unknown>;
    } catch {
      return {};
    }
  }
}
