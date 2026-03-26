/**
 * MCP scope challenge auto-detection + HITL step-up trigger.
 *
 * When an MCP server returns 403 with WWW-Authenticate containing
 * insufficient_scope, this module automatically:
 * 1. Detects the missing scope from the challenge
 * 2. Checks if the scope is in the HITL_SCOPES list
 * 3. Initiates a step-up request via POST /stepup
 * 4. Polls for approval
 * 5. Returns the step-up token for retry
 */

import {
  AuthgentError,
  StepUpDeniedError,
  StepUpTimeoutError,
} from "./errors.js";

/** Parsed WWW-Authenticate scope challenge. */
export interface ScopeChallenge {
  requiredScope: string;
  error: string;
  realm: string;
}

/** Result of a step-up flow. */
export interface StepUpResult {
  stepupId: string;
  status: "approved" | "denied" | "expired";
  stepUpToken?: string;
}

/**
 * Parse a WWW-Authenticate header for scope challenge info.
 *
 * @example
 * ```
 * Bearer scope="db:delete" error="insufficient_scope"
 * ```
 */
export function parseScopeChallenge(
  wwwAuthenticate: string,
): ScopeChallenge | null {
  if (!wwwAuthenticate.includes("insufficient_scope")) {
    return null;
  }

  let scope = "";
  let error = "insufficient_scope";
  let realm = "";

  for (const part of wwwAuthenticate.split(/\s+/)) {
    if (part.includes("=")) {
      const eqIdx = part.indexOf("=");
      const key = part.slice(0, eqIdx).replace(/,/g, "").trim();
      const value = part
        .slice(eqIdx + 1)
        .replace(/^"/, "")
        .replace(/"$/, "")
        .replace(/,/g, "")
        .trim();

      if (key === "scope") scope = value;
      else if (key === "error") error = value;
      else if (key === "realm") realm = value;
    }
  }

  if (!scope) return null;

  return { requiredScope: scope, error, realm };
}

export interface ScopeChallengeHandlerOptions {
  /** URL of the authgent server. */
  serverUrl: string;
  /** Scopes that should trigger HITL step-up. */
  hitlScopes?: string[];
  /** Polling interval in ms. Default: 2000. */
  pollIntervalMs?: number;
  /** Timeout in ms. Default: 300000 (5 min). */
  timeoutMs?: number;
  /** HTTP request timeout in ms. Default: 30000. */
  httpTimeoutMs?: number;
}

/**
 * Automatic scope challenge detection and step-up flow for MCP clients.
 *
 * @example
 * ```ts
 * const handler = new ScopeChallengeHandler({
 *   serverUrl: "http://localhost:8000",
 *   hitlScopes: ["db:delete", "bank:transfer"],
 * });
 *
 * // After receiving a 403 from an MCP server:
 * if (handler.isScopeChallenge(response)) {
 *   const result = await handler.handleChallenge(response, {
 *     agentId: "agent:my-agent",
 *     resource: "https://mcp-server.example.com",
 *   });
 *   if (result?.stepUpToken) {
 *     // Retry with step-up token
 *   }
 * }
 * ```
 */
export class ScopeChallengeHandler {
  private readonly serverUrl: string;
  private readonly hitlScopes: Set<string>;
  private readonly pollIntervalMs: number;
  private readonly timeoutMs: number;
  private readonly httpTimeoutMs: number;

  constructor(options: ScopeChallengeHandlerOptions) {
    this.serverUrl = options.serverUrl.replace(/\/+$/, "");
    this.hitlScopes = new Set(options.hitlScopes ?? []);
    this.pollIntervalMs = options.pollIntervalMs ?? 2000;
    this.timeoutMs = options.timeoutMs ?? 300_000;
    this.httpTimeoutMs = options.httpTimeoutMs ?? 30_000;
  }

  /** Check if an HTTP response is a scope challenge requiring step-up. */
  isScopeChallenge(response: { status: number; headers: Headers }): boolean {
    if (response.status !== 403) return false;
    const wwwAuth = response.headers.get("WWW-Authenticate") ?? "";
    const challenge = parseScopeChallenge(wwwAuth);
    if (!challenge) return false;
    return this.isHitlScope(challenge.requiredScope);
  }

  /** Handle a 403 scope challenge by initiating and polling a step-up request. */
  async handleChallenge(
    response: { status: number; headers: Headers },
    options: {
      agentId: string;
      resource?: string;
      delegationChain?: Array<Record<string, unknown>>;
      accessToken?: string;
    },
  ): Promise<StepUpResult | null> {
    const wwwAuth = response.headers.get("WWW-Authenticate") ?? "";
    const challenge = parseScopeChallenge(wwwAuth);
    if (!challenge) return null;

    // 1. POST /stepup to initiate step-up request
    const headers: Record<string, string> = {
      "Content-Type": "application/json",
    };
    if (options.accessToken) {
      headers["Authorization"] = `Bearer ${options.accessToken}`;
    }

    const stepupPayload: Record<string, unknown> = {
      agent_id: options.agentId,
      action: "scope_escalation",
      scope: challenge.requiredScope,
      resource: options.resource ?? "",
    };
    if (options.delegationChain) {
      stepupPayload.delegation_chain_snapshot = options.delegationChain;
    }

    const initResp = await fetch(`${this.serverUrl}/stepup`, {
      method: "POST",
      headers,
      body: JSON.stringify(stepupPayload),
      signal: AbortSignal.timeout(this.httpTimeoutMs),
    });

    if (!initResp.ok) {
      throw new AuthgentError(
        `Step-up request failed: ${initResp.status} ${await initResp.text()}`,
      );
    }

    const initData = (await initResp.json()) as Record<string, unknown>;
    const stepupId = initData.id as string;

    // 2. Poll for approval
    let elapsed = 0;
    while (elapsed < this.timeoutMs) {
      await sleep(this.pollIntervalMs);
      elapsed += this.pollIntervalMs;

      const pollResp = await fetch(`${this.serverUrl}/stepup/${stepupId}`, {
        headers,
        signal: AbortSignal.timeout(this.httpTimeoutMs),
      });

      if (!pollResp.ok) continue;

      const pollData = (await pollResp.json()) as Record<string, unknown>;
      const status = pollData.status as string;

      if (status === "approved") {
        return {
          stepupId,
          status: "approved",
          stepUpToken: pollData.step_up_token as string | undefined,
        };
      } else if (status === "denied") {
        throw new StepUpDeniedError(
          `Step-up request ${stepupId} was denied`,
        );
      } else if (status === "expired") {
        throw new StepUpTimeoutError(
          `Step-up request ${stepupId} expired`,
        );
      }
      // else: still pending, continue polling
    }

    throw new StepUpTimeoutError(
      `Step-up request ${stepupId} timed out after ${this.timeoutMs}ms`,
    );
  }

  private isHitlScope(scope: string): boolean {
    if (this.hitlScopes.size === 0) return false;
    return scope.split(/\s+/).some((s) => this.hitlScopes.has(s));
  }
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
