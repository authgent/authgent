/**
 * SDK data models — AgentIdentity, DelegationChain, TokenClaims.
 * Mirrors Python SDK models for cross-language consistency.
 */

/** Raw JWT claims with typed accessors. */
export interface TokenClaims {
  readonly raw: Record<string, unknown>;
  readonly jti?: string;
  readonly exp?: number;
  readonly iat?: number;
  readonly sub?: string;
  readonly iss?: string;
  readonly aud?: string | string[];
  readonly scope?: string;
  readonly client_id?: string;
  readonly cnf?: { jkt?: string };
  readonly act?: ActClaim;
}

/** Nested actor claim per RFC 8693. */
export interface ActClaim {
  sub: string;
  act?: ActClaim;
  [key: string]: unknown;
}

/** Parsed delegation chain from nested act claims. */
export interface DelegationChain {
  /** Flat list of actors from outermost to innermost. */
  readonly actors: Array<{ sub: string }>;
  /** Number of delegation hops. */
  readonly depth: number;
  /** Whether the root of the chain is a human (sub starts with "user:"). */
  readonly humanRoot: boolean;
}

/** OIDC-A agent extension claims (optional). */
export interface AgentExtensionClaims {
  agent_type?: string;
  agent_model?: string;
  agent_version?: string;
  agent_provider?: string;
  agent_instance_id?: string;
}

/** Verified agent identity — attached to request context by middleware. */
export interface AgentIdentity {
  /** Token subject (e.g., "client:agnt_xxx"). */
  readonly subject: string;
  /** Parsed scopes from the scope claim. */
  readonly scopes: string[];
  /** Parsed delegation chain. */
  readonly delegationChain: DelegationChain;
  /** Full token claims. */
  readonly claims: TokenClaims;
  /** OAuth client_id. */
  readonly clientId?: string;
  /** Token audience. */
  readonly audience?: string | string[];
  /** OIDC-A extension claims. */
  readonly agentType?: string;
  readonly agentModel?: string;
  readonly agentVersion?: string;
  readonly agentProvider?: string;
  readonly agentInstanceId?: string;
}

// ── Factory functions ──────────────────────────────────────────────

/** Extract a flat actor list from nested act claims. */
function extractChain(claims: Record<string, unknown>): DelegationChain {
  const actors: Array<{ sub: string }> = [];
  let act = claims.act as ActClaim | undefined;

  while (act && typeof act === "object") {
    actors.push({ sub: act.sub ?? "" });
    act = act.act;
  }

  const depth = actors.length;
  const humanRoot =
    depth > 0 && (actors[depth - 1]?.sub ?? "").startsWith("user:");

  return { actors, depth, humanRoot };
}

/** Build TokenClaims from raw decoded payload. */
export function createTokenClaims(
  raw: Record<string, unknown>,
): TokenClaims {
  return {
    raw,
    jti: raw.jti as string | undefined,
    exp: raw.exp as number | undefined,
    iat: raw.iat as number | undefined,
    sub: raw.sub as string | undefined,
    iss: raw.iss as string | undefined,
    aud: raw.aud as string | string[] | undefined,
    scope: raw.scope as string | undefined,
    client_id: raw.client_id as string | undefined,
    cnf: raw.cnf as { jkt?: string } | undefined,
    act: raw.act as ActClaim | undefined,
  };
}

/** Build AgentIdentity from decoded JWT claims. */
export function createAgentIdentity(
  claims: Record<string, unknown>,
): AgentIdentity {
  const tokenClaims = createTokenClaims(claims);
  const chain = extractChain(claims);
  const scopeStr = (claims.scope as string) ?? "";
  const scopes = scopeStr ? scopeStr.split(" ") : [];

  return {
    subject: (claims.sub as string) ?? "",
    scopes,
    delegationChain: chain,
    claims: tokenClaims,
    clientId: claims.client_id as string | undefined,
    audience: claims.aud as string | string[] | undefined,
    agentType: claims.agent_type as string | undefined,
    agentModel: claims.agent_model as string | undefined,
    agentVersion: claims.agent_version as string | undefined,
    agentProvider: claims.agent_provider as string | undefined,
    agentInstanceId: claims.agent_instance_id as string | undefined,
  };
}

/** Check if an AgentIdentity has a specific actor in its delegation chain. */
export function hasActor(identity: AgentIdentity, sub: string): boolean {
  return identity.delegationChain.actors.some((a) => a.sub === sub);
}
