/**
 * DPoP proof verification and client-side proof generation.
 * RFC 9449 — Demonstrating Proof of Possession.
 */

import * as jose from "jose";
import { DPoPError } from "./errors.js";

const MAX_CLOCK_SKEW = 60; // seconds

// ── Verification (resource server side) ────────────────────────────

export interface VerifyDPoPProofOptions {
  /** AgentIdentity claims dict or object with cnf.jkt. */
  tokenClaims: Record<string, unknown>;
  /** The DPoP proof JWT string. */
  dpopProof: string;
  /** Expected HTTP method (e.g., "POST"). */
  httpMethod: string;
  /** Expected request URI. */
  httpUri: string;
}

/**
 * Verify a DPoP proof JWT against an access token's cnf.jkt binding.
 *
 * @returns Decoded proof payload with `jkt` added.
 * @throws DPoPError if verification fails.
 */
export async function verifyDPoPProof(
  options: VerifyDPoPProofOptions,
): Promise<Record<string, unknown> & { jkt: string }> {
  const { tokenClaims, dpopProof, httpMethod, httpUri } = options;

  // Extract expected JKT from token
  const cnf = tokenClaims.cnf as { jkt?: string } | undefined;
  const expectedJkt = cnf?.jkt;
  if (!expectedJkt) {
    throw new DPoPError("Token does not contain cnf.jkt — not DPoP-bound");
  }

  // Decode header
  let header: jose.ProtectedHeaderParameters;
  try {
    header = jose.decodeProtectedHeader(dpopProof);
  } catch {
    throw new DPoPError("Invalid DPoP proof JWT: cannot decode header");
  }

  if (header.typ !== "dpop+jwt") {
    throw new DPoPError("DPoP proof must have typ=dpop+jwt");
  }

  const jwk = header.jwk as jose.JWK | undefined;
  if (!jwk || jwk.kty !== "EC") {
    throw new DPoPError("DPoP proof must contain EC JWK in header");
  }

  // Import public key from JWK
  let publicKey: jose.KeyLike | Uint8Array;
  try {
    publicKey = await jose.importJWK(jwk, "ES256");
  } catch (err) {
    throw new DPoPError(`Invalid JWK in DPoP proof: ${(err as Error).message}`);
  }

  // Verify signature
  let payload: jose.JWTPayload;
  try {
    const result = await jose.jwtVerify(dpopProof, publicKey, {
      algorithms: ["ES256"],
    });
    payload = result.payload;
  } catch (err) {
    throw new DPoPError(
      `DPoP proof signature invalid: ${(err as Error).message}`,
    );
  }

  // Verify htm and htu
  if (
    typeof payload.htm !== "string" ||
    payload.htm.toUpperCase() !== httpMethod.toUpperCase()
  ) {
    throw new DPoPError(`DPoP htm mismatch: expected ${httpMethod}`);
  }
  if (payload.htu !== httpUri) {
    throw new DPoPError(`DPoP htu mismatch: expected ${httpUri}`);
  }

  // Verify iat freshness
  const iat = payload.iat;
  if (iat === undefined || Math.abs(Date.now() / 1000 - iat) > MAX_CLOCK_SKEW) {
    throw new DPoPError("DPoP proof iat too old or missing");
  }

  // Verify JWK thumbprint matches cnf.jkt
  const jkt = await computeJkt(jwk);
  if (jkt !== expectedJkt) {
    throw new DPoPError("DPoP JWK thumbprint does not match token cnf.jkt");
  }

  return { ...(payload as Record<string, unknown>), jkt };
}

// ── JKT computation ────────────────────────────────────────────────

/** Compute JWK Thumbprint (RFC 7638) for an EC key. */
export async function computeJkt(jwk: jose.JWK): Promise<string> {
  const thumbprint = await jose.calculateJwkThumbprint(jwk, "sha256");
  return thumbprint;
}

// ── Client-side proof generation ───────────────────────────────────

/**
 * Client-side DPoP proof generator.
 * Creates an ephemeral EC key pair on instantiation.
 *
 * @example
 * ```ts
 * const dpop = await DPoPClient.create();
 * const proof = await dpop.createProof("POST", "https://api.example.com/data");
 * const headers = await dpop.createProofHeaders(accessToken, "POST", url);
 * // headers = { Authorization: "DPoP eyJ...", DPoP: "eyJ..." }
 * ```
 */
export class DPoPClient {
  private privateKey!: jose.KeyLike;
  private jwk!: jose.JWK;
  private _jkt!: string;

  private constructor() {}

  /** Factory method — generates ephemeral EC P-256 key pair. */
  static async create(): Promise<DPoPClient> {
    const client = new DPoPClient();
    const { publicKey, privateKey } = await jose.generateKeyPair("ES256");
    client.privateKey = privateKey;

    const exported = await jose.exportJWK(publicKey);
    // Only include required fields for JWK thumbprint
    client.jwk = {
      kty: exported.kty,
      crv: exported.crv,
      x: exported.x,
      y: exported.y,
    };
    client._jkt = await computeJkt(client.jwk);

    return client;
  }

  /** JWK Thumbprint for cnf.jkt binding. */
  get jkt(): string {
    return this._jkt;
  }

  /**
   * Create a DPoP proof JWT.
   *
   * @param httpMethod - HTTP method (e.g., "POST").
   * @param httpUri - Target URI.
   * @param accessToken - If provided, includes `ath` (access token hash).
   * @param nonce - Server-provided nonce.
   */
  async createProof(
    httpMethod: string,
    httpUri: string,
    accessToken?: string,
    nonce?: string,
  ): Promise<string> {
    const payload: jose.JWTPayload & Record<string, unknown> = {
      jti: crypto.randomUUID(),
      htm: httpMethod.toUpperCase(),
      htu: httpUri,
      iat: Math.floor(Date.now() / 1000),
    };

    if (accessToken) {
      // ath = base64url(SHA-256(access_token))
      const encoder = new TextEncoder();
      const digest = await crypto.subtle.digest(
        "SHA-256",
        encoder.encode(accessToken),
      );
      payload.ath = jose.base64url.encode(new Uint8Array(digest));
    }

    if (nonce) {
      payload.nonce = nonce;
    }

    return new jose.SignJWT(payload)
      .setProtectedHeader({
        typ: "dpop+jwt",
        alg: "ES256",
        jwk: this.jwk,
      })
      .sign(this.privateKey);
  }

  /**
   * Create Authorization + DPoP headers for a request.
   *
   * @returns `{ Authorization: "DPoP <token>", DPoP: "<proof>" }`
   */
  async createProofHeaders(
    accessToken: string,
    httpMethod: string,
    httpUri: string,
    nonce?: string,
  ): Promise<{ Authorization: string; DPoP: string }> {
    const proof = await this.createProof(
      httpMethod,
      httpUri,
      accessToken,
      nonce,
    );
    return {
      Authorization: `DPoP ${accessToken}`,
      DPoP: proof,
    };
  }
}
