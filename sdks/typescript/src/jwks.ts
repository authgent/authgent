/**
 * JWKS fetcher with TTL cache — fetches public keys from authgent-server
 * or any OIDC-compliant issuer. Uses a mutex to prevent thundering-herd
 * on cache miss.
 */

import * as jose from "jose";
import { InvalidTokenError } from "./errors.js";

/** In-memory JWKS cache entry. */
interface CacheEntry {
  keys: Map<string, jose.JWK>;
  fetchedAt: number;
}

export class JWKSFetcher {
  private readonly issuer: string;
  private readonly cacheTtlMs: number;
  private cache: CacheEntry | null = null;
  private refreshPromise: Promise<void> | null = null;

  /**
   * @param issuer - Base URL of the authorization server.
   * @param cacheTtlSeconds - How long to cache the JWKS (default 300s).
   */
  constructor(issuer: string, cacheTtlSeconds = 300) {
    this.issuer = issuer.replace(/\/+$/, "");
    this.cacheTtlMs = cacheTtlSeconds * 1000;
  }

  /** Get a JWK by kid. Auto-fetches and caches. */
  async getKey(kid: string): Promise<jose.JWK> {
    // Fast path: key in cache and cache is fresh
    if (this.cache && !this.isStale()) {
      const key = this.cache.keys.get(kid);
      if (key) return key;
    }

    // Cache miss or stale — refresh
    await this.refresh();

    // Check again after refresh
    if (this.cache) {
      const key = this.cache.keys.get(kid);
      if (key) return key;
    }

    // Key rotation: one forced re-fetch
    await this.refresh(true);

    const key = this.cache?.keys.get(kid);
    if (!key) {
      throw new InvalidTokenError(`Unknown signing key: ${kid}`);
    }
    return key;
  }

  /** Get all cached keys, refreshing if stale. */
  async getAllKeys(): Promise<Map<string, jose.JWK>> {
    if (!this.cache || this.isStale()) {
      await this.refresh();
    }
    return new Map(this.cache?.keys ?? []);
  }

  /** Refresh the JWKS cache. Uses a mutex to prevent concurrent fetches. */
  private async refresh(force = false): Promise<void> {
    // If a refresh is already in progress, wait for it
    if (this.refreshPromise) {
      await this.refreshPromise;
      if (!force) return;
    }

    // Double-check after acquiring
    if (!force && this.cache && !this.isStale()) {
      return;
    }

    this.refreshPromise = this.doRefresh();
    try {
      await this.refreshPromise;
    } finally {
      this.refreshPromise = null;
    }
  }

  private async doRefresh(): Promise<void> {
    const url = `${this.issuer}/.well-known/jwks.json`;
    const response = await fetch(url, {
      signal: AbortSignal.timeout(10_000),
    });

    if (!response.ok) {
      throw new InvalidTokenError(
        `Failed to fetch JWKS from ${url}: ${response.status}`,
      );
    }

    const jwks = (await response.json()) as { keys?: jose.JWK[] };
    const keys = new Map<string, jose.JWK>();
    for (const key of jwks.keys ?? []) {
      if (key.kid) {
        keys.set(key.kid, key);
      }
    }

    this.cache = { keys, fetchedAt: Date.now() };
  }

  private isStale(): boolean {
    if (!this.cache) return true;
    return Date.now() - this.cache.fetchedAt > this.cacheTtlMs;
  }
}

// ── Module-level fetcher cache (keyed by issuer) ───────────────────

const fetchers = new Map<string, JWKSFetcher>();

/** Get or create a cached JWKSFetcher for an issuer. */
export function getFetcher(
  issuer: string,
  cacheTtlSeconds?: number,
): JWKSFetcher {
  const key = issuer.replace(/\/+$/, "");
  let fetcher = fetchers.get(key);
  if (!fetcher) {
    fetcher = new JWKSFetcher(issuer, cacheTtlSeconds);
    fetchers.set(key, fetcher);
  }
  return fetcher;
}
