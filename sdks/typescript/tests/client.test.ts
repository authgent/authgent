/**
 * Tests for AgentAuthClient — stepup, checkExchange, decodeJwtClaims.
 */

import { describe, it, expect, vi, beforeEach } from "vitest";
import { AgentAuthClient } from "../src/client.js";

// ── Helpers ──────────────────────────────────────────────────────────────

function fakeJwt(claims: Record<string, unknown>): string {
  const header = btoa(JSON.stringify({ alg: "ES256", typ: "JWT" }))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
  const payload = btoa(JSON.stringify(claims))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
  return `${header}.${payload}.fake_signature`;
}

function mockFetch(status: number, body: Record<string, unknown>) {
  return vi.fn().mockResolvedValue({
    ok: status >= 200 && status < 300,
    status,
    json: () => Promise.resolve(body),
    text: () => Promise.resolve(JSON.stringify(body)),
  });
}

// ══════════════════════════════════════════════════════════════════════════

describe("AgentAuthClient", () => {
  let client: AgentAuthClient;

  beforeEach(() => {
    client = new AgentAuthClient("http://localhost:8000");
  });

  // ── requestStepup ────────────────────────────────────────────────────

  describe("requestStepup", () => {
    it("sends correct payload with agent_id, action, scope", async () => {
      const fetchMock = mockFetch(202, {
        id: "req_1",
        agent_id: "agent-1",
        action: "delete",
        scope: "admin",
        status: "pending",
        expires_at: "2026-01-01T00:00:00",
        created_at: "2026-01-01T00:00:00",
      });
      vi.stubGlobal("fetch", fetchMock);

      const result = await client.requestStepup({
        agentId: "agent-1",
        action: "delete",
        scope: "admin",
        resource: "https://api.example.com/records",
      });

      expect(result.id).toBe("req_1");
      expect(result.status).toBe("pending");
      expect(result.agentId).toBe("agent-1");

      // Verify payload
      const callBody = JSON.parse(fetchMock.mock.calls[0][1].body);
      expect(callBody.agent_id).toBe("agent-1");
      expect(callBody.action).toBe("delete");
      expect(callBody.scope).toBe("admin");
      expect(callBody.resource).toBe("https://api.example.com/records");
      // Must NOT contain old broken fields
      expect(callBody.token).toBeUndefined();
      expect(callBody.reason).toBeUndefined();

      vi.unstubAllGlobals();
    });

    it("sends minimal payload without optional fields", async () => {
      const fetchMock = mockFetch(202, {
        id: "req_2",
        agent_id: "a1",
        action: "act",
        scope: "s1",
        status: "pending",
        expires_at: "2026-01-01T00:00:00",
        created_at: "2026-01-01T00:00:00",
      });
      vi.stubGlobal("fetch", fetchMock);

      await client.requestStepup({ agentId: "a1", action: "act", scope: "s1" });

      const callBody = JSON.parse(fetchMock.mock.calls[0][1].body);
      expect(callBody.resource).toBeUndefined();
      expect(callBody.delegation_chain).toBeUndefined();
      expect(callBody.metadata).toBeUndefined();

      vi.unstubAllGlobals();
    });
  });

  // ── requestStepupForToken ────────────────────────────────────────────

  describe("requestStepupForToken", () => {
    it("extracts client_id from JWT and uses as agentId", async () => {
      const token = fakeJwt({ sub: "client:agnt_xyz", client_id: "agnt_xyz" });
      const fetchMock = mockFetch(202, {
        id: "req_3",
        agent_id: "agnt_xyz",
        action: "escalate",
        scope: "admin",
        status: "pending",
        expires_at: "2026-01-01T00:00:00",
        created_at: "2026-01-01T00:00:00",
      });
      vi.stubGlobal("fetch", fetchMock);

      await client.requestStepupForToken({
        token,
        action: "escalate",
        scope: "admin",
      });

      const callBody = JSON.parse(fetchMock.mock.calls[0][1].body);
      expect(callBody.agent_id).toBe("agnt_xyz");
      expect(callBody.action).toBe("escalate");

      vi.unstubAllGlobals();
    });

    it("falls back to sub when client_id is missing", async () => {
      const token = fakeJwt({ sub: "client:fallback_id" });
      const fetchMock = mockFetch(202, {
        id: "req_4",
        agent_id: "client:fallback_id",
        action: "act",
        scope: "read",
        status: "pending",
        expires_at: "2026-01-01T00:00:00",
        created_at: "2026-01-01T00:00:00",
      });
      vi.stubGlobal("fetch", fetchMock);

      await client.requestStepupForToken({ token, action: "act", scope: "read" });

      const callBody = JSON.parse(fetchMock.mock.calls[0][1].body);
      expect(callBody.agent_id).toBe("client:fallback_id");

      vi.unstubAllGlobals();
    });
  });

  // ── checkStepup ──────────────────────────────────────────────────────

  describe("checkStepup", () => {
    it("polls step-up request status via GET", async () => {
      const fetchMock = mockFetch(200, {
        id: "req_1",
        agent_id: "agent-1",
        action: "delete",
        scope: "admin",
        status: "approved",
        approved_by: "human@corp.com",
        expires_at: "2026-01-01T00:00:00",
        created_at: "2026-01-01T00:00:00",
      });
      vi.stubGlobal("fetch", fetchMock);

      const result = await client.checkStepup("req_1");
      expect(result.status).toBe("approved");
      expect(result.approvedBy).toBe("human@corp.com");

      // Verify GET request to correct URL
      expect(fetchMock.mock.calls[0][0]).toBe("http://localhost:8000/stepup/req_1");
      expect(fetchMock.mock.calls[0][1].method).toBe("GET");

      vi.unstubAllGlobals();
    });
  });

  // ── checkExchange ────────────────────────────────────────────────────

  describe("checkExchange", () => {
    it("sends pre-check payload and parses response", async () => {
      const fetchMock = mockFetch(200, {
        allowed: true,
        effective_scopes: ["read"],
        delegation_depth: 0,
        max_delegation_depth: 5,
        reasons: [],
      });
      vi.stubGlobal("fetch", fetchMock);

      const result = await client.checkExchange({
        subjectToken: "eyJ...",
        audience: "https://target.example.com",
        clientId: "agnt_123",
        scope: "read",
      });

      expect(result.allowed).toBe(true);
      expect(result.effectiveScopes).toEqual(["read"]);
      expect(result.delegationDepth).toBe(0);
      expect(result.maxDelegationDepth).toBe(5);
      expect(result.reasons).toEqual([]);

      const callBody = JSON.parse(fetchMock.mock.calls[0][1].body);
      expect(callBody.subject_token).toBe("eyJ...");
      expect(callBody.audience).toBe("https://target.example.com");
      expect(callBody.client_id).toBe("agnt_123");

      vi.unstubAllGlobals();
    });

    it("reports denial reasons", async () => {
      const fetchMock = mockFetch(200, {
        allowed: false,
        effective_scopes: [],
        delegation_depth: 0,
        max_delegation_depth: 5,
        reasons: ["Scope escalation: admin not in parent scopes"],
      });
      vi.stubGlobal("fetch", fetchMock);

      const result = await client.checkExchange({
        subjectToken: "eyJ...",
        audience: "https://target.example.com",
        clientId: "agnt_123",
        scope: "admin",
      });

      expect(result.allowed).toBe(false);
      expect(result.reasons).toHaveLength(1);
      expect(result.reasons[0]).toContain("escalation");

      vi.unstubAllGlobals();
    });
  });

  // ── introspectToken ──────────────────────────────────────────────────

  describe("introspectToken", () => {
    it("posts to /introspect with form data", async () => {
      const fetchMock = mockFetch(200, {
        active: true,
        sub: "client:agnt_1",
        scope: "read",
      });
      vi.stubGlobal("fetch", fetchMock);

      const result = await client.introspectToken("access_token_here", "c1");
      expect(result.active).toBe(true);
      expect(result.scope).toBe("read");

      vi.unstubAllGlobals();
    });
  });
});
