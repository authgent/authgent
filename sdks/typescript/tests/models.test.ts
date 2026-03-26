import { describe, it, expect } from "vitest";
import {
  createAgentIdentity,
  createTokenClaims,
  hasActor,
} from "../src/models.js";

describe("createTokenClaims", () => {
  it("extracts standard JWT claims", () => {
    const raw = {
      jti: "tok_abc",
      exp: 1700000000,
      iat: 1699999000,
      sub: "client:agnt_123",
      iss: "http://localhost:8000",
      aud: "https://api.example.com",
      scope: "read write",
      client_id: "agnt_123",
    };
    const claims = createTokenClaims(raw);
    expect(claims.jti).toBe("tok_abc");
    expect(claims.exp).toBe(1700000000);
    expect(claims.iat).toBe(1699999000);
    expect(claims.sub).toBe("client:agnt_123");
    expect(claims.iss).toBe("http://localhost:8000");
    expect(claims.aud).toBe("https://api.example.com");
    expect(claims.scope).toBe("read write");
    expect(claims.client_id).toBe("agnt_123");
    expect(claims.raw).toBe(raw);
  });

  it("handles missing optional claims", () => {
    const claims = createTokenClaims({});
    expect(claims.jti).toBeUndefined();
    expect(claims.cnf).toBeUndefined();
    expect(claims.act).toBeUndefined();
  });

  it("extracts cnf.jkt for DPoP", () => {
    const claims = createTokenClaims({ cnf: { jkt: "thumbprint123" } });
    expect(claims.cnf?.jkt).toBe("thumbprint123");
  });
});

describe("createAgentIdentity", () => {
  it("builds identity from basic claims", () => {
    const identity = createAgentIdentity({
      sub: "client:agnt_abc",
      scope: "search:execute tools:read",
      iss: "http://localhost:8000",
      aud: "https://api.example.com",
      client_id: "agnt_abc",
    });

    expect(identity.subject).toBe("client:agnt_abc");
    expect(identity.scopes).toEqual(["search:execute", "tools:read"]);
    expect(identity.clientId).toBe("agnt_abc");
    expect(identity.audience).toBe("https://api.example.com");
    expect(identity.delegationChain.depth).toBe(0);
    expect(identity.delegationChain.actors).toEqual([]);
    expect(identity.delegationChain.humanRoot).toBe(false);
  });

  it("parses single-hop delegation chain", () => {
    const identity = createAgentIdentity({
      sub: "client:agnt_A",
      scope: "read",
      act: { sub: "client:agnt_B" },
    });

    expect(identity.delegationChain.depth).toBe(1);
    expect(identity.delegationChain.actors).toEqual([
      { sub: "client:agnt_B" },
    ]);
    expect(identity.delegationChain.humanRoot).toBe(false);
  });

  it("parses multi-hop delegation chain with human root", () => {
    const identity = createAgentIdentity({
      sub: "client:agnt_A",
      scope: "read",
      act: {
        sub: "client:agnt_B",
        act: {
          sub: "user:alice",
        },
      },
    });

    expect(identity.delegationChain.depth).toBe(2);
    expect(identity.delegationChain.actors).toEqual([
      { sub: "client:agnt_B" },
      { sub: "user:alice" },
    ]);
    expect(identity.delegationChain.humanRoot).toBe(true);
  });

  it("handles empty scope", () => {
    const identity = createAgentIdentity({ sub: "test" });
    expect(identity.scopes).toEqual([]);
  });

  it("extracts OIDC-A extension claims", () => {
    const identity = createAgentIdentity({
      sub: "client:agnt_1",
      scope: "",
      agent_type: "assistant",
      agent_model: "gpt-4",
      agent_version: "2.0",
      agent_provider: "openai",
      agent_instance_id: "inst_xyz",
    });

    expect(identity.agentType).toBe("assistant");
    expect(identity.agentModel).toBe("gpt-4");
    expect(identity.agentVersion).toBe("2.0");
    expect(identity.agentProvider).toBe("openai");
    expect(identity.agentInstanceId).toBe("inst_xyz");
  });
});

describe("hasActor", () => {
  it("returns true when actor is in chain", () => {
    const identity = createAgentIdentity({
      sub: "client:agnt_A",
      scope: "",
      act: { sub: "client:agnt_B", act: { sub: "user:alice" } },
    });
    expect(hasActor(identity, "client:agnt_B")).toBe(true);
    expect(hasActor(identity, "user:alice")).toBe(true);
  });

  it("returns false when actor is not in chain", () => {
    const identity = createAgentIdentity({
      sub: "client:agnt_A",
      scope: "",
      act: { sub: "client:agnt_B" },
    });
    expect(hasActor(identity, "client:agnt_C")).toBe(false);
  });

  it("returns false for empty chain", () => {
    const identity = createAgentIdentity({ sub: "client:agnt_A", scope: "" });
    expect(hasActor(identity, "anyone")).toBe(false);
  });
});
