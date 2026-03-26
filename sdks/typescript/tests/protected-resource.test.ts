import { describe, it, expect } from "vitest";
import { ProtectedResourceMetadata } from "../src/adapters/protected-resource.js";

describe("ProtectedResourceMetadata", () => {
  it("generates minimal RFC 9728 metadata", () => {
    const meta = new ProtectedResourceMetadata({
      resource: "https://mcp-server.example.com",
      authorizationServers: ["http://localhost:8000"],
    });

    const doc = meta.toJSON();
    expect(doc.resource).toBe("https://mcp-server.example.com");
    expect(doc.authorization_servers).toEqual(["http://localhost:8000"]);
    expect(doc.bearer_methods_supported).toEqual(["header"]);
    expect(doc.resource_signing_alg_values_supported).toEqual(["ES256"]);
  });

  it("includes scopes when provided", () => {
    const meta = new ProtectedResourceMetadata({
      resource: "https://api.example.com",
      authorizationServers: ["http://localhost:8000"],
      scopesSupported: ["read", "write", "admin"],
    });

    const doc = meta.toJSON();
    expect(doc.scopes_supported).toEqual(["read", "write", "admin"]);
  });

  it("includes optional fields", () => {
    const meta = new ProtectedResourceMetadata({
      resource: "https://api.example.com",
      authorizationServers: ["http://localhost:8000"],
      resourceDocumentation: "https://docs.example.com",
      resourcePolicyUri: "https://example.com/policy",
      resourceTosUri: "https://example.com/tos",
      dpopSigningAlgValuesSupported: ["ES256"],
    });

    const doc = meta.toJSON();
    expect(doc.resource_documentation).toBe("https://docs.example.com");
    expect(doc.resource_policy_uri).toBe("https://example.com/policy");
    expect(doc.resource_tos_uri).toBe("https://example.com/tos");
    expect(doc.dpop_signing_alg_values_supported).toEqual(["ES256"]);
  });

  it("serializes to JSON string", () => {
    const meta = new ProtectedResourceMetadata({
      resource: "https://api.example.com",
      authorizationServers: ["http://localhost:8000"],
    });

    const jsonStr = meta.toString();
    const parsed = JSON.parse(jsonStr);
    expect(parsed.resource).toBe("https://api.example.com");
  });

  it("supports multiple authorization servers", () => {
    const meta = new ProtectedResourceMetadata({
      resource: "https://api.example.com",
      authorizationServers: [
        "http://localhost:8000",
        "https://auth.example.com",
      ],
    });

    const doc = meta.toJSON();
    expect(doc.authorization_servers).toHaveLength(2);
  });
});
