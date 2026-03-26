import { describe, it, expect } from "vitest";
import { parseScopeChallenge } from "../src/scope-challenge.js";

describe("parseScopeChallenge", () => {
  it("parses standard WWW-Authenticate scope challenge", () => {
    const result = parseScopeChallenge(
      'Bearer scope="db:delete" error="insufficient_scope"',
    );
    expect(result).not.toBeNull();
    expect(result!.requiredScope).toBe("db:delete");
    expect(result!.error).toBe("insufficient_scope");
  });

  it("parses challenge with realm", () => {
    const result = parseScopeChallenge(
      'Bearer realm="api" scope="admin:write" error="insufficient_scope"',
    );
    expect(result).not.toBeNull();
    expect(result!.requiredScope).toBe("admin:write");
    expect(result!.realm).toBe("api");
  });

  it("returns null for non-scope challenges", () => {
    expect(parseScopeChallenge("Bearer")).toBeNull();
    expect(parseScopeChallenge('Bearer error="invalid_token"')).toBeNull();
    expect(parseScopeChallenge("")).toBeNull();
  });

  it("returns null when scope is missing from challenge", () => {
    const result = parseScopeChallenge(
      'Bearer error="insufficient_scope"',
    );
    expect(result).toBeNull();
  });

  it("handles multi-space separated values", () => {
    const result = parseScopeChallenge(
      'Bearer   scope="tools:execute"   error="insufficient_scope"',
    );
    expect(result).not.toBeNull();
    expect(result!.requiredScope).toBe("tools:execute");
  });
});
