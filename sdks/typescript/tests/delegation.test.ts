import { describe, it, expect } from "vitest";
import { verifyDelegationChain } from "../src/delegation.js";
import { DelegationError } from "../src/errors.js";
import type { DelegationChain } from "../src/models.js";

function makeChain(
  actors: Array<{ sub: string }>,
  humanRoot = false,
): DelegationChain {
  return { actors, depth: actors.length, humanRoot };
}

describe("verifyDelegationChain", () => {
  it("passes valid chain within depth limit", () => {
    const chain = makeChain([{ sub: "client:agnt_B" }]);
    const result = verifyDelegationChain(chain, { maxDepth: 5 });
    expect(result).toBe(chain);
  });

  it("passes empty chain (no delegation)", () => {
    const chain = makeChain([]);
    const result = verifyDelegationChain(chain);
    expect(result.depth).toBe(0);
  });

  it("rejects chain exceeding max depth", () => {
    const chain = makeChain([
      { sub: "a" },
      { sub: "b" },
      { sub: "c" },
    ]);
    expect(() => verifyDelegationChain(chain, { maxDepth: 2 })).toThrow(
      DelegationError,
    );
    expect(() => verifyDelegationChain(chain, { maxDepth: 2 })).toThrow(
      "exceeds maximum",
    );
  });

  it("enforces human root requirement", () => {
    const agentChain = makeChain([{ sub: "client:agnt_B" }], false);
    expect(() =>
      verifyDelegationChain(agentChain, { requireHumanRoot: true }),
    ).toThrow("human root");

    const humanChain = makeChain([{ sub: "user:alice" }], true);
    const result = verifyDelegationChain(humanChain, {
      requireHumanRoot: true,
    });
    expect(result).toBe(humanChain);
  });

  it("skips human root check for empty chains", () => {
    const chain = makeChain([]);
    // Should not throw — no delegation means no root to check
    const result = verifyDelegationChain(chain, { requireHumanRoot: true });
    expect(result.depth).toBe(0);
  });

  it("enforces allowed actors list", () => {
    const chain = makeChain([
      { sub: "client:agnt_A" },
      { sub: "client:agnt_B" },
    ]);

    // All actors allowed
    const result = verifyDelegationChain(chain, {
      allowedActors: ["client:agnt_A", "client:agnt_B"],
    });
    expect(result).toBe(chain);

    // One actor not allowed
    expect(() =>
      verifyDelegationChain(chain, {
        allowedActors: ["client:agnt_A"],
      }),
    ).toThrow("not in the allowed actors list");
  });

  it("uses correct error codes", () => {
    try {
      verifyDelegationChain(makeChain([{ sub: "a" }, { sub: "b" }]), {
        maxDepth: 1,
      });
    } catch (err) {
      expect(err).toBeInstanceOf(DelegationError);
      expect((err as DelegationError).errorCode).toBe(
        "delegation_depth_exceeded",
      );
    }

    try {
      verifyDelegationChain(makeChain([{ sub: "agent:x" }], false), {
        requireHumanRoot: true,
      });
    } catch (err) {
      expect((err as DelegationError).errorCode).toBe("no_human_root");
    }

    try {
      verifyDelegationChain(makeChain([{ sub: "bad:actor" }]), {
        allowedActors: ["good:actor"],
      });
    } catch (err) {
      expect((err as DelegationError).errorCode).toBe("unauthorized_actor");
    }
  });
});
