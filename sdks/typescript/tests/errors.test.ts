import { describe, it, expect } from "vitest";
import {
  AuthgentError,
  InvalidTokenError,
  DelegationError,
  DPoPError,
  ServerError,
  InsufficientScopeError,
  StepUpDeniedError,
  StepUpTimeoutError,
} from "../src/errors.js";

describe("Error hierarchy", () => {
  it("all errors extend AuthgentError", () => {
    const errors = [
      new InvalidTokenError("test"),
      new DelegationError("test"),
      new DPoPError("test"),
      new ServerError("test"),
      new InsufficientScopeError("test"),
      new StepUpDeniedError("test"),
      new StepUpTimeoutError("test"),
    ];

    for (const err of errors) {
      expect(err).toBeInstanceOf(AuthgentError);
      expect(err).toBeInstanceOf(Error);
    }
  });

  it("each error has correct error code", () => {
    expect(new InvalidTokenError("x").errorCode).toBe("invalid_token");
    expect(new DelegationError("x").errorCode).toBe("delegation_error");
    expect(new DPoPError("x").errorCode).toBe("dpop_error");
    expect(new ServerError("x").errorCode).toBe("server_error");
    expect(new InsufficientScopeError("x").errorCode).toBe("insufficient_scope");
    expect(new StepUpDeniedError("x").errorCode).toBe("step_up_denied");
    expect(new StepUpTimeoutError("x").errorCode).toBe("step_up_timeout");
  });

  it("each error has correct name", () => {
    expect(new InvalidTokenError("x").name).toBe("InvalidTokenError");
    expect(new DelegationError("x").name).toBe("DelegationError");
    expect(new DPoPError("x").name).toBe("DPoPError");
    expect(new ServerError("x").name).toBe("ServerError");
    expect(new InsufficientScopeError("x").name).toBe("InsufficientScopeError");
    expect(new StepUpDeniedError("x").name).toBe("StepUpDeniedError");
    expect(new StepUpTimeoutError("x").name).toBe("StepUpTimeoutError");
  });

  it("preserves message", () => {
    const err = new InvalidTokenError("Token expired at 12:00");
    expect(err.message).toBe("Token expired at 12:00");
  });

  it("DelegationError supports custom error codes", () => {
    const err = new DelegationError("depth exceeded", "delegation_depth_exceeded");
    expect(err.errorCode).toBe("delegation_depth_exceeded");
  });
});
