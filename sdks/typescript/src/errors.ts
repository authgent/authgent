/**
 * SDK error hierarchy — mirrors Python SDK structure.
 * All errors extend AuthgentError for consistent catch patterns.
 */

export class AuthgentError extends Error {
  readonly errorCode: string;

  constructor(message: string, errorCode = "authgent_error") {
    super(message);
    this.name = "AuthgentError";
    this.errorCode = errorCode;
  }
}

export class InvalidTokenError extends AuthgentError {
  constructor(message: string) {
    super(message, "invalid_token");
    this.name = "InvalidTokenError";
  }
}

export class DelegationError extends AuthgentError {
  constructor(message: string, errorCode = "delegation_error") {
    super(message, errorCode);
    this.name = "DelegationError";
  }
}

export class DPoPError extends AuthgentError {
  constructor(message: string) {
    super(message, "dpop_error");
    this.name = "DPoPError";
  }
}

export class ServerError extends AuthgentError {
  constructor(message: string) {
    super(message, "server_error");
    this.name = "ServerError";
  }
}

export class InsufficientScopeError extends AuthgentError {
  constructor(message: string) {
    super(message, "insufficient_scope");
    this.name = "InsufficientScopeError";
  }
}

export class StepUpDeniedError extends AuthgentError {
  constructor(message: string) {
    super(message, "step_up_denied");
    this.name = "StepUpDeniedError";
  }
}

export class StepUpTimeoutError extends AuthgentError {
  constructor(message: string) {
    super(message, "step_up_timeout");
    this.name = "StepUpTimeoutError";
  }
}
