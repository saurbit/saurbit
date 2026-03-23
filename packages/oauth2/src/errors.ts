/**
 * Base class for all OAuth 2.0 errors.
 *
 * @see https://datatracker.ietf.org/doc/html/rfc6749#section-5.2
 */
export class OAuth2Error extends Error {
  /** HTTP status code to return. */
  readonly statusCode: number;

  /** The OAuth 2.0 `error` code string. */
  readonly errorCode: string;

  errorUri?: string;

  constructor(message: string, statusCode = 500, errorCode = "server_error", errorUri?: string) {
    super(message);
    this.name = "OAuth2Error";
    this.statusCode = statusCode;
    this.errorCode = errorCode;
    this.errorUri = errorUri;
  }
}

/**
 * An error that encapsulates multiple OAuth2Error instances, such as when trying multiple flows in OIDCMultipleFlows.
 * The individual errors can be accessed via the `errors` property.
 */
export class OAuth2Errors extends OAuth2Error {
  readonly errors: OAuth2Error[];
  constructor(errors: OAuth2Error[]) {
    super(
      `Multiple OAuth2 errors: ${errors.map((e) => e.message).join("; ")}`,
      500,
      "server_error",
    );
    this.errors = errors;
  }
}

/** The request is missing a required parameter or is otherwise malformed. */
export class InvalidRequestError extends OAuth2Error {
  constructor(message = "Invalid request", errorUri?: string) {
    super(message, 400, "invalid_request", errorUri);
    this.name = "InvalidRequestError";
  }
}

/** Client authentication failed. */
export class InvalidClientError extends OAuth2Error {
  constructor(message = "Invalid client", errorUri?: string) {
    super(message, 401, "invalid_client", errorUri);
    this.name = "InvalidClientError";
  }
}

/** The provided grant (code, credentials, refresh token) is invalid or expired. */
export class InvalidGrantError extends OAuth2Error {
  constructor(message = "Invalid grant", errorUri?: string) {
    super(message, 400, "invalid_grant", errorUri);
    this.name = "InvalidGrantError";
  }
}

/** The client is not authorized to use the requested grant type. */
export class UnauthorizedClientError extends OAuth2Error {
  constructor(message = "Unauthorized client", errorUri?: string) {
    super(message, 401, "unauthorized_client", errorUri);
    this.name = "UnauthorizedClientError";
  }
}

/** The grant type is not supported by the server. */
export class UnsupportedGrantTypeError extends OAuth2Error {
  constructor(message = "Unsupported grant type", errorUri?: string) {
    super(message, 400, "unsupported_grant_type", errorUri);
    this.name = "UnsupportedGrantTypeError";
  }
}

/** The requested scope is invalid, unknown, or exceeds what is allowed. */
export class InvalidScopeError extends OAuth2Error {
  constructor(message = "Invalid scope", errorUri?: string) {
    super(message, 400, "invalid_scope", errorUri);
    this.name = "InvalidScopeError";
  }
}

/** The resource owner denied the authorization request. */
export class AccessDeniedError extends OAuth2Error {
  constructor(message = "Access denied", errorUri?: string) {
    super(message, 403, "access_denied", errorUri);
    this.name = "AccessDeniedError";
  }
}

/** The authorization request is still pending. The client should keep polling. */
export class AuthorizationPendingError extends OAuth2Error {
  constructor(message = "Authorization pending", errorUri?: string) {
    super(message, 400, "authorization_pending", errorUri);
    this.name = "AuthorizationPendingError";
  }
}

/** The client is polling too quickly. Increase interval by 5 seconds. */
export class SlowDownError extends OAuth2Error {
  constructor(message = "Slow down", errorUri?: string) {
    super(message, 400, "slow_down", errorUri);
    this.name = "SlowDownError";
  }
}

/** The device code has expired. The client should request a new device code. */
export class ExpiredTokenError extends OAuth2Error {
  constructor(message = "Expired token", errorUri?: string) {
    super(message, 400, "expired_token", errorUri);
    this.name = "ExpiredTokenError";
  }
}

/** The response type is not supported by the authorization server. */
export class UnsupportedResponseTypeError extends OAuth2Error {
  constructor(message = "Unsupported response type", errorUri?: string) {
    super(message, 400, "unsupported_response_type", errorUri);
    this.name = "UnsupportedResponseTypeError";
  }
}

/** An unexpected server error occurred. */
export class ServerError extends OAuth2Error {
  constructor(message = "Server error", errorUri?: string) {
    super(message, 500, "server_error", errorUri);
    this.name = "ServerError";
  }
}

/** The access token is expired, revoked, or otherwise invalid. */
export class InvalidTokenError extends OAuth2Error {
  constructor(message = "Invalid token", errorUri?: string) {
    super(message, 401, "invalid_token", errorUri);
    this.name = "InvalidTokenError";
  }
}

/** The token does not have sufficient scope for the requested resource. */
export class InsufficientScopeError extends OAuth2Error {
  constructor(message = "Insufficient scope", errorUri?: string) {
    super(message, 403, "insufficient_scope", errorUri);
    this.name = "InsufficientScopeError";
  }
}

/** The request requires authentication but none was provided. */
export class UnauthorizedRequestError extends OAuth2Error {
  constructor(message = "Unauthorized request", errorUri?: string) {
    super(message, 401, "unauthorized_request", errorUri);
    this.name = "UnauthorizedRequestError";
  }
}
