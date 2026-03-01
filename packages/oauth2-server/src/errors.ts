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

  constructor(message: string, statusCode = 500, errorCode = "server_error") {
    super(message);
    this.name = "OAuth2Error";
    this.statusCode = statusCode;
    this.errorCode = errorCode;
  }
}

/** The request is missing a required parameter or is otherwise malformed. */
export class InvalidRequestError extends OAuth2Error {
  constructor(message = "Invalid request") {
    super(message, 400, "invalid_request");
    this.name = "InvalidRequestError";
  }
}

/** Client authentication failed. */
export class InvalidClientError extends OAuth2Error {
  constructor(message = "Invalid client") {
    super(message, 401, "invalid_client");
    this.name = "InvalidClientError";
  }
}

/** The provided grant (code, credentials, refresh token) is invalid or expired. */
export class InvalidGrantError extends OAuth2Error {
  constructor(message = "Invalid grant") {
    super(message, 400, "invalid_grant");
    this.name = "InvalidGrantError";
  }
}

/** The client is not authorized to use the requested grant type. */
export class UnauthorizedClientError extends OAuth2Error {
  constructor(message = "Unauthorized client") {
    super(message, 401, "unauthorized_client");
    this.name = "UnauthorizedClientError";
  }
}

/** The grant type is not supported by the server. */
export class UnsupportedGrantTypeError extends OAuth2Error {
  constructor(message = "Unsupported grant type") {
    super(message, 400, "unsupported_grant_type");
    this.name = "UnsupportedGrantTypeError";
  }
}

/** The requested scope is invalid, unknown, or exceeds what is allowed. */
export class InvalidScopeError extends OAuth2Error {
  constructor(message = "Invalid scope") {
    super(message, 400, "invalid_scope");
    this.name = "InvalidScopeError";
  }
}

/** The resource owner denied the authorization request. */
export class AccessDeniedError extends OAuth2Error {
  constructor(message = "Access denied") {
    super(message, 403, "access_denied");
    this.name = "AccessDeniedError";
  }
}

/** The response type is not supported by the authorization server. */
export class UnsupportedResponseTypeError extends OAuth2Error {
  constructor(message = "Unsupported response type") {
    super(message, 400, "unsupported_response_type");
    this.name = "UnsupportedResponseTypeError";
  }
}

/** An unexpected server error occurred. */
export class ServerError extends OAuth2Error {
  constructor(message = "Server error") {
    super(message, 500, "server_error");
    this.name = "ServerError";
  }
}

/** The access token is expired, revoked, or otherwise invalid. */
export class InvalidTokenError extends OAuth2Error {
  constructor(message = "Invalid token") {
    super(message, 401, "invalid_token");
    this.name = "InvalidTokenError";
  }
}

/** The token does not have sufficient scope for the requested resource. */
export class InsufficientScopeError extends OAuth2Error {
  constructor(message = "Insufficient scope") {
    super(message, 403, "insufficient_scope");
    this.name = "InsufficientScopeError";
  }
}

/** The request requires authentication but none was provided. */
export class UnauthorizedRequestError extends OAuth2Error {
  constructor(message = "Unauthorized request") {
    super(message, 401, "unauthorized_request");
    this.name = "UnauthorizedRequestError";
  }
}
