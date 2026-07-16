/**
 * @module strategy
 * @description Framework-agnostic token validation strategy for protecting routes.
 * Provides error classes, option interfaces, and the {@link evaluateStrategy} function
 * that validates an incoming `Authorization` header against a configured {@link TokenType}
 * and an optional application-level `verifyToken` callback.
 */

import type { TokenType, TokenTypeValidationResponse } from "./token_types/types.ts";

/**
 * Base class for all strategy errors.
 * Subclasses carry an HTTP `status` of `401` (client error) or `500` (server error).
 */
export abstract class StrategyError extends Error {
  /** The HTTP status code associated with this error. */
  abstract readonly status: 401 | 500;
  /**
   * @param message - Optional human-readable error message.
   */
  constructor(message?: string) {
    super(message);
    this.name = this.constructor.name;
  }
}

/**
 * Returned when the `Authorization` header is missing or has an invalid token type prefix
 * (e.g. `Bearer` was expected but `DPoP` was received, or the header is absent entirely).
 */
export class StrategyInvalidTokenTypeError extends StrategyError {
  /** HTTP 401 Unauthorized. */
  readonly status = 401 as const;
}

/**
 * Returned when the token type prefix is correct but the token format or value is invalid
 * (e.g. the DPoP proof fails validation, or the token is malformed).
 */
export class StrategyInvalidTokenError extends StrategyError {
  /** HTTP 401 Unauthorized. */
  readonly status = 401 as const;
}

/**
 * Returned when the access token is structurally valid but the granted scopes are
 * insufficient for the requested resource.
 */
export class StrategyInsufficientScopeError extends StrategyError {
  /** HTTP 401 Unauthorized. */
  readonly status = 401 as const;
}

/**
 * Returned when the `verifyToken` callback throws an unexpected error.
 * Wraps the original thrown value and exposes it via {@link cause}.
 */
export class StrategyInternalError extends StrategyError {
  /** HTTP 500 Internal Server Error. */
  readonly status = 500 as const;
  override readonly cause: unknown;
  constructor(cause: unknown) {
    super(`${cause}`);
    this.cause = cause;
  }
}

/**
 * Returned when multiple strategy errors occur simultaneously, such as when
 * {@link OIDCMultipleFlows} tries each registered flow in turn and all fail.
 * The individual errors are accessible via the {@link errors} property.
 */
export class StrategyErrors extends StrategyError {
  /** HTTP 500 Internal Server Error. */
  readonly status = 500 as const;

  /** The list of individual {@link StrategyError} instances that were collected. */
  readonly errors: StrategyError[];

  /**
   * @param errors - The array of strategy errors to aggregate.
   */
  constructor(errors: StrategyError[]) {
    super(`Multiple strategy errors: ${errors.map((e) => e.message).join("; ")}`);
    this.errors = errors;
  }
}

/**
 * User-extensible interface for end-user identity claims.
 * Augment this interface in your application to add typed user properties
 * to {@link AuthCredentials}.
 *
 * @example
 * ```ts
 * declare module "@saurbit/oauth2" {
 *   interface UserCredentials {
 *     userId: string;
 *     email: string;
 *   }
 * }
 * ```
 */
// deno-lint-ignore no-empty-interface
export interface UserCredentials {}

/**
 * User-extensible interface for application (client) identity claims.
 * Augment this interface in your application to add typed app/client properties
 * to {@link AuthCredentials}.
 *
 * @example
 * ```ts
 * declare module "@saurbit/oauth2" {
 *   interface AppCredentials {
 *     clientId: string;
 *   }
 * }
 * ```
 */
// deno-lint-ignore no-empty-interface
export interface AppCredentials {}

/**
 * The resolved credentials returned by a successful `verifyToken` call.
 * Contains the granted scopes and optional typed user and app identity objects.
 *
 * @template AuthUser - The shape of user credentials. Defaults to {@link UserCredentials}.
 * @template AuthApp - The shape of app/client credentials. Defaults to {@link AppCredentials}.
 */
export interface AuthCredentials<
  AuthUser = UserCredentials,
  AuthApp = AppCredentials,
> {
  scope?: string[] | undefined;
  user?: AuthUser;
  app?: AuthApp;
}

/**
 * Callback signature for application-level token verification.
 * Receives the incoming request and the extracted raw token string, and must return
 * whether the token is valid along with the resolved credentials.
 *
 * @template Req - The request type. Defaults to the standard `Request`.
 *
 * @example
 * ```ts
 * const verifyToken: StrategyVerifyTokenFunction = async (req, { token }) => {
 *   const payload = await jwt.verify(token, publicKey);
 *   return { isValid: true, credentials: { user: { userId: payload.sub } } };
 * };
 * ```
 */
export interface StrategyVerifyTokenFunction<Req = Request> {
  (
    request: Req,
    tokens: {
      /**
       * The raw access token extracted from the `Authorization` header,
       * after the token type prefix has been stripped.
       */
      token: string;
      /**
       * The result of the token type validation.
       */
      tokenTypeValidation: TokenTypeValidationResponse;
    },
  ):
    | Promise<{
      /** Whether the token is considered valid. */
      isValid?: boolean;
      /** The resolved credentials to attach to the request context on success. */
      credentials?: AuthCredentials;
      /** An optional human-readable message included in error responses on failure. */
      message?: string;
    }>
    | {
      isValid?: boolean;
      credentials?: AuthCredentials;
      message?: string;
    };
}

/**
 * Options passed to {@link evaluateStrategy} to configure token validation.
 */
export interface StrategyOptions {
  /**
   * The token type implementation used to validate the access token format and proof.
   * Determines the expected `Authorization` header prefix (e.g. `Bearer` or `DPoP`).
   */
  tokenType: TokenType;

  /**
   * Optional application-level callback for verifying the token's content and
   * resolving authenticated credentials. If omitted, the strategy returns a
   * {@link StrategyInvalidTokenError} even when the token type check passes.
   */
  verifyToken?: StrategyVerifyTokenFunction<Request>;
}

/**
 * The discriminated union result returned by {@link evaluateStrategy}.
 * On success, carries the resolved {@link AuthCredentials}.
 * On failure, carries a {@link StrategyError} describing the reason.
 */
export type StrategyResult =
  | { success: true; credentials: AuthCredentials }
  | { success: false; error: StrategyError };

const HEADER = "Authorization";

/**
 * Framework-agnostic token strategy evaluation.
 * Works with any framework that can provide a standard `Request`.
 *
 * Performs the following steps:
 * 1. Extracts the `Authorization` header and checks the token type prefix against
 *    `options.tokenType.prefix`. Returns {@link StrategyInvalidTokenTypeError} if it does not match.
 * 2. Validates the token format/proof via `options.tokenType.isValid()`. Returns
 *    {@link StrategyInvalidTokenError} if invalid.
 * 3. If `options.verifyToken` is provided, invokes it with a clone of the request and
 *    the raw token. Returns the resolved credentials on success, or a
 *    {@link StrategyInvalidTokenError} / {@link StrategyInternalError} on failure.
 *
 * @param request - The incoming HTTP request containing the `Authorization` header.
 * @param options - Strategy configuration including the token type and optional verify callback.
 * @returns A promise resolving to a {@link StrategyResult} - either successful credentials
 *   or a typed strategy error.
 */
export async function evaluateStrategy(
  request: Request,
  options: StrategyOptions,
): Promise<StrategyResult> {
  const authorization = request.headers.get(HEADER);
  const [tokenType, token = ""] = authorization ? authorization.split(/\s+/) : ["", ""];

  if (tokenType?.toLowerCase() !== options.tokenType.prefix.toLowerCase()) {
    return { success: false, error: new StrategyInvalidTokenTypeError() };
  }

  const tokenTypeValidation = await options.tokenType.isValid(request.clone(), token);
  if (!tokenTypeValidation.isValid) {
    return { success: false, error: new StrategyInvalidTokenError(tokenTypeValidation.message) };
  }

  if (options.verifyToken) {
    try {
      const result = await options.verifyToken(request.clone(), { token, tokenTypeValidation });
      if (result?.isValid && result.credentials) {
        return { success: true, credentials: result.credentials };
      }
      return { success: false, error: new StrategyInvalidTokenError(result?.message) };
    } catch (err) {
      return { success: false, error: new StrategyInternalError(err) };
    }
  }

  return { success: false, error: new StrategyInvalidTokenError() };
}
