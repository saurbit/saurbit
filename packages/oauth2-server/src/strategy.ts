import type { JwtPayload, JwtVerifier } from "./utils/jwt_authority.ts";
import type { TokenType } from "./token_types/types.ts";

/**
 * Base class for all strategy errors.
 */
export abstract class StrategyError extends Error {
  abstract readonly status: 401 | 500;
  constructor(message?: string) {
    super(message);
    this.name = this.constructor.name;
  }
}

/**
 * Returned when the Authorization header is missing or has an invalid token type prefix.
 */
export class StrategyInvalidTokenTypeError extends StrategyError {
  readonly status = 401 as const;
}

/**
 * Returned when the token format/value is invalid.
 */
export class StrategyInvalidTokenError extends StrategyError {
  readonly status = 401 as const;
}

/**
 * Returned when JWT verification fails.
 */
export class StrategyJwtVerificationError extends StrategyError {
  readonly status = 401 as const;
}

/**
 * Returned when the token is valid but the scope is insufficient.
 */
export class StrategyInsufficientScopeError extends StrategyError {
    readonly status = 401 as const;
}

/**
 * Returned when the verifyToken callback rejects unexpectedly.
 */
export class StrategyInternalError extends StrategyError {
  readonly status = 500 as const;
  override readonly cause: unknown;
  constructor(cause: unknown) {
    super(`${cause}`);
    this.cause = cause;
  }
}

/**
 * User extensible types user credentials.
 */
// deno-lint-ignore no-empty-interface
export interface UserCredentials { }

/**
 * User extensible types app credentials.
 */
// deno-lint-ignore no-empty-interface
export interface AppCredentials { }

export interface AuthCredentials<
    AuthUser = UserCredentials,
    AuthApp = AppCredentials
> {
    scope?: string[] | undefined;
    user?: AuthUser;
    app?: AuthApp;
}

export interface StrategyVerifyTokenFunction<Req = Request> {
    (
        request: Req,
        tokens: {
            /**
             * The access token to validate and/or decode
             */
            token: string;
            /**
             * Only defined if useAccessTokenJwks is true and jwtVerifier is provided. 
             * Otherwise, validate and decode the token manually.
             */
            jwtAccessTokenPayload?: JwtPayload;
        }
    ): Promise<{
        isValid?: boolean;
        credentials?: AuthCredentials;
        message?: string;
    }> | {
        isValid?: boolean;
        credentials?: AuthCredentials;
        message?: string;
    }
}

export interface StrategyOptions {
    tokenType: TokenType;
    useAccessTokenJwks?: boolean;
    jwtVerifier?: JwtVerifier;
    verifyToken?: StrategyVerifyTokenFunction<Request>;
}

export type StrategyResult =
    | { success: true; credentials: AuthCredentials }
    | { success: false; error: StrategyError };

const HEADER = "Authorization";

/**
 * Framework-agnostic token strategy evaluation.
 * Works with any framework that can provide a standard `Request`.
 */
export async function evaluateStrategy(
    request: Request,
    options: StrategyOptions
): Promise<StrategyResult> {
    const authorization = request.headers.get(HEADER);
    const [tokenType, token = ''] = authorization ? authorization.split(/\s+/) : ["", ""];

    if (tokenType?.toLowerCase() !== options.tokenType.prefix.toLowerCase()) {
        return { success: false, error: new StrategyInvalidTokenTypeError() };
    }

    const tokenValidation = await options.tokenType.isValid(request, token);
    if (!tokenValidation.isValid) {
        return { success: false, error: new StrategyInvalidTokenError(tokenValidation.message) };
    }

    let jwtAccessTokenPayload: JwtPayload | undefined;
    if (options.useAccessTokenJwks && options.jwtVerifier) {
        try {
            jwtAccessTokenPayload = await options.jwtVerifier.verify(token);
        } catch {
            return { success: false, error: new StrategyJwtVerificationError("JWT verification failed") };
        }
    }

    if (options.verifyToken) {
        try {
            const result = await options.verifyToken(request, { token, jwtAccessTokenPayload });
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