import type { JwtPayload, JwtVerifier } from "./utils/jwt_authority.ts";
import type { TokenType } from "./token_types/types.ts";

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

export interface StrategyOptions {
    tokenType: TokenType;
    useAccessTokenJwks?: boolean;
    jwtVerifier?: JwtVerifier;
    verifyToken?(
        request: Request,
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
    };
}

export type StrategyResult =
    | { success: true; credentials: AuthCredentials }
    | { success: false; status: 401 | 500; message?: string };

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
        return { success: false, status: 401, message: "Invalid token type" };
    }

    const tokenValidation = await options.tokenType.isValid(request, token);
    if (!tokenValidation.isValid) {
        return { success: false, status: 401, message: tokenValidation.message };
    }

    let jwtAccessTokenPayload: JwtPayload | undefined;
    if (options.useAccessTokenJwks && options.jwtVerifier) {
        try {
            jwtAccessTokenPayload = await options.jwtVerifier.verify(token);
        } catch {
            return { success: false, status: 401, message: "JWT verification failed" };
        }
    }

    if (options.verifyToken) {
        try {
            const result = await options.verifyToken(request, { token, jwtAccessTokenPayload });
            if (result?.isValid && result.credentials) {
                return { success: true, credentials: result.credentials };
            }
            return { success: false, status: 401, message: result?.message };
        } catch (err) {
            return { success: false, status: 500, message: `${err}` };
        }
    }

    return { success: false, status: 401 };
}