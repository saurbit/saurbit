import { MiddlewareHandler } from "hono/types";
import { HTTPException } from 'hono/http-exception'
import { Context, Env } from "hono";
import { JwtPayload, JwtVerifier } from "../utils/jwt_authority.ts";

/**
 * User extensible types user credentials.
 */
// deno-lint-ignore no-empty-interface
export interface UserCredentials {
}

/**
 * User extensible types app credentials.
 */
// deno-lint-ignore no-empty-interface
export interface AppCredentials {
}

/**
 * User-extensible type for request.auth credentials.
 */
export interface AuthCredentials<
    AuthUser = UserCredentials,
    AuthApp = AppCredentials
> {
    /**
     * The application scopes to be granted.
     * [See docs](https://github.com/hapijs/hapi/blob/master/API.md#-routeoptionsauthaccessscope)
     */
    scope?: string[] | undefined;

    /**
     * If set, will only work with routes that set `access.entity` to `user`.
     */
    user?: AuthUser

    /**
     * If set, will only work with routes that set `access.entity` to `app`.
     */
    app?: AuthApp;
}

export interface Oauth2ServerEnv extends Env {
  Variables: {
    credentials?: AuthCredentials
  }
}

export type TokenTypeValidationResponse = {
    isValid?: boolean | undefined;
    message?: string | undefined;
};

// deno-lint-ignore no-explicit-any
export type TokenTypeValidation<E extends Env = any> = (
    c: Context<E>,
    token: string,
    ttl: number
) => TokenTypeValidationResponse | Promise<TokenTypeValidationResponse>;

// deno-lint-ignore no-explicit-any
export interface TokenType<E extends Env = any> {
    readonly prefix: string; // Bearer
    /**
     * 401 if not valid
     */
    isValid: (c: Context<E>, token: string) => TokenTypeValidationResponse | Promise<TokenTypeValidationResponse>;

    isValidTokenRequest?: (c: Context<E>) => TokenTypeValidationResponse | Promise<TokenTypeValidationResponse>;
}

// deno-lint-ignore no-explicit-any
export interface IBearerToken<E extends Env = any> extends TokenType<E> {
    readonly prefix: 'Bearer';
}

// deno-lint-ignore no-explicit-any
export class BearerToken<E extends Env = any> implements IBearerToken<E> {
    #ttl: number = 300;
    #_handler: TokenTypeValidation<E>;

    get prefix(): 'Bearer' {
        return 'Bearer';
    }

    get configuration() {
        return {};
    }

    constructor() {
        this.#_handler = (_, token) => {
            if (!token) return { isValid: false };
            return { isValid: true };
        };
    }

    validate(handler: TokenTypeValidation<E>): this {
        this.#_handler = handler;
        return this;
    }

    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    async isValid(c: Context<E>, token: string): Promise<TokenTypeValidationResponse> {
        return await this.#_handler(c, token, this.#ttl);
    }
}

// deno-lint-ignore no-explicit-any
export interface StrategyOptions<E extends Env = any> {
    tokenType: TokenType
    /**
     * Auto-verifies the access token JWT using the configured JWKS before running user validation.
     */
    useAccessTokenJwks?: boolean;
    jwtVerifier?: JwtVerifier;

    /**
     *
     * User validations
     */
    verifyToken?(
        c: Context<E>,
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
    ): Promise<
        | {
              isValid?: boolean;
              credentials?: AuthCredentials;
              message?: string;
          }
    > | {
              isValid?: boolean;
              credentials?: AuthCredentials;
              message?: string;
          };
}

const HEADER = 'Authorization'

export function integrateStrategy<E extends Env = Env>(options: StrategyOptions<E & Oauth2ServerEnv>): MiddlewareHandler<E & Oauth2ServerEnv> {
    const tokenTypePrefix = options.tokenType.prefix
    const tokenTypeInstance = options.tokenType
    const getJwtVerifier = () => options.useAccessTokenJwks && options.jwtVerifier ? options.jwtVerifier : undefined;

    const authMiddleware: MiddlewareHandler<E & Oauth2ServerEnv> = async (c, next) => {
        const authorization = c.req.header(HEADER);

        const authSplit = authorization ? authorization.split(/\s+/) : ['', ''];

        const tokenType = authSplit[0];
        let jwtAccessTokenPayload: JwtPayload | undefined;

        if (tokenType.toLowerCase() !== tokenTypePrefix.toLowerCase()) {
            // TODO: log
            throw new HTTPException(401)
        }

        const token = authSplit[1];

        if (!(await tokenTypeInstance.isValid(c, token)).isValid) {
            // TODO: log
            throw new HTTPException(401)
        }

        const jwtVerifier = getJwtVerifier();
        if (jwtVerifier) {
            try {
                jwtAccessTokenPayload = await jwtVerifier.verify(token);
            } catch (_err) {
                // TODO log
                throw new HTTPException(401)
            }
        }
        
        if (options.verifyToken) {
            try {
                const result = await options.verifyToken?.(c, { token, jwtAccessTokenPayload });

                if (result) {
                    const { isValid, credentials, message } = result;

                    if (isValid && credentials) {
                        c.set('credentials', credentials)
                        return await next()
                    }

                    if (message) {
                        // TODO: log
                        throw new HTTPException(401, { message })
                    }
                }
            } catch (err) {
                // TODO: log
                throw new HTTPException(500, { message: `${err}` })
            }
        }

        throw new HTTPException(401)
    }

    return authMiddleware
}