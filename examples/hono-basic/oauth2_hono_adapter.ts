import type { MiddlewareHandler, Env, Context } from "hono";
import { HTTPException } from "hono/http-exception";
import { evaluateStrategy, type StrategyOptions, type AuthCredentials, StrategyInternalError, StrategyVerifyTokenFunction } from "@saurbit/oauth2-server";

export interface OAuth2ServerEnv extends Env {
  Variables: {
    credentials?: AuthCredentials;
  };
}

export interface HonoStrategyOptions<E extends Env = Env> extends Omit<StrategyOptions, "verifyToken"> {
  verifyToken?: StrategyVerifyTokenFunction<Context<E & OAuth2ServerEnv>>;
}

// Re-export for convenience
export type { StrategyOptions, StrategyVerifyTokenFunction, AuthCredentials, TokenType, TokenTypeValidationResponse } from "@saurbit/oauth2-server";
export { BearerTokenType } from "@saurbit/oauth2-server";



/**
 * Hono adapter for the oauth2-server strategy.
 */
export function createAuthMiddleware<E extends Env = Env>(
  options: HonoStrategyOptions<E>
): MiddlewareHandler<E & OAuth2ServerEnv> {
  return async (c, next) => {

    const honoVerifyToken = options.verifyToken;
    const verifyToken: StrategyVerifyTokenFunction | undefined = honoVerifyToken ? async (_, params) => {
      return await honoVerifyToken(c, params);
    } : undefined

    const result = await evaluateStrategy(c.req.raw, {
      ...options,
      verifyToken
    });

    if (result.success) {
      // set credentials in context for downstream handlers
      c.set("credentials", result.credentials);
      return await next();
    }

    let message: string;
    if (Deno.env.get("DENO_ENV") === "production") {
      message = result.error instanceof StrategyInternalError ? "Internal Server Error" : "Unauthorized";
    } else {
      message = result.error.message;
    }

    throw new HTTPException(result.error.status, {
      message
    });
  };
}