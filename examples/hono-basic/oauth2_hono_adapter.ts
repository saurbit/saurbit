import type { MiddlewareHandler, Env } from "hono";
import { HTTPException } from "hono/http-exception";
import { evaluateStrategy, type StrategyOptions, type AuthCredentials, StrategyInternalError } from "@saurbit/oauth2-server";

export interface Oauth2ServerEnv extends Env {
  Variables: {
    credentials?: AuthCredentials;
  };
}

// Re-export for convenience
export type { StrategyOptions, AuthCredentials, TokenType, TokenValidationResponse } from "@saurbit/oauth2-server";
export { BearerToken } from "@saurbit/oauth2-server";

/**
 * Hono adapter for the oauth2-server strategy.
 */
export function createAuthMiddleware<E extends Env = Env>(
  options: StrategyOptions
): MiddlewareHandler<E & Oauth2ServerEnv> {
  return async (c, next) => {
    const result = await evaluateStrategy(c.req.raw, options);

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