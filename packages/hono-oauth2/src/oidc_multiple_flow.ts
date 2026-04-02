import {
  OAuth2Error,
  OAuth2Errors,
  type OAuth2FlowTokenResponse,
  type OIDCFlow,
  OIDCMultipleFlows,
  StrategyError,
  StrategyInternalError,
  StrategyResult,
} from "@saurbit/oauth2";
import type { Context, Env, MiddlewareHandler } from "hono";
import { HonoAdapted, HonoMethods, OAuth2ServerEnv } from "./types.ts";
import { HTTPException } from "hono/http-exception";

/**
 * A Hono-adapted OIDC flow.
 *
 * Combines the base `OIDCFlow` contract with {@link HonoAdapted} so that any
 * OIDC flow registered with {@link HonoOIDCMultipleFlows} exposes a `.hono()`
 * accessor for use inside Hono route handlers.
 *
 * @template E - The Hono `Env` type for the application.
 */
export interface HonoOIDCFlow<
  E extends Env = Env,
> extends OIDCFlow, HonoAdapted<E> {
}

/**
 * Hono adapter that aggregates multiple OIDC flows behind a single interface.
 *
 * Delegates token issuance and token verification to each registered
 * {@link HonoOIDCFlow} in order, returning the first successful result.
 * The `authorizeMiddleware` similarly tries each flow's middleware in sequence,
 * falling through to the next on a 401 and only propagating the error when all
 * flows have been exhausted.
 *
 * Useful when an authorization server must support more than one grant type
 * or token format simultaneously (e.g. Client Credentials alongside
 * Authorization Code).
 *
 * @template E - The Hono `Env` type for the application.
 */
export class HonoOIDCMultipleFlows<
  E extends Env = Env,
> extends OIDCMultipleFlows<HonoOIDCFlow<E>> {
  readonly #hono: HonoMethods<E> = {
    authorizeMiddleware: (scopes?: string[]): MiddlewareHandler<E & OAuth2ServerEnv> => {
      const middlewares = this.flows.map((flow) => flow.hono().authorizeMiddleware(scopes));
      return async (context, next) => {
        for (const [i, middleware] of middlewares.entries()) {
          try {
            const response = await middleware(context, next);
            return response;
          } catch (error) {
            if (
              middlewares.length - 1 === i ||
              !(error instanceof HTTPException && error.status === 401)
            ) {
              throw error;
            }
          }
        }
      };
    },
    token: async (context: Context): Promise<OAuth2FlowTokenResponse> => {
      const errors: OAuth2Error[] = [];
      for (const flow of this.flows) {
        const result = await flow.hono().token(context);
        if (result.success) {
          return result;
        }
        errors.push(result.error);
      }
      return errors.length
        ? { success: false, error: new OAuth2Errors(errors) }
        : { success: false, error: new OAuth2Error("No flows available") };
    },

    verifyToken: async (context: Context<E & OAuth2ServerEnv>): Promise<StrategyResult> => {
      const errors: StrategyError[] = [];
      for (const flow of this.flows) {
        const validation = await flow.hono().verifyToken(context);
        if (validation.success) {
          return validation;
        }
        errors.push(validation.error);
      }
      return errors.length
        ? { success: false, error: new StrategyInternalError(errors) }
        : { success: false, error: new StrategyInternalError("No flows available") };
    },
  };

  /**
   * Returns a frozen object of Hono-adapted methods that fan out across all registered flows.
   *
   * @returns A readonly {@link HonoMethods} instance.
   */
  hono(): Readonly<HonoMethods<E>> {
    return Object.freeze(this.#hono);
  }
}
