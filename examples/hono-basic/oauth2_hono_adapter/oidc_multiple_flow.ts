import {
  OAuth2Error,
  OAuth2Errors,
  OAuth2FlowTokenResponse,
  OIDCFlow,
  OIDCMultipleFlows,
  StrategyError,
  StrategyInternalError,
  StrategyResult,
} from "@saurbit/oauth2-server";
import type { Context, Env, MiddlewareHandler } from "hono";
import { HonoMethods, OAuth2ServerEnv } from "./types.ts";
import { HTTPException } from "hono/http-exception";

export interface HonoOIDCFlow<
  E extends Env = Env,
> extends OIDCFlow {
  hono(): HonoMethods<E>;
}

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

  hono() {
    return Object.freeze(this.#hono);
  }
}
