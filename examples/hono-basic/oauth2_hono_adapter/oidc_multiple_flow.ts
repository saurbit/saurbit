import {
    OAuth2Errors,
    OAuth2FlowTokenResponse,
    OIDCFlow,
    OIDCMultipleFlows,
    StrategyInternalError,
    StrategyResult,
    OAuth2Error, StrategyError
} from "@saurbit/oauth2-server";
import type { Context, Env, MiddlewareHandler } from "hono";
import { OAuth2ServerEnv } from "./types.ts";
import { HTTPException } from "hono/http-exception";

export interface HonoOIDCFlow<
    E extends Env = Env,
> extends OIDCFlow {
    authorizeMiddleware(scopes?: string[]): MiddlewareHandler<E & OAuth2ServerEnv>;
    tokenFromHono(context: Context): Promise<OAuth2FlowTokenResponse>;
    verifyTokenFromHono(context: Context<E & OAuth2ServerEnv>): Promise<StrategyResult>;
}

export class HonoOIDCMultipleFlows<
    E extends Env = Env,
> extends OIDCMultipleFlows<HonoOIDCFlow<E>> {
    async tokenFromHono(context: Context): Promise<OAuth2FlowTokenResponse> {
        const errors: OAuth2Error[] = [];
        for (const flow of this.flows) {
            const result = await flow.tokenFromHono(context);
            if (result.success) {
                return result;
            }
            errors.push(result.error);
        }
        return errors.length
            ? { success: false, error: new OAuth2Errors(errors) }
            : { success: false, error: new OAuth2Error("No flows available") };
    }
    async verifyTokenFromHono(context: Context<E & OAuth2ServerEnv>): Promise<StrategyResult> {
        const errors: StrategyError[] = [];
        for (const flow of this.flows) {
            const validation = await flow.verifyTokenFromHono(context);
            if (validation.success) {
                return validation;
            }
            errors.push(validation.error);
        }
        return errors.length
            ? { success: false, error: new StrategyInternalError(errors) }
            : { success: false, error: new StrategyInternalError("No flows available") };
    }

    authorizeMiddleware(scopes?: string[]): MiddlewareHandler<E & OAuth2ServerEnv> {
        const middlewares = this.flows.map((flow) => flow.authorizeMiddleware(scopes));
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
    }
}
