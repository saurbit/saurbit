import type { Context, Env, MiddlewareHandler } from "hono";
import type {
  AuthCredentials,
  OAuth2FlowTokenResponse,
  StrategyError,
  StrategyOptions,
  StrategyResult,
  StrategyVerifyTokenFunction,
} from "@saurbit/oauth2-server";

export interface OAuth2ServerEnv extends Env {
  Variables: {
    credentials?: AuthCredentials;
  };
}

export interface HonoStrategyOptions<E extends Env = Env>
  extends Omit<StrategyOptions, "verifyToken"> {
  verifyToken?: StrategyVerifyTokenFunction<Context<E & OAuth2ServerEnv>>;
}

export interface FailedAuthorizationAction<E extends Env = Env> {
  (context: Context<E & OAuth2ServerEnv>, error: StrategyError): Promise<void> | void;
}

export interface HonoStrategyOptionsWithFailedAuth<E extends Env = Env>
  extends Omit<HonoStrategyOptions<E>, "tokenType"> {
  failedAuthorizationAction?: FailedAuthorizationAction<E>;
}

export interface HonoMethods<E extends Env = Env> {
  authorizeMiddleware(scopes?: string[]): MiddlewareHandler<E & OAuth2ServerEnv>;
  token(context: Context): Promise<OAuth2FlowTokenResponse>;
  verifyToken(context: Context<E & OAuth2ServerEnv>): Promise<StrategyResult>;
}

export interface HonoAdapted<E extends Env = Env> {
  hono(): HonoMethods<E>;
}
