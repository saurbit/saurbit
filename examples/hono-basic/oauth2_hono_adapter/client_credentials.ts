import type { Context, Env, MiddlewareHandler } from "hono";
import { HTTPException } from "hono/http-exception";
import {
  ClientCredentialsBuilder,
  ClientCredentialsFlow,
  ClientCredentialsFlowOptions,
  evaluateStrategy,
  OAuth2FlowTokenResponse,
  OIDCClientCredentialsFlowOptions,
  StrategyInsufficientScopeError,
  StrategyResult,
  StrategyVerifyTokenFunction,
} from "@saurbit/oauth2-server";
import {
  FailedAuthorizationAction,
  HonoAdapted,
  HonoMethods,
  HonoOAuth2StrategyOptions,
  OAuth2ServerEnv,
} from "./types.ts";
import { OIDCClientCredentialsFlow } from "@saurbit/oauth2-server";
import { OIDCClientCredentialsBuilder } from "@saurbit/oauth2-server";

//#region Types and Interfaces

export interface HonoClientCredentialsFlowOptions<E extends Env = Env>
  extends Omit<ClientCredentialsFlowOptions, "strategyOptions"> {
  strategyOptions: HonoOAuth2StrategyOptions<E>;
}

//#endregion

//#region OpenID Connect Types and Interfaces

export interface HonoOIDCClientCredentialsFlowOptions<E extends Env = Env>
  extends Omit<OIDCClientCredentialsFlowOptions, "strategyOptions"> {
  strategyOptions: HonoOAuth2StrategyOptions<E>;
}

//#endregion

//#region Classes

export class HonoClientCredentialsFlow<
  E extends Env = Env,
> extends ClientCredentialsFlow implements HonoAdapted<E> {
  readonly #verifyTokenHandler: (
    context: Context<E & OAuth2ServerEnv>,
  ) => Promise<StrategyResult>;
  readonly #authorizeMiddleware: MiddlewareHandler<E & OAuth2ServerEnv>;

  readonly #failedAuthorizationAction: FailedAuthorizationAction<E>;

  readonly #hono: HonoMethods<E> = {
    authorizeMiddleware: (scopes?: string[]): MiddlewareHandler<E & OAuth2ServerEnv> => {
      return scopes?.length ? this.#createAuthorizeMiddleware(scopes) : this.#authorizeMiddleware;
    },
    token: async (context: Context): Promise<OAuth2FlowTokenResponse> => {
      return await this.token(context.req.raw);
    },

    verifyToken: async (context: Context<E & OAuth2ServerEnv>): Promise<StrategyResult> => {
      return await this.#verifyTokenHandler(context);
    },
  };

  constructor(options: HonoClientCredentialsFlowOptions<E>) {
    const { strategyOptions, ...flowOptions } = options;

    super({
      ...flowOptions,
      strategyOptions: {},
    });

    this.#failedAuthorizationAction = strategyOptions.failedAuthorizationAction ?? (() => {
      throw new HTTPException(401, {
        message: "Unauthorized",
      });
    });

    this.#verifyTokenHandler = async (context: Context<E & OAuth2ServerEnv>) => {
      const honoVerifyToken = strategyOptions.verifyToken;
      const verifyToken: StrategyVerifyTokenFunction | undefined = honoVerifyToken
        ? async (_, params) => {
          return await honoVerifyToken(context, params);
        }
        : undefined;

      return await evaluateStrategy(context.req.raw, {
        ...strategyOptions,
        verifyToken,
        tokenType: this._tokenType,
      });
    };

    this.#authorizeMiddleware = this.#createAuthorizeMiddleware([]);
  }

  #createAuthorizeMiddleware(scopes: string[]): MiddlewareHandler<E & OAuth2ServerEnv> {
    return async (c, next) => {
      const result = await this.hono().verifyToken(c);

      if (result.success) {
        if (
          scopes.length &&
          !scopes.every((n) => result.credentials?.scope?.includes(n))
        ) {
          return this.#failedAuthorizationAction(
            c,
            new StrategyInsufficientScopeError("Insufficient scope"),
          );
        }
        // set credentials in context for downstream handlers
        c.set("credentials", result.credentials);
        return await next();
      }
      return this.#failedAuthorizationAction(c, result.error);
    };
  }

  hono(): Readonly<HonoMethods<E>> {
    return Object.freeze(this.#hono);
  }
}

export class HonoOIDCClientCredentialsFlow<
  E extends Env = Env,
> extends OIDCClientCredentialsFlow implements HonoAdapted<E> {
  readonly #verifyTokenHandler: (
    context: Context<E & OAuth2ServerEnv>,
  ) => Promise<StrategyResult>;
  readonly #authorizeMiddleware: MiddlewareHandler<E & OAuth2ServerEnv>;

  readonly #failedAuthorizationAction: FailedAuthorizationAction<E>;

  readonly #hono: HonoMethods<E> = {
    authorizeMiddleware: (scopes?: string[]): MiddlewareHandler<E & OAuth2ServerEnv> => {
      return scopes?.length ? this.#createAuthorizeMiddleware(scopes) : this.#authorizeMiddleware;
    },
    token: async (context: Context): Promise<OAuth2FlowTokenResponse> => {
      return await this.token(context.req.raw);
    },

    verifyToken: async (context: Context<E & OAuth2ServerEnv>): Promise<StrategyResult> => {
      return await this.#verifyTokenHandler(context);
    },
  };

  constructor(options: HonoOIDCClientCredentialsFlowOptions<E>) {
    const { strategyOptions, ...flowOptions } = options;

    super({
      ...flowOptions,
      strategyOptions: {},
    });

    this.#failedAuthorizationAction = strategyOptions.failedAuthorizationAction ?? (() => {
      throw new HTTPException(401, {
        message: "Unauthorized",
      });
    });

    this.#verifyTokenHandler = async (context: Context<E & OAuth2ServerEnv>) => {
      const honoVerifyToken = strategyOptions.verifyToken;
      const verifyToken: StrategyVerifyTokenFunction | undefined = honoVerifyToken
        ? async (_, params) => {
          return await honoVerifyToken(context, params);
        }
        : undefined;

      return await evaluateStrategy(context.req.raw, {
        ...strategyOptions,
        verifyToken,
        tokenType: this._tokenType,
      });
    };

    this.#authorizeMiddleware = this.#createAuthorizeMiddleware([]);
  }

  #createAuthorizeMiddleware(scopes: string[]): MiddlewareHandler<E & OAuth2ServerEnv> {
    return async (c, next) => {
      const result = await this.hono().verifyToken(c);

      if (result.success) {
        if (
          scopes.length &&
          !scopes.every((n) => result.credentials?.scope?.includes(n))
        ) {
          return this.#failedAuthorizationAction(
            c,
            new StrategyInsufficientScopeError("Insufficient scope"),
          );
        }
        // set credentials in context for downstream handlers
        c.set("credentials", result.credentials);
        return await next();
      }
      return this.#failedAuthorizationAction(c, result.error);
    };
  }

  hono(): Readonly<HonoMethods<E>> {
    return Object.freeze(this.#hono);
  }
}

//#endregion

//#region Builder

export class HonoClientCredentialsFlowBuilder<
  E extends Env = Env,
> extends ClientCredentialsBuilder {
  protected strategyOptions: HonoOAuth2StrategyOptions<E> = {};

  constructor(options: Partial<HonoClientCredentialsFlowOptions<E>>) {
    const { strategyOptions, ...flowOptions } = options;
    super({
      ...flowOptions,
      strategyOptions: {},
    });
    this.strategyOptions = strategyOptions || {};
  }

  static override create<E extends Env = Env>(
    options?: Partial<HonoClientCredentialsFlowOptions<E>>,
  ) {
    return new HonoClientCredentialsFlowBuilder<E>(options || {});
  }

  failedAuthorizationAction(action: FailedAuthorizationAction<E>): this {
    this.strategyOptions.failedAuthorizationAction = action;
    return this;
  }

  /**
   * This method is overridden to prevent setting a verifyToken handler that does not have access to the Hono context.
   * Use `verifyTokenHandler` instead to set a handler that receives the Hono context.
   * @deprecated Use `verifyTokenHandler` instead to set a handler that receives the Hono context.
   * @param _handler
   * @returns
   */
  override verifyToken(_handler: StrategyVerifyTokenFunction<Request>): this {
    throw new Error("Use verifyTokenHandler() instead, which provides access to the Hono context.");
  }

  verifyTokenHandler(handler: StrategyVerifyTokenFunction<Context<E & OAuth2ServerEnv>>): this {
    this.strategyOptions.verifyToken = handler;
    return this;
  }

  override build(): HonoClientCredentialsFlow<E> {
    const params: HonoClientCredentialsFlowOptions<E> = {
      ...this.buildParams(),
      strategyOptions: this.strategyOptions,
    };
    return new HonoClientCredentialsFlow<E>(params);
  }
}

export class HonoOIDCClientCredentialsFlowBuilder<
  E extends Env = Env,
> extends OIDCClientCredentialsBuilder {
  protected strategyOptions: HonoOAuth2StrategyOptions<E> = {};

  constructor(options: Partial<HonoOIDCClientCredentialsFlowOptions<E>>) {
    const { strategyOptions, ...flowOptions } = options;
    super({
      ...flowOptions,
      strategyOptions: {},
    });
    this.strategyOptions = strategyOptions || {};
  }

  static override create<E extends Env = Env>(
    options?: Partial<HonoOIDCClientCredentialsFlowOptions<E>>,
  ) {
    return new HonoOIDCClientCredentialsFlowBuilder<E>(options || {});
  }

  failedAuthorizationAction(action: FailedAuthorizationAction<E>): this {
    this.strategyOptions.failedAuthorizationAction = action;
    return this;
  }

  /**
   * This method is overridden to prevent setting a verifyToken handler that does not have access to the Hono context.
   * Use `verifyTokenHandler` instead to set a handler that receives the Hono context.
   * @deprecated Use `verifyTokenHandler` instead to set a handler that receives the Hono context.
   * @param _handler
   * @returns
   */
  override verifyToken(_handler: StrategyVerifyTokenFunction<Request>): this {
    throw new Error("Use verifyTokenHandler() instead, which provides access to the Hono context.");
  }

  verifyTokenHandler(handler: StrategyVerifyTokenFunction<Context<E & OAuth2ServerEnv>>): this {
    this.strategyOptions.verifyToken = handler;
    return this;
  }

  override build(): HonoOIDCClientCredentialsFlow<E> {
    const params: HonoOIDCClientCredentialsFlowOptions<E> = {
      ...this.buildParams(),
      strategyOptions: this.strategyOptions,
    };
    return new HonoOIDCClientCredentialsFlow<E>(params);
  }
}

//#endregion
