import type { Context, Env, MiddlewareHandler } from "hono";
import { HTTPException } from "hono/http-exception";
import {
  ClientCredentialsFlow,
  ClientCredentialsFlowBuilder,
  type ClientCredentialsFlowOptions,
  evaluateStrategy,
  type OAuth2FlowTokenResponse,
  OIDCClientCredentialsFlow,
  OIDCClientCredentialsFlowBuilder,
  type OIDCClientCredentialsFlowOptions,
  StrategyInsufficientScopeError,
  type StrategyResult,
  type StrategyVerifyTokenFunction,
} from "@saurbit/oauth2";
import type {
  FailedAuthorizationAction,
  HonoAdapted,
  HonoMethods,
  HonoOAuth2StrategyOptions,
  OAuth2ServerEnv,
} from "./types.ts";

//#region Types and Interfaces

/**
 * Configuration options for {@link HonoClientCredentialsFlow}.
 *
 * Extends the base `ClientCredentialsFlowOptions` with Hono-specific strategy options
 * for token verification and failed-authorization handling.
 *
 * @template E - The Hono `Env` type for the application.
 */
export interface HonoClientCredentialsFlowOptions<E extends Env = Env>
  extends Omit<ClientCredentialsFlowOptions, "strategyOptions"> {
  /** Hono-specific strategy options, including token verification and failed authorization handling. */
  strategyOptions: HonoOAuth2StrategyOptions<E>;
}

//#endregion

//#region OpenID Connect Types and Interfaces

/**
 * Configuration options for {@link HonoOIDCClientCredentialsFlow}.
 *
 * Extends the base `OIDCClientCredentialsFlowOptions` with Hono-specific strategy options
 * for token verification and failed-authorization handling.
 *
 * @template E - The Hono `Env` type for the application.
 */
export interface HonoOIDCClientCredentialsFlowOptions<E extends Env = Env>
  extends Omit<OIDCClientCredentialsFlowOptions, "strategyOptions"> {
  /** Hono-specific strategy options, including token verification and failed authorization handling. */
  strategyOptions: HonoOAuth2StrategyOptions<E>;
}

//#endregion

//#region Classes

/**
 * Hono adapter for the OAuth 2.0 Client Credentials flow.
 *
 * Wraps {@link ClientCredentialsFlow} to integrate natively with Hono's `Context`,
 * providing a token endpoint handler and middleware for protecting routes.
 * This flow is intended for machine-to-machine authentication where no user
 * interaction is required.
 *
 * Use {@link HonoClientCredentialsFlowBuilder} for a fluent configuration API.
 *
 * @template E - The Hono `Env` type for the application.
 */
export class HonoClientCredentialsFlow<
  E extends Env = Env,
> extends ClientCredentialsFlow implements HonoAdapted<E> {
  readonly #tokenVerifier: (
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
      return await this.#tokenVerifier(context);
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

    this.#tokenVerifier = async (context: Context<E & OAuth2ServerEnv>) => {
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

  /**
   * Returns a frozen object of Hono-adapted methods for use inside Hono route handlers.
   *
   * @returns A readonly {@link HonoMethods} instance.
   */
  hono(): Readonly<HonoMethods<E>> {
    return Object.freeze(this.#hono);
  }
}

/**
 * Hono adapter for the OpenID Connect Client Credentials flow.
 *
 * Wraps {@link OIDCClientCredentialsFlow} to integrate natively with Hono's `Context`,
 * providing a token endpoint handler and middleware for protecting routes.
 * Extends the standard Client Credentials flow with OpenID Connect features.
 *
 * Use {@link HonoOIDCClientCredentialsFlowBuilder} for a fluent configuration API.
 *
 * @template E - The Hono `Env` type for the application.
 */
export class HonoOIDCClientCredentialsFlow<
  E extends Env = Env,
> extends OIDCClientCredentialsFlow implements HonoAdapted<E> {
  readonly #tokenVerifier: (
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
      return await this.#tokenVerifier(context);
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

    this.#tokenVerifier = async (context: Context<E & OAuth2ServerEnv>) => {
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

  /**
   * Returns a frozen object of Hono-adapted methods for use inside Hono route handlers.
   *
   * @returns A readonly {@link HonoMethods} instance.
   */
  hono(): Readonly<HonoMethods<E>> {
    return Object.freeze(this.#hono);
  }
}

//#endregion

//#region Builders

/**
 * Fluent builder for {@link HonoClientCredentialsFlow}.
 *
 * Provides a chainable API to configure all aspects of the Client Credentials flow
 * for Hono, including client lookup, token generation, token verification, and
 * scope enforcement.
 *
 * @template E - The Hono `Env` type for the application.
 *
 * @example
 * ```ts
 * const flow = HonoClientCredentialsFlowBuilder
 *   .create()
 *   .setTokenEndpoint("/token")
 *   .clientSecretBasicAuthenticationMethod()
 *   .getClient(async (req) => lookupClient(req))
 *   .generateAccessToken(async (ctx) => generateJwt(ctx))
 *   .tokenVerifier((c, { token }) => verifyJwt(token))
 *   .build();
 * ```
 */
export class HonoClientCredentialsFlowBuilder<
  E extends Env = Env,
> extends ClientCredentialsFlowBuilder {
  protected strategyOptions: HonoOAuth2StrategyOptions<E> = {};

  constructor(options: Partial<HonoClientCredentialsFlowOptions<E>>) {
    const { strategyOptions, ...flowOptions } = options;
    super({
      ...flowOptions,
      strategyOptions: {},
    });
    this.strategyOptions = strategyOptions || {};
  }

  /**
   * Creates a new `HonoClientCredentialsFlowBuilder` instance.
   *
   * @param options - Optional initial builder options.
   * @returns A new builder instance.
   */
  static create<E extends Env = Env>(
    options?: Partial<HonoClientCredentialsFlowOptions<E>>,
  ): HonoClientCredentialsFlowBuilder<E> {
    return new HonoClientCredentialsFlowBuilder<E>(options || {});
  }

  /**
   * Sets the action to invoke when authorization fails (e.g. missing or invalid token).
   *
   * @param action - A handler that receives the Hono context and the authorization error.
   * @returns `this` for chaining.
   */
  failedAuthorizationAction(action: FailedAuthorizationAction<E>): this {
    this.strategyOptions.failedAuthorizationAction = action;
    return this;
  }

  /**
   * This method does not have access to the Hono context.
   * Use `tokenVerifier` instead to set a handler that receives the Hono context.
   * @deprecated Use `tokenVerifier` instead to set a handler that receives the Hono context.
   * @param handler
   * @returns
   */
  override verifyToken(handler: StrategyVerifyTokenFunction<Request>): this {
    this.strategyOptions.verifyToken = async (c, params) => {
      return await handler(c.req.raw.clone(), params);
    };
    return this;
  }

  /**
   * Sets the token verification handler with full access to the Hono `Context`.
   *
   * Prefer this over `verifyToken` when you need to access Hono
   * context variables, environment bindings, or other request state during verification.
   *
   * @param handler - Async function that receives the Hono context and token params, and returns a strategy result.
   * @returns `this` for chaining.
   */
  tokenVerifier(handler: StrategyVerifyTokenFunction<Context<E & OAuth2ServerEnv>>): this {
    this.strategyOptions.verifyToken = handler;
    return this;
  }

  /**
   * Builds and returns a configured {@link HonoClientCredentialsFlow} instance.
   *
   * @returns A new `HonoClientCredentialsFlow`.
   */
  override build(): HonoClientCredentialsFlow<E> {
    const params: HonoClientCredentialsFlowOptions<E> = {
      ...this.buildParams(),
      strategyOptions: this.strategyOptions,
    };
    return new HonoClientCredentialsFlow<E>(params);
  }
}

/**
 * Fluent builder for {@link HonoOIDCClientCredentialsFlow}.
 *
 * Provides a chainable API to configure all aspects of the OIDC Client Credentials flow
 * for Hono, including client lookup, token generation, token verification, and
 * scope enforcement.
 *
 * @template E - The Hono `Env` type for the application.
 *
 * @example
 * ```ts
 * const flow = HonoOIDCClientCredentialsFlowBuilder
 *   .create()
 *   .setTokenEndpoint("/token")
 *   .clientSecretBasicAuthenticationMethod()
 *   .getClient(async (req) => lookupClient(req))
 *   .generateAccessToken(async (ctx) => generateJwt(ctx))
 *   .tokenVerifier((c, { token }) => verifyJwt(token))
 *   .build();
 * ```
 */
export class HonoOIDCClientCredentialsFlowBuilder<
  E extends Env = Env,
> extends OIDCClientCredentialsFlowBuilder {
  protected strategyOptions: HonoOAuth2StrategyOptions<E> = {};

  constructor(options: Partial<HonoOIDCClientCredentialsFlowOptions<E>>) {
    const { strategyOptions, ...flowOptions } = options;
    super({
      ...flowOptions,
      strategyOptions: {},
    });
    this.strategyOptions = strategyOptions || {};
  }

  /**
   * Creates a new `HonoOIDCClientCredentialsFlowBuilder` instance.
   *
   * @param options - Optional initial builder options.
   * @returns A new builder instance.
   */
  static create<E extends Env = Env>(
    options?: Partial<HonoOIDCClientCredentialsFlowOptions<E>>,
  ): HonoOIDCClientCredentialsFlowBuilder<E> {
    return new HonoOIDCClientCredentialsFlowBuilder<E>(options || {});
  }

  /**
   * Sets the action to invoke when authorization fails (e.g. missing or invalid token).
   *
   * @param action - A handler that receives the Hono context and the authorization error.
   * @returns `this` for chaining.
   */
  failedAuthorizationAction(action: FailedAuthorizationAction<E>): this {
    this.strategyOptions.failedAuthorizationAction = action;
    return this;
  }

  /**
   * This method does not have access to the Hono context.
   * Use `tokenVerifier` instead to set a handler that receives the Hono context.
   * @deprecated Use `tokenVerifier` instead to set a handler that receives the Hono context.
   * @param handler
   * @returns
   */
  override verifyToken(handler: StrategyVerifyTokenFunction<Request>): this {
    this.strategyOptions.verifyToken = async (c, params) => {
      return await handler(c.req.raw.clone(), params);
    };
    return this;
  }

  /**
   * Sets the token verification handler with full access to the Hono `Context`.
   *
   * Prefer this over `verifyToken` when you need to access Hono
   * context variables, environment bindings, or other request state during verification.
   *
   * @param handler - Async function that receives the Hono context and token params, and returns a strategy result.
   * @returns `this` for chaining.
   */
  tokenVerifier(handler: StrategyVerifyTokenFunction<Context<E & OAuth2ServerEnv>>): this {
    this.strategyOptions.verifyToken = handler;
    return this;
  }

  /**
   * Builds and returns a configured {@link HonoOIDCClientCredentialsFlow} instance.
   *
   * @returns A new `HonoOIDCClientCredentialsFlow`.
   */
  override build(): HonoOIDCClientCredentialsFlow<E> {
    const params: HonoOIDCClientCredentialsFlowOptions<E> = {
      ...this.buildParams(),
      strategyOptions: this.strategyOptions,
    };
    return new HonoOIDCClientCredentialsFlow<E>(params);
  }
}

//#endregion
