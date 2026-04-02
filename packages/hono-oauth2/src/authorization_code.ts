// @saurbit/hono-oauth2/authorization_code.ts

import type { Context, Env, MiddlewareHandler } from "hono";
import { HTTPException } from "hono/http-exception";
import {
  type AuthorizationCodeEndpointResponse,
  AuthorizationCodeFlow,
  AuthorizationCodeFlowBuilder,
  type AuthorizationCodeFlowOptions,
  type AuthorizationCodeInitiationResponse,
  type AuthorizationCodeProcessResponse,
  type AuthorizationCodeReqData,
  evaluateStrategy,
  InvalidRequestError,
  type OAuth2FlowTokenResponse,
  type OIDCAuthorizationCodeEndpointResponse,
  OIDCAuthorizationCodeFlow,
  OIDCAuthorizationCodeFlowBuilder,
  type OIDCAuthorizationCodeFlowOptions,
  type OIDCAuthorizationCodeInitiationResponse,
  type OIDCAuthorizationCodeProcessResponse,
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
 * Configuration options for {@link HonoAuthorizationCodeFlow}.
 *
 * Extends the base `AuthorizationCodeFlowOptions` with Hono-specific strategy options
 * and a handler to extract authorization endpoint data from the Hono `Context`.
 *
 * @template AuthReqData - The shape of the parsed authorization request data.
 * @template E - The Hono `Env` type for the application.
 */
export interface HonoAuthorizationCodeFlowOptions<
  AuthReqData extends AuthorizationCodeReqData = AuthorizationCodeReqData,
  E extends Env = Env,
> extends Omit<AuthorizationCodeFlowOptions<AuthReqData>, "strategyOptions"> {
  /** Hono-specific strategy options, including token verification and failed authorization handling. */
  strategyOptions: HonoOAuth2StrategyOptions<E>;
  /** Handler called on POST requests to parse and return the authorization request data from the Hono context. */
  parseAuthorizationEndpointData: (context: Context<E & OAuth2ServerEnv>) => Promise<AuthReqData>;
}

/**
 * Builder options for {@link HonoAuthorizationCodeFlowBuilder}.
 *
 * All fields from {@link HonoAuthorizationCodeFlowOptions} are optional except
 * `parseAuthorizationEndpointData`, which is required.
 *
 * @template AuthReqData - The shape of the parsed authorization request data.
 * @template E - The Hono `Env` type for the application.
 */
export interface HonoAuthorizationCodeFlowBuilderOptions<
  AuthReqData extends AuthorizationCodeReqData = AuthorizationCodeReqData,
  E extends Env = Env,
> extends
  Partial<Omit<HonoAuthorizationCodeFlowOptions<AuthReqData, E>, "parseAuthorizationEndpointData">>,
  Pick<HonoAuthorizationCodeFlowOptions<AuthReqData, E>, "parseAuthorizationEndpointData"> {
}

/**
 * Hono-adapted methods for the Authorization Code flow.
 *
 * Provides convenience wrappers around the core flow that accept a Hono `Context`
 * instead of a raw `Request`. Obtained via {@link HonoAuthorizationCodeFlow.hono}.
 *
 * @template E - The Hono `Env` type for the application.
 */
export interface HonoAuthorizationCodeMethods<E extends Env = Env> extends HonoMethods<E> {
  /**
   * This method is a convenience method that combines the logic of initiating (GET) the authorization code flow for Hono.
   * It checks the HTTP method of the request and calls the appropriate method to handle the authorization endpoint logic.
   * @param context
   * @returns
   */
  initiateAuthorization(
    context: Context,
  ): Promise<AuthorizationCodeInitiationResponse>;

  /**
   * This method is a convenience method that combines the logic of processing (POST) the authorization code flow for Hono.
   * It checks the HTTP method of the request and calls the appropriate method to handle the authorization endpoint logic.
   * @param context
   * @returns
   */
  processAuthorization(
    context: Context,
  ): Promise<AuthorizationCodeProcessResponse>;

  /**
   * This method is a convenience method that handles the authorization endpoint logic for Hono.
   * It checks the HTTP method of the request and calls the appropriate method to handle the authorization endpoint logic.
   * @param context
   * @returns
   */
  handleAuthorizationEndpoint(
    context: Context,
  ): Promise<AuthorizationCodeEndpointResponse>;
}

//#endregion

//#region OpenID Connect Types and Interfaces

/**
 * Configuration options for {@link HonoOIDCAuthorizationCodeFlow}.
 *
 * Extends the base `OIDCAuthorizationCodeFlowOptions` with Hono-specific strategy options
 * and a handler to extract authorization endpoint data from the Hono `Context`.
 *
 * @template AuthReqData - The shape of the parsed authorization request data.
 * @template E - The Hono `Env` type for the application.
 */
export interface HonoOIDCAuthorizationCodeFlowOptions<
  AuthReqData extends AuthorizationCodeReqData = AuthorizationCodeReqData,
  E extends Env = Env,
> extends Omit<OIDCAuthorizationCodeFlowOptions<AuthReqData>, "strategyOptions"> {
  /** Hono-specific strategy options, including token verification and failed authorization handling. */
  strategyOptions: HonoOAuth2StrategyOptions<E>;
  /** Handler called on POST requests to parse and return the authorization request data from the Hono context. */
  parseAuthorizationEndpointData: (context: Context<E & OAuth2ServerEnv>) => Promise<AuthReqData>;
}

/**
 * Builder options for {@link HonoOIDCAuthorizationCodeFlowBuilder}.
 *
 * All fields from {@link HonoOIDCAuthorizationCodeFlowOptions} are optional except
 * `parseAuthorizationEndpointData`, which is required.
 *
 * @template AuthReqData - The shape of the parsed authorization request data.
 * @template E - The Hono `Env` type for the application.
 */
export interface HonoOIDCAuthorizationCodeFlowBuilderOptions<
  AuthReqData extends AuthorizationCodeReqData = AuthorizationCodeReqData,
  E extends Env = Env,
> extends
  Partial<
    Omit<HonoOIDCAuthorizationCodeFlowOptions<AuthReqData, E>, "parseAuthorizationEndpointData">
  >,
  Pick<HonoOIDCAuthorizationCodeFlowOptions<AuthReqData, E>, "parseAuthorizationEndpointData"> {
}

/**
 * Hono-adapted methods for the OIDC Authorization Code flow.
 *
 * Provides convenience wrappers around the core OIDC flow that accept a Hono `Context`
 * instead of a raw `Request`. Obtained via {@link HonoOIDCAuthorizationCodeFlow.hono}.
 *
 * @template E - The Hono `Env` type for the application.
 */
export interface HonoOIDCAuthorizationCodeMethods<E extends Env = Env> extends HonoMethods<E> {
  /**
   * This method is a convenience method that combines the logic of initiating (GET) the authorization code flow for Hono.
   * It checks the HTTP method of the request and calls the appropriate method to handle the authorization endpoint logic.
   * @param context
   * @returns
   */
  initiateAuthorization(
    context: Context,
  ): Promise<OIDCAuthorizationCodeInitiationResponse>;

  /**
   * This method is a convenience method that combines the logic of processing (POST) the authorization code flow for Hono.
   * It checks the HTTP method of the request and calls the appropriate method to handle the authorization endpoint logic.
   * @param context
   * @returns
   */
  processAuthorization(
    context: Context,
  ): Promise<OIDCAuthorizationCodeProcessResponse>;

  /**
   * This method is a convenience method that handles the authorization endpoint logic for Hono.
   * It checks the HTTP method of the request and calls the appropriate method to handle the authorization endpoint logic.
   * @param context
   * @returns
   */
  handleAuthorizationEndpoint(
    context: Context,
  ): Promise<OIDCAuthorizationCodeEndpointResponse>;
}

//#endregion

//#region Classes

/**
 * Hono adapter for the OAuth 2.0 Authorization Code flow.
 *
 * Wraps {@link AuthorizationCodeFlow} to integrate natively with Hono's `Context`,
 * providing middleware for route protection and convenience methods for the
 * authorization and token endpoints.
 *
 * Use {@link HonoAuthorizationCodeFlowBuilder} for a fluent configuration API.
 *
 * @template E - The Hono `Env` type for the application.
 * @template AuthReqData - The shape of the parsed authorization request data.
 */
export class HonoAuthorizationCodeFlow<
  E extends Env = Env,
  AuthReqData extends AuthorizationCodeReqData = AuthorizationCodeReqData,
> extends AuthorizationCodeFlow<AuthReqData> implements HonoAdapted<E> {
  readonly #tokenVerifier: (
    context: Context<E & OAuth2ServerEnv>,
  ) => Promise<StrategyResult>;
  readonly #authorizeMiddleware: MiddlewareHandler<E & OAuth2ServerEnv>;

  readonly #failedAuthorizationAction: FailedAuthorizationAction<E>;

  readonly #parseAuthorizationEndpointData: (
    context: Context<E & OAuth2ServerEnv>,
  ) => Promise<AuthReqData>;

  readonly #hono: HonoAuthorizationCodeMethods<E> = {
    authorizeMiddleware: (scopes?: string[]): MiddlewareHandler<E & OAuth2ServerEnv> => {
      return scopes?.length ? this.#createAuthorizeMiddleware(scopes) : this.#authorizeMiddleware;
    },
    token: async (context: Context): Promise<OAuth2FlowTokenResponse> => {
      return await this.token(context.req.raw);
    },

    verifyToken: async (context: Context<E & OAuth2ServerEnv>): Promise<StrategyResult> => {
      return await this.#tokenVerifier(context);
    },

    initiateAuthorization: async (
      context: Context,
    ): Promise<AuthorizationCodeInitiationResponse> => {
      return await this.initiateAuthorization(context.req.raw);
    },

    processAuthorization: async (
      context: Context,
    ): Promise<AuthorizationCodeProcessResponse> => {
      return await this.processAuthorization(
        context.req.raw.clone(),
        await this.#parseAuthorizationEndpointData(context),
      );
    },

    handleAuthorizationEndpoint: async (
      context: Context,
    ): Promise<AuthorizationCodeEndpointResponse> => {
      if (context.req.method === "GET") {
        // In a real implementation, you would render a login page
        // or consent page here for the user
        // to authenticate and authorize the client.
        const result = await this.hono().initiateAuthorization(context);

        if (!result.success) {
          return {
            type: "error",
            ...result,
          };
        }

        return {
          ...result,
          type: "initiated",
          method: "GET",
        };
      }

      if (context.req.method === "POST") {
        // In a real implementation, you would authenticate the user here,
        // and if authentication is successful, generate an authorization code,
        // and redirect the user to the redirect_uri with the code and state as query parameters.

        const result = await this.hono().processAuthorization(context);

        if (result.type === "error") {
          return result;
        }

        return {
          ...result,
          method: "POST",
        };
      }

      return {
        type: "error",
        error: new InvalidRequestError("Unsupported HTTP method"),
        redirectable: false,
      };
    },
  };

  constructor(options: HonoAuthorizationCodeFlowOptions<AuthReqData, E>) {
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

    this.#parseAuthorizationEndpointData = options.parseAuthorizationEndpointData;

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
   * @returns A readonly {@link HonoAuthorizationCodeMethods} instance.
   */
  hono(): Readonly<HonoAuthorizationCodeMethods<E>> {
    return Object.freeze(this.#hono);
  }
}

/**
 * Hono adapter for the OpenID Connect Authorization Code flow.
 *
 * Wraps {@link OIDCAuthorizationCodeFlow} to integrate natively with Hono's `Context`,
 * providing middleware for route protection and convenience methods for the
 * authorization and token endpoints. Extends the standard Authorization Code flow
 * with OpenID Connect features such as ID token issuance.
 *
 * Use {@link HonoOIDCAuthorizationCodeFlowBuilder} for a fluent configuration API.
 *
 * @template E - The Hono `Env` type for the application.
 * @template AuthReqData - The shape of the parsed authorization request data.
 */
export class HonoOIDCAuthorizationCodeFlow<
  E extends Env = Env,
  AuthReqData extends AuthorizationCodeReqData = AuthorizationCodeReqData,
> extends OIDCAuthorizationCodeFlow<AuthReqData> implements HonoAdapted<E> {
  readonly #tokenVerifier: (
    context: Context<E & OAuth2ServerEnv>,
  ) => Promise<StrategyResult>;
  readonly #authorizeMiddleware: MiddlewareHandler<E & OAuth2ServerEnv>;

  readonly #failedAuthorizationAction: FailedAuthorizationAction<E>;

  readonly #parseAuthorizationEndpointData: (
    context: Context<E & OAuth2ServerEnv>,
  ) => Promise<AuthReqData>;

  readonly #hono: HonoOIDCAuthorizationCodeMethods<E> = {
    authorizeMiddleware: (scopes?: string[]): MiddlewareHandler<E & OAuth2ServerEnv> => {
      return scopes?.length ? this.#createAuthorizeMiddleware(scopes) : this.#authorizeMiddleware;
    },
    token: async (context: Context): Promise<OAuth2FlowTokenResponse> => {
      return await this.token(context.req.raw);
    },

    verifyToken: async (context: Context<E & OAuth2ServerEnv>): Promise<StrategyResult> => {
      return await this.#tokenVerifier(context);
    },

    initiateAuthorization: async (
      context: Context,
    ): Promise<OIDCAuthorizationCodeInitiationResponse> => {
      return await this.initiateAuthorization(context.req.raw);
    },

    processAuthorization: async (
      context: Context,
    ): Promise<OIDCAuthorizationCodeProcessResponse> => {
      return await this.processAuthorization(
        context.req.raw.clone(),
        await this.#parseAuthorizationEndpointData(context),
      );
    },

    handleAuthorizationEndpoint: async (
      context: Context,
    ): Promise<OIDCAuthorizationCodeEndpointResponse> => {
      if (context.req.method === "GET") {
        // In a real implementation, you would render a login page
        // or consent page here for the user
        // to authenticate and authorize the client.
        const result = await this.hono().initiateAuthorization(context);

        if (!result.success) {
          return {
            type: "error",
            ...result,
          };
        }

        return {
          ...result,
          type: "initiated",
          method: "GET",
        };
      }

      if (context.req.method === "POST") {
        // In a real implementation, you would authenticate the user here,
        // and if authentication is successful, generate an authorization code,
        // and redirect the user to the redirect_uri with the code and state as query parameters.

        const result = await this.hono().processAuthorization(context);

        if (result.type === "error") {
          return result;
        }

        return {
          ...result,
          method: "POST",
        };
      }

      return {
        type: "error",
        error: new InvalidRequestError("Unsupported HTTP method"),
        redirectable: false,
      };
    },
  };

  constructor(options: HonoOIDCAuthorizationCodeFlowOptions<AuthReqData, E>) {
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

    this.#parseAuthorizationEndpointData = options.parseAuthorizationEndpointData;

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
   * @returns A readonly {@link HonoOIDCAuthorizationCodeMethods} instance.
   */
  hono(): Readonly<HonoOIDCAuthorizationCodeMethods<E>> {
    return Object.freeze(this.#hono);
  }
}

//#endregion

//#region Builders

/**
 * Fluent builder for {@link HonoAuthorizationCodeFlow}.
 *
 * Provides a chainable API to configure all aspects of the Authorization Code flow
 * for Hono, including client lookup, token generation, token verification, scope
 * enforcement, and authorization endpoint data parsing.
 *
 * @template E - The Hono `Env` type for the application.
 * @template AuthReqData - The shape of the parsed authorization request data.
 *
 * @example
 * ```ts
 * const flow = HonoAuthorizationCodeFlowBuilder
 *   .create({ parseAuthorizationEndpointData: (c) => parseFormData(c) })
 *   .setTokenEndpoint("/token")
 *   .tokenVerifier((c, { token }) => verifyJwt(token))
 *   .build();
 * ```
 */
export class HonoAuthorizationCodeFlowBuilder<
  E extends Env = Env,
  AuthReqData extends AuthorizationCodeReqData = AuthorizationCodeReqData,
> extends AuthorizationCodeFlowBuilder<AuthReqData> {
  protected strategyOptions: HonoOAuth2StrategyOptions<E> = {};
  protected parseAuthorizationEndpointDataHandler: (
    context: Context<E & OAuth2ServerEnv>,
  ) => Promise<AuthReqData>;

  constructor(options: HonoAuthorizationCodeFlowBuilderOptions<AuthReqData, E>) {
    const { strategyOptions, parseAuthorizationEndpointData, ...flowOptions } = options;
    super({
      ...flowOptions,
      strategyOptions: {},
    });
    this.strategyOptions = strategyOptions || {};
    this.parseAuthorizationEndpointDataHandler = parseAuthorizationEndpointData;
  }

  /**
   * Creates a new `HonoAuthorizationCodeFlowBuilder` instance.
   *
   * @param options - Initial builder options. `parseAuthorizationEndpointData` is required.
   * @returns A new builder instance.
   */
  static create<
    E extends Env = Env,
    AuthReqData extends AuthorizationCodeReqData = AuthorizationCodeReqData,
  >(
    options: HonoAuthorizationCodeFlowBuilderOptions<AuthReqData, E>,
  ): HonoAuthorizationCodeFlowBuilder<E, AuthReqData> {
    return new HonoAuthorizationCodeFlowBuilder<E, AuthReqData>(options);
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
   * Sets the handler used to parse authorization request data from the Hono context on POST requests.
   *
   * @param handler - Async function that extracts and returns the authorization request data.
   * @returns `this` for chaining.
   */
  parseAuthorizationEndpointData(
    handler: (context: Context<E & OAuth2ServerEnv>) => Promise<AuthReqData>,
  ): this {
    this.parseAuthorizationEndpointDataHandler = handler;
    return this;
  }

  /**
   * Builds and returns a configured {@link HonoAuthorizationCodeFlow} instance.
   *
   * @returns A new `HonoAuthorizationCodeFlow`.
   */
  override build(): HonoAuthorizationCodeFlow<E, AuthReqData> {
    const params: HonoAuthorizationCodeFlowOptions<AuthReqData, E> = {
      ...this.buildParams(),
      strategyOptions: this.strategyOptions,
      parseAuthorizationEndpointData: this.parseAuthorizationEndpointDataHandler,
    };
    return new HonoAuthorizationCodeFlow<E, AuthReqData>(params);
  }
}

/**
 * Fluent builder for {@link HonoOIDCAuthorizationCodeFlow}.
 *
 * Provides a chainable API to configure all aspects of the OIDC Authorization Code flow
 * for Hono, including client lookup, token generation, token verification, scope
 * enforcement, and authorization endpoint data parsing.
 *
 * @template E - The Hono `Env` type for the application.
 * @template AuthReqData - The shape of the parsed authorization request data.
 *
 * @example
 * ```ts
 * const flow = HonoOIDCAuthorizationCodeFlowBuilder
 *   .create({ parseAuthorizationEndpointData: (c) => parseFormData(c) })
 *   .setTokenEndpoint("/token")
 *   .tokenVerifier((c, { token }) => verifyJwt(token))
 *   .build();
 * ```
 */
export class HonoOIDCAuthorizationCodeFlowBuilder<
  E extends Env = Env,
  AuthReqData extends AuthorizationCodeReqData = AuthorizationCodeReqData,
> extends OIDCAuthorizationCodeFlowBuilder<AuthReqData> {
  protected strategyOptions: HonoOAuth2StrategyOptions<E> = {};
  protected parseAuthorizationEndpointDataHandler: (
    context: Context<E & OAuth2ServerEnv>,
  ) => Promise<AuthReqData>;

  constructor(options: HonoOIDCAuthorizationCodeFlowBuilderOptions<AuthReqData, E>) {
    const { strategyOptions, parseAuthorizationEndpointData, ...flowOptions } = options;
    super({
      ...flowOptions,
      strategyOptions: {},
    });
    this.strategyOptions = strategyOptions || {};
    this.parseAuthorizationEndpointDataHandler = parseAuthorizationEndpointData;
  }

  /**
   * Creates a new `HonoOIDCAuthorizationCodeFlowBuilder` instance.
   *
   * @param options - Initial builder options. `parseAuthorizationEndpointData` is required.
   * @returns A new builder instance.
   */
  static create<
    E extends Env = Env,
    AuthReqData extends AuthorizationCodeReqData = AuthorizationCodeReqData,
  >(
    options: HonoOIDCAuthorizationCodeFlowBuilderOptions<AuthReqData, E>,
  ): HonoOIDCAuthorizationCodeFlowBuilder<E, AuthReqData> {
    return new HonoOIDCAuthorizationCodeFlowBuilder<E, AuthReqData>(options);
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
   * Sets the handler used to parse authorization request data from the Hono context on POST requests.
   *
   * @param handler - Async function that extracts and returns the authorization request data.
   * @returns `this` for chaining.
   */
  parseAuthorizationEndpointData(
    handler: (context: Context<E & OAuth2ServerEnv>) => Promise<AuthReqData>,
  ): this {
    this.parseAuthorizationEndpointDataHandler = handler;
    return this;
  }

  /**
   * Builds and returns a configured {@link HonoOIDCAuthorizationCodeFlow} instance.
   *
   * @returns A new `HonoOIDCAuthorizationCodeFlow`.
   */
  override build(): HonoOIDCAuthorizationCodeFlow<E, AuthReqData> {
    const params: HonoOIDCAuthorizationCodeFlowOptions<AuthReqData, E> = {
      ...this.buildParams(),
      strategyOptions: this.strategyOptions,
      parseAuthorizationEndpointData: this.parseAuthorizationEndpointDataHandler,
    };
    return new HonoOIDCAuthorizationCodeFlow<E, AuthReqData>(params);
  }
}

//#endregion
