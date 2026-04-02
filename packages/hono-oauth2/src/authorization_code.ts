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

export interface HonoAuthorizationCodeFlowOptions<
  AuthReqData extends AuthorizationCodeReqData = AuthorizationCodeReqData,
  E extends Env = Env,
> extends Omit<AuthorizationCodeFlowOptions<AuthReqData>, "strategyOptions"> {
  strategyOptions: HonoOAuth2StrategyOptions<E>;
  parseAuthorizationEndpointData: (context: Context<E & OAuth2ServerEnv>) => Promise<AuthReqData>;
}

export interface HonoAuthorizationCodeFlowBuilderOptions<
  AuthReqData extends AuthorizationCodeReqData = AuthorizationCodeReqData,
  E extends Env = Env,
> extends
  Partial<Omit<HonoAuthorizationCodeFlowOptions<AuthReqData, E>, "parseAuthorizationEndpointData">>,
  Pick<HonoAuthorizationCodeFlowOptions<AuthReqData, E>, "parseAuthorizationEndpointData"> {
}

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

export interface HonoOIDCAuthorizationCodeFlowOptions<
  AuthReqData extends AuthorizationCodeReqData = AuthorizationCodeReqData,
  E extends Env = Env,
> extends Omit<OIDCAuthorizationCodeFlowOptions<AuthReqData>, "strategyOptions"> {
  strategyOptions: HonoOAuth2StrategyOptions<E>;
  parseAuthorizationEndpointData: (context: Context<E & OAuth2ServerEnv>) => Promise<AuthReqData>;
}

export interface HonoOIDCAuthorizationCodeFlowBuilderOptions<
  AuthReqData extends AuthorizationCodeReqData = AuthorizationCodeReqData,
  E extends Env = Env,
> extends
  Partial<
    Omit<HonoOIDCAuthorizationCodeFlowOptions<AuthReqData, E>, "parseAuthorizationEndpointData">
  >,
  Pick<HonoOIDCAuthorizationCodeFlowOptions<AuthReqData, E>, "parseAuthorizationEndpointData"> {
}

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

  hono(): Readonly<HonoAuthorizationCodeMethods<E>> {
    return Object.freeze(this.#hono);
  }
}

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

  hono(): Readonly<HonoOIDCAuthorizationCodeMethods<E>> {
    return Object.freeze(this.#hono);
  }
}

//#endregion

//#region Builders

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

  static create<
    E extends Env = Env,
    AuthReqData extends AuthorizationCodeReqData = AuthorizationCodeReqData,
  >(
    options: HonoAuthorizationCodeFlowBuilderOptions<AuthReqData, E>,
  ) {
    return new HonoAuthorizationCodeFlowBuilder<E, AuthReqData>(options);
  }

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

  tokenVerifier(handler: StrategyVerifyTokenFunction<Context<E & OAuth2ServerEnv>>): this {
    this.strategyOptions.verifyToken = handler;
    return this;
  }

  parseAuthorizationEndpointData(
    handler: (context: Context<E & OAuth2ServerEnv>) => Promise<AuthReqData>,
  ): this {
    this.parseAuthorizationEndpointDataHandler = handler;
    return this;
  }

  override build(): HonoAuthorizationCodeFlow<E, AuthReqData> {
    const params: HonoAuthorizationCodeFlowOptions<AuthReqData, E> = {
      ...this.buildParams(),
      strategyOptions: this.strategyOptions,
      parseAuthorizationEndpointData: this.parseAuthorizationEndpointDataHandler,
    };
    return new HonoAuthorizationCodeFlow<E, AuthReqData>(params);
  }
}

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

  static create<
    E extends Env = Env,
    AuthReqData extends AuthorizationCodeReqData = AuthorizationCodeReqData,
  >(
    options: HonoOIDCAuthorizationCodeFlowBuilderOptions<AuthReqData, E>,
  ) {
    return new HonoOIDCAuthorizationCodeFlowBuilder<E, AuthReqData>(options);
  }

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

  tokenVerifier(handler: StrategyVerifyTokenFunction<Context<E & OAuth2ServerEnv>>): this {
    this.strategyOptions.verifyToken = handler;
    return this;
  }

  parseAuthorizationEndpointData(
    handler: (context: Context<E & OAuth2ServerEnv>) => Promise<AuthReqData>,
  ): this {
    this.parseAuthorizationEndpointDataHandler = handler;
    return this;
  }

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
