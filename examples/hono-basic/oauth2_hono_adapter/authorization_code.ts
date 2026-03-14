// oauth2_hono_adapter/authorization_code.ts

import type { Context, Env, MiddlewareHandler } from "hono";
import { HTTPException } from "hono/http-exception";
import {
  AuthorizationCodeFlow,
  AuthorizationCodeFlowOptions,
  AuthorizationCodeReqData,
  evaluateStrategy,
  InvalidRequestError,
  OAuth2FlowTokenResponse,
  OIDCAuthorizationCodeFlowOptions,
  OIDCAuthorizationCodeInitiationResponse,
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
import { OIDCAuthorizationCodeFlow } from "@saurbit/oauth2-server";
import { OIDCAuthorizationCodeProcessResponse } from "@saurbit/oauth2-server";
import { OIDCAuthorizationCodeEndpointResponse } from "@saurbit/oauth2-server";
import { AuthorizationCodeBuilder } from "@saurbit/oauth2-server";

//#region Types and Interfaces

export interface HonoAuthorizationCodeFlowOptions<
  AuthReqData extends AuthorizationCodeReqData = AuthorizationCodeReqData,
  E extends Env = Env,
> extends Omit<AuthorizationCodeFlowOptions<AuthReqData>, "strategyOptions"> {
  strategyOptions: HonoOAuth2StrategyOptions<E>;
  parseAuthorizationEndpointData: (context: Context<E & OAuth2ServerEnv>) => Promise<AuthReqData>;
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

//#region OpenID Connect Types and Interfaces

export interface HonoOIDCAuthorizationCodeFlowOptions<
  AuthReqData extends AuthorizationCodeReqData = AuthorizationCodeReqData,
  E extends Env = Env,
> extends Omit<OIDCAuthorizationCodeFlowOptions<AuthReqData>, "strategyOptions"> {
  strategyOptions: HonoOAuth2StrategyOptions<E>;
  parseAuthorizationEndpointData: (context: Context<E & OAuth2ServerEnv>) => Promise<AuthReqData>;
}

//#endregion

//#region Classes

export class HonoAuthorizationCodeFlow<
  E extends Env = Env,
  AuthReqData extends AuthorizationCodeReqData = AuthorizationCodeReqData,
> extends AuthorizationCodeFlow<AuthReqData> implements HonoAdapted<E> {
  readonly #verifyTokenHandler: (
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
      return await this.#verifyTokenHandler(context);
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

  hono(): Readonly<HonoAuthorizationCodeMethods<E>> {
    return Object.freeze(this.#hono);
  }
}

export class HonoOIDCAuthorizationCodeFlow<
  E extends Env = Env,
  AuthReqData extends AuthorizationCodeReqData = AuthorizationCodeReqData,
> extends OIDCAuthorizationCodeFlow<AuthReqData> implements HonoAdapted<E> {
  readonly #verifyTokenHandler: (
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
      return await this.#verifyTokenHandler(context);
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

  hono(): Readonly<HonoAuthorizationCodeMethods<E>> {
    return Object.freeze(this.#hono);
  }
}

//#endregion

//#region Builders

export class HonoAuthorizationCodeFlowBuilder<
  E extends Env = Env,
  AuthReqData extends AuthorizationCodeReqData = AuthorizationCodeReqData,
> extends AuthorizationCodeBuilder<AuthReqData> {
  protected strategyOptions: HonoOAuth2StrategyOptions<E> = {};
  protected _parseAuthorizationEndpointData?: (
    context: Context<E & OAuth2ServerEnv>,
  ) => Promise<AuthReqData>;

  constructor(options: Partial<HonoAuthorizationCodeFlowOptions<AuthReqData, E>>) {
    const { strategyOptions, parseAuthorizationEndpointData, ...flowOptions } = options;
    super({
      ...flowOptions,
      strategyOptions: {},
    });
    this.strategyOptions = strategyOptions || {};
    this._parseAuthorizationEndpointData = parseAuthorizationEndpointData;
  }

  static override create<
    E extends Env = Env,
    AuthReqData extends AuthorizationCodeReqData = AuthorizationCodeReqData,
  >(
    options?: Partial<HonoAuthorizationCodeFlowOptions<AuthReqData, E>>,
  ) {
    return new HonoAuthorizationCodeFlowBuilder<E, AuthReqData>(options || {});
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

  parseAuthorizationEndpointData(
    handler: (context: Context<E & OAuth2ServerEnv>) => Promise<AuthReqData>,
  ): this {
    this._parseAuthorizationEndpointData = handler;
    return this;
  }

  override build(): HonoAuthorizationCodeFlow<E, AuthReqData> {
    const params: HonoAuthorizationCodeFlowOptions<AuthReqData, E> = {
      ...this.buildParams(),
      strategyOptions: this.strategyOptions,
      parseAuthorizationEndpointData: this._parseAuthorizationEndpointData || (async (context) => {
        const formData = await context.req.formData();
        const data: Record<string, unknown> = {};

        for (const key of formData.keys()) {
          const values = formData.getAll(key);
          data[key] = values.length === 1 ? values[0] : values;
        }

        return data as AuthReqData;
      }),
    };
    return new HonoAuthorizationCodeFlow<E, AuthReqData>(params);
  }
}

//#endregion
