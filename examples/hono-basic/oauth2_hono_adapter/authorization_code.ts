// oauth2_hono_adapter/authorization_code.ts

import type { Context, Env, MiddlewareHandler } from "hono";
import { HTTPException } from "hono/http-exception";
import {
  AuthorizationCodeFlow,
  AuthorizationCodeFlowOptions,
  AuthorizationCodeReqBody,
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
  HonoStrategyOptionsWithFailedAuth,
  OAuth2ServerEnv,
} from "./types.ts";
import { OIDCAuthorizationCodeFlow } from "@saurbit/oauth2-server";
import { OIDCAuthorizationCodeProcessResponse } from "@saurbit/oauth2-server";
import { OIDCAuthorizationCodeEndpointResponse } from "@saurbit/oauth2-server";

//#region Types and Interfaces

export interface HonoAuthorizationCodeFlowOptions<
  AuthReqBody extends AuthorizationCodeReqBody = AuthorizationCodeReqBody,
  E extends Env = Env,
> extends Omit<AuthorizationCodeFlowOptions<AuthReqBody>, "strategyOptions"> {
  strategyOptions: HonoStrategyOptionsWithFailedAuth<E>;
  parseAuthorizationEndpointBody: (context: Context<E & OAuth2ServerEnv>) => Promise<AuthReqBody>;
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
  AuthReqBody extends AuthorizationCodeReqBody = AuthorizationCodeReqBody,
  E extends Env = Env,
> extends Omit<OIDCAuthorizationCodeFlowOptions<AuthReqBody>, "strategyOptions"> {
  strategyOptions: HonoStrategyOptionsWithFailedAuth<E>;
  parseAuthorizationEndpointBody: (context: Context<E & OAuth2ServerEnv>) => Promise<AuthReqBody>;
}

//#endregion

//#region Classes

export class HonoAuthorizationCodeFlow<
  E extends Env = Env,
  AuthReqBody extends AuthorizationCodeReqBody = AuthorizationCodeReqBody,
> extends AuthorizationCodeFlow<AuthReqBody> implements HonoAdapted<E> {
  readonly #verifyTokenHandler: (
    context: Context<E & OAuth2ServerEnv>,
  ) => Promise<StrategyResult>;
  readonly #authorizeMiddleware: MiddlewareHandler<E & OAuth2ServerEnv>;

  readonly #failedAuthorizationAction: FailedAuthorizationAction<E>;

  readonly #parseAuthorizationEndpointBody: (
    context: Context<E & OAuth2ServerEnv>,
  ) => Promise<AuthReqBody>;

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
        await this.#parseAuthorizationEndpointBody(context),
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

  constructor(options: HonoAuthorizationCodeFlowOptions<AuthReqBody, E>) {
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

    this.#parseAuthorizationEndpointBody = options.parseAuthorizationEndpointBody;

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
  AuthReqBody extends AuthorizationCodeReqBody = AuthorizationCodeReqBody,
> extends OIDCAuthorizationCodeFlow<AuthReqBody> implements HonoAdapted<E> {
  readonly #verifyTokenHandler: (
    context: Context<E & OAuth2ServerEnv>,
  ) => Promise<StrategyResult>;
  readonly #authorizeMiddleware: MiddlewareHandler<E & OAuth2ServerEnv>;

  readonly #failedAuthorizationAction: FailedAuthorizationAction<E>;

  readonly #parseAuthorizationEndpointBody: (
    context: Context<E & OAuth2ServerEnv>,
  ) => Promise<AuthReqBody>;

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
        await this.#parseAuthorizationEndpointBody(context),
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

  constructor(options: HonoOIDCAuthorizationCodeFlowOptions<AuthReqBody, E>) {
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

    this.#parseAuthorizationEndpointBody = options.parseAuthorizationEndpointBody;

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
