// oauth2_hono_adapter/authorization_code.ts

import type { Context, Env, MiddlewareHandler } from "hono";
import { HTTPException } from "hono/http-exception";
import {
  AuthorizationCodeGrantFlow,
  AuthorizationCodeGrantFlowOptions,
  AuthorizationCodeInitiationResponse,
  AuthorizationCodeProcessResponse,
  AuthorizationCodeReqBody,
  evaluateStrategy,
  InvalidRequestError,
  OAuth2AuthFlowTokenResponse,
  StrategyInsufficientScopeError,
  StrategyResult,
  StrategyVerifyTokenFunction,
} from "@saurbit/oauth2-server";
import {
  FailedAuthorizationAction,
  HonoStrategyOptionsWithFailedAuth,
  OAuth2ServerEnv,
} from "./types.ts";
import { AuthorizationCodeEndpointResponse } from "@saurbit/oauth2-server";

export interface HonoAuthorizationCodeFlowOptions<
  AuthReqBody extends AuthorizationCodeReqBody = AuthorizationCodeReqBody,
  E extends Env = Env,
> extends Omit<AuthorizationCodeGrantFlowOptions<AuthReqBody>, "strategyOptions"> {
  strategyOptions: HonoStrategyOptionsWithFailedAuth<E>;
  parseAuthorizationEndpointBody: (context: Context<E & OAuth2ServerEnv>) => Promise<AuthReqBody>;
}

export class HonoAuthorizationCodeGrantFlow<
  E extends Env = Env,
  AuthReqBody extends AuthorizationCodeReqBody = AuthorizationCodeReqBody,
> extends AuthorizationCodeGrantFlow<AuthReqBody> {
  readonly #verifyTokenHandler: (
    context: Context<E & OAuth2ServerEnv>,
  ) => Promise<StrategyResult>;
  readonly #authorizeMiddleware: MiddlewareHandler<E & OAuth2ServerEnv>;

  readonly #failedAuthorizationAction: FailedAuthorizationAction<E>;

  readonly #parseAuthorizationEndpointBody: (
    context: Context<E & OAuth2ServerEnv>,
  ) => Promise<AuthReqBody>;

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
      const result = await this.verifyTokenFromHono(c);

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

  async verifyTokenFromHono(
    context: Context<E & OAuth2ServerEnv>,
  ): Promise<StrategyResult> {
    return await this.#verifyTokenHandler(context);
  }

  async tokenFromHono(context: Context): Promise<OAuth2AuthFlowTokenResponse> {
    return await this.token(context.req.raw);
  }

  authorizeMiddleware(scopes?: string[]): MiddlewareHandler<E & OAuth2ServerEnv> {
    return scopes?.length ? this.#createAuthorizeMiddleware(scopes) : this.#authorizeMiddleware;
  }

  /**
   * This method is a convenience method that combines the logic of initiating (GET) the authorization code flow for Hono.
   * It checks the HTTP method of the request and calls the appropriate method to handle the authorization endpoint logic.
   * @param context
   * @returns
   */
  async initiateAuthorizationFromHono(
    context: Context,
  ): Promise<AuthorizationCodeInitiationResponse> {
    return await this.initiateAuthorization(context.req.raw);
  }

  /**
   * This method is a convenience method that combines the logic of processing (POST) the authorization code flow for Hono.
   * It checks the HTTP method of the request and calls the appropriate method to handle the authorization endpoint logic.
   * @param context
   * @returns
   */
  async processAuthorizationFromHono(context: Context): Promise<AuthorizationCodeProcessResponse> {
    return await this.processAuthorization(
      context.req.raw.clone(),
      await this.#parseAuthorizationEndpointBody(context),
    );
  }

  /**
   * This method is a convenience method that handles the authorization endpoint logic for Hono.
   * It checks the HTTP method of the request and calls the appropriate method to handle the authorization endpoint logic.
   * @param context
   * @returns
   */
  async handleAuthorizationEndpointFromHono(
    context: Context,
  ): Promise<AuthorizationCodeEndpointResponse> {
    if (context.req.method === "GET") {
      // In a real implementation, you would render a login page
      // or consent page here for the user
      // to authenticate and authorize the client.
      const result = await this.initiateAuthorizationFromHono(context);

      if (!result.success) {
        return result;
      }

      return {
        ...result,
        method: "GET",
      };
    }

    if (context.req.method === "POST") {
      // In a real implementation, you would authenticate the user here,
      // and if authentication is successful, generate an authorization code,
      // and redirect the user to the redirect_uri with the code and state as query parameters.

      const result = await this.processAuthorizationFromHono(context);

      if (!result.success) {
        return result;
      }

      return {
        ...result,
        method: "POST",
      };
    }

    return { success: false, error: new InvalidRequestError("Unsupported HTTP method") };
  }
}
