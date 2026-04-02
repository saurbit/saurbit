// @saurbit/hono-oauth2/device_authorization.ts

import type { Context, Env, MiddlewareHandler } from "hono";
import { HTTPException } from "hono/http-exception";
import {
  type DeviceAuthorizationEndpointResponse,
  DeviceAuthorizationFlow,
  DeviceAuthorizationFlowBuilder,
  type DeviceAuthorizationFlowOptions,
  type DeviceAuthorizationProcessResponse,
  evaluateStrategy,
  InvalidRequestError,
  type OAuth2FlowTokenResponse,
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
 * Configuration options for {@link HonoDeviceAuthorizationFlow}.
 *
 * Extends the base `DeviceAuthorizationFlowOptions` with Hono-specific strategy options
 * for token verification and failed-authorization handling.
 *
 * @template E - The Hono `Env` type for the application.
 */
export interface HonoDeviceAuthorizationFlowOptions<
  E extends Env = Env,
> extends Omit<DeviceAuthorizationFlowOptions, "strategyOptions"> {
  /** Hono-specific strategy options, including token verification and failed authorization handling. */
  strategyOptions: HonoOAuth2StrategyOptions<E>;
}

/**
 * Builder options for {@link HonoDeviceAuthorizationFlowBuilder}.
 *
 * All fields from {@link HonoDeviceAuthorizationFlowOptions} are optional.
 *
 * @template E - The Hono `Env` type for the application.
 */
export interface HonoDeviceAuthorizationFlowBuilderOptions<
  E extends Env = Env,
> extends Partial<HonoDeviceAuthorizationFlowOptions<E>> {
}

/**
 * Hono-adapted methods for the Device Authorization flow.
 *
 * Extends the base {@link HonoMethods} with device-specific endpoint helpers that
 * accept a Hono `Context` instead of a raw `Request`.
 * Obtained via {@link HonoDeviceAuthorizationFlow.hono}.
 *
 * @template E - The Hono `Env` type for the application.
 */
export interface HonoDeviceAuthorizationMethods<E extends Env = Env> extends HonoMethods<E> {
  /**
   * This method is a convenience method that combines the logic of processing (POST) the device authorization flow for Hono.
   * It checks the HTTP method of the request and calls the appropriate method to handle the authorization endpoint logic.
   * @param context
   * @returns
   */
  processAuthorization(
    context: Context,
  ): Promise<DeviceAuthorizationProcessResponse>;

  /**
   * This method is a convenience method that handles the authorization endpoint logic for Hono.
   * It checks the HTTP method of the request and calls the appropriate method to handle the authorization endpoint logic.
   * @param context
   * @returns
   */
  handleAuthorizationEndpoint(
    context: Context,
  ): Promise<DeviceAuthorizationEndpointResponse>;
}

//#endregion

//#region Classes

/**
 * Hono adapter for the OAuth 2.0 Device Authorization flow.
 *
 * Wraps {@link DeviceAuthorizationFlow} to integrate natively with Hono's `Context`,
 * providing a token endpoint handler, middleware for protecting routes, and
 * convenience methods for the device authorization endpoint.
 * This flow is intended for input-constrained devices (e.g. smart TVs, CLIs)
 * that cannot easily handle a browser-based redirect.
 *
 * Use {@link HonoDeviceAuthorizationFlowBuilder} for a fluent configuration API.
 *
 * @template E - The Hono `Env` type for the application.
 */
export class HonoDeviceAuthorizationFlow<
  E extends Env = Env,
> extends DeviceAuthorizationFlow implements HonoAdapted<E> {
  readonly #tokenVerifier: (
    context: Context<E & OAuth2ServerEnv>,
  ) => Promise<StrategyResult>;
  readonly #authorizeMiddleware: MiddlewareHandler<E & OAuth2ServerEnv>;

  readonly #failedAuthorizationAction: FailedAuthorizationAction<E>;

  readonly #hono: HonoDeviceAuthorizationMethods<E> = {
    authorizeMiddleware: (scopes?: string[]): MiddlewareHandler<E & OAuth2ServerEnv> => {
      return scopes?.length ? this.#createAuthorizeMiddleware(scopes) : this.#authorizeMiddleware;
    },
    token: async (context: Context): Promise<OAuth2FlowTokenResponse> => {
      return await this.token(context.req.raw);
    },

    verifyToken: async (context: Context<E & OAuth2ServerEnv>): Promise<StrategyResult> => {
      return await this.#tokenVerifier(context);
    },

    processAuthorization: async (
      context: Context,
    ): Promise<DeviceAuthorizationProcessResponse> => {
      return await this.processAuthorization(
        context.req.raw.clone(),
      );
    },

    handleAuthorizationEndpoint: async (
      context: Context,
    ): Promise<DeviceAuthorizationEndpointResponse> => {
      if (context.req.method === "POST") {
        // In a real implementation, you would authenticate the user here,
        // and if authentication is successful, generate a device code,
        // and return it to the client in the response.

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
      };
    },
  };

  constructor(options: HonoDeviceAuthorizationFlowOptions<E>) {
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
   * @returns A readonly {@link HonoDeviceAuthorizationMethods} instance.
   */
  hono(): Readonly<HonoDeviceAuthorizationMethods<E>> {
    return Object.freeze(this.#hono);
  }
}

//#endregion

//#region Builders

/**
 * Fluent builder for {@link HonoDeviceAuthorizationFlow}.
 *
 * Provides a chainable API to configure all aspects of the Device Authorization flow
 * for Hono, including device code generation, token polling, token verification,
 * and scope enforcement.
 *
 * @template E - The Hono `Env` type for the application.
 *
 * @example
 * ```ts
 * const flow = HonoDeviceAuthorizationFlowBuilder
 *   .create()
 *   .setTokenEndpoint("/token")
 *   .tokenVerifier((c, { token }) => verifyJwt(token))
 *   .build();
 * ```
 */
export class HonoDeviceAuthorizationFlowBuilder<
  E extends Env = Env,
> extends DeviceAuthorizationFlowBuilder {
  protected strategyOptions: HonoOAuth2StrategyOptions<E> = {};

  constructor(options?: HonoDeviceAuthorizationFlowBuilderOptions<E>) {
    const { strategyOptions, ...flowOptions } = options || {};
    super({
      ...flowOptions,
      strategyOptions: {},
    });
    this.strategyOptions = strategyOptions || {};
  }

  /**
   * Creates a new `HonoDeviceAuthorizationFlowBuilder` instance.
   *
   * @param options - Optional initial builder options.
   * @returns A new builder instance.
   */
  static create<
    E extends Env = Env,
  >(
    options?: HonoDeviceAuthorizationFlowBuilderOptions<E>,
  ): HonoDeviceAuthorizationFlowBuilder<E> {
    return new HonoDeviceAuthorizationFlowBuilder<E>(options);
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
   * Builds and returns a configured {@link HonoDeviceAuthorizationFlow} instance.
   *
   * @returns A new `HonoDeviceAuthorizationFlow`.
   */
  override build(): HonoDeviceAuthorizationFlow<E> {
    const params: HonoDeviceAuthorizationFlowOptions<E> = {
      ...this.buildParams(),
      strategyOptions: this.strategyOptions,
    };
    return new HonoDeviceAuthorizationFlow<E>(params);
  }
}

//#endregion
