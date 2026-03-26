/**
 * @module
 *
 * Core abstractions shared by all OAuth 2.0 grant type flow implementations.
 *
 * Defines the base {@link OAuth2Flow} class, shared option/model interfaces,
 * and the function signature types used by the pluggable model layer.
 */

import { InvalidRequestError, OAuth2Error } from "../errors.ts";
import { BearerTokenType } from "../token_types/bearer_token.ts";
import { TokenType } from "../token_types/types.ts";
import {
  ClientAuthMethod,
  ClientSecretBasic,
  ClientSecretPost,
  NoneAuthMethod,
  sortTokenEndpointAuthMethods,
  TokenEndpointAuthMethod,
} from "../client_auth_methods/mod.ts";
import { OAuth2Client, OAuth2TokenResponseBody } from "../types.ts";
import { evaluateStrategy, StrategyOptions, StrategyResult } from "../strategy.ts";

/**
 * The discriminated union returned by a flow's `token()` method.
 *
 * - On success: contains the token response body and the grant type that produced it.
 * - On failure: contains the OAuth2 error to return to the client.
 */
export type OAuth2FlowTokenResponse =
  | { success: true; tokenResponse: OAuth2TokenResponseBody; grantType: string }
  | { success: false; error: OAuth2Error };

/**
 * Strategy options passed to the token verification layer.
 * Mirrors {@link StrategyOptions} but omits `tokenType`, which is managed by the flow.
 */
export interface OAuth2FlowStrategyOptions extends Omit<StrategyOptions, "tokenType"> {}

/**
 * Base configuration options shared by all OAuth 2.0 flow implementations.
 */
export interface OAuth2FlowOptions {
  /**
   * Options forwarded to the token verification strategy (e.g. the `verifyToken` handler).
   */
  strategyOptions: OAuth2FlowStrategyOptions;

  /**
   * The OpenAPI security scheme name for this flow.
   * Used as the key in `toOpenAPISecurityScheme()` and `toOpenAPIPathItem()`.
   * @default "oauth2-flow"
   */
  securitySchemeName?: string;

  /**
   * The default lifetime in seconds for issued access tokens.
   * @default 3600
   */
  accessTokenLifetime?: number;

  /**
   * The URL of the token endpoint. Used in OpenAPI security scheme generation.
   * @default "/token"
   */
  tokenEndpoint?: string;

  /**
   * The token type implementation to use for this flow (e.g. Bearer, DPoP).
   * Defaults to {@link BearerTokenType}.
   */
  tokenType?: TokenType;

  /**
   * A human-readable description for the OpenAPI security scheme.
   */
  description?: string;

  /**
   * A map of scope names to their descriptions, used in OpenAPI security scheme generation.
   */
  scopes?: Record<string, string>;

  /**
   * The client authentication methods to register on this flow.
   * Accepts method identifier strings or custom {@link ClientAuthMethod} instances.
   * Defaults to `client_secret_basic` if none are provided.
   */
  clientAuthenticationMethods?: (
    | ClientAuthMethod
    | "client_secret_basic"
    | "client_secret_post"
    | "none"
  )[];
}

/**
 * The base shape of a successful access token result returned by `generateAccessToken()`.
 */
export interface OAuth2AccessTokenResult {
  type?: "access_token";
  accessToken: string;
}

/**
 * Returned by `generateAccessToken()` to signal a domain-level error
 * (e.g. `authorization_pending` in the device code flow) without throwing.
 *
 * The flow's `token()` method maps these to the appropriate OAuth 2.0 error responses.
 */
export interface OAuth2AccessTokenError {
  /** Discriminator. Always `"error"`. */
  type: "error";

  /** The OAuth 2.0 error code (e.g. `"authorization_pending"`, `"access_denied"`). */
  error: string;

  /** A human-readable description of the error. */
  errorDescription?: string;

  /** A URI pointing to a page with more information about the error. */
  errorUri?: string;
}

/**
 * Validation context passed to `generateAccessTokenFromRefreshToken()` when
 * handling a `refresh_token` grant request.
 */
export interface OAuth2RefreshTokenGrantContext {
  /** The grant type identifier. Always `"refresh_token"`. */
  grantType: "refresh_token";

  /** The authenticated client presenting the refresh token. */
  client: OAuth2Client;

  /** The token type prefix (e.g. `"Bearer"`, `"DPoP"`). */
  tokenType: string;

  /** The access token lifetime in seconds. */
  accessTokenLifetime: number;

  /** The refresh token string from the request. */
  refreshToken: string;

  /** The requested scopes for the new access token, if provided. */
  scope?: string[];
}

/**
 * Raw refresh token request parameters for refresh token grant.
 */
export interface OAuth2RefreshTokenRequest {
  /** The grant type value. Always `"refresh_token"`. */
  grantType: "refresh_token";

  /** The client identifier. */
  clientId: string;

  /** The refresh token string from the request. */
  refreshToken: string;

  /** The client secret, if the client is confidential. */
  clientSecret?: string;

  /** The requested scopes for the new access token, if provided. */
  scope?: string[];
}

/**
 * A function that retrieves a registered OAuth 2.0 client from the application's store.
 *
 * @template TRequestInfo - The shape of the token or authorization request object.
 *
 * @param requestInfo - The parsed request parameters.
 * @returns The matching client, or `undefined` if not found or authentication fails.
 */
export interface OAuth2GetClientFunction<TRequestInfo> {
  (requestInfo: TRequestInfo): Promise<OAuth2Client | undefined> | OAuth2Client | undefined;
}

/**
 * A function that generates an access token for an authenticated grant context.
 *
 * @template TGrantContext - The grant-specific context object (client, scopes, lifetime, etc.).
 * @template TAccessToken - The shape of the token result (string, result object, or error object).
 *
 * @param context - The validated grant context.
 * @returns The generated token, an error result, or `undefined` on failure.
 */
export interface OAuth2GenerateAccessTokenFunction<
  TGrantContext,
  TAccessToken extends OAuth2AccessTokenResult | OAuth2AccessTokenError | string,
> {
  (context: TGrantContext): Promise<TAccessToken | undefined> | TAccessToken | undefined;
}

/**
 * A function that generates a new access token from an existing refresh token.
 *
 * @template TAccessToken - The shape of the token result (string, result object, or error object).
 *
 * @param context - The refresh token grant context.
 * @returns The generated token, an error result, or `undefined` on failure.
 */
export interface OAuth2GenerateAccessTokenFromRefreshTokenFunction<
  TAccessToken extends OAuth2AccessTokenResult | OAuth2AccessTokenError | string,
> {
  (
    context: OAuth2RefreshTokenGrantContext,
  ): Promise<TAccessToken | undefined> | TAccessToken | undefined;
}

/**
 * The pluggable model interface that grant flow implementations delegate to
 * for client lookup and token generation.
 *
 * @template TTokenRequest - The shape of the token endpoint request parameters.
 * @template TGrantContext - The grant-specific context object passed to token generation.
 * @template TAccessToken - The shape of the token result. Defaults to `OAuth2AccessTokenResult | string`.
 */
export interface OAuth2GrantModel<
  TTokenRequest,
  TGrantContext,
  TAccessToken extends OAuth2AccessTokenResult | OAuth2AccessTokenError | string =
    | OAuth2AccessTokenResult
    | string,
> {
  /**
   * Retrieve a client by its id and optionally verify its secret.
   */
  getClient: OAuth2GetClientFunction<TTokenRequest>;
  /**
   * Generate an access token for the grant type.
   */
  generateAccessToken: OAuth2GenerateAccessTokenFunction<TGrantContext, TAccessToken>;

  /**
   * Generate a new access token from a refresh token.
   * Optional - only implement if the flow supports refresh token grants.
   */
  generateAccessTokenFromRefreshToken?: OAuth2GenerateAccessTokenFromRefreshTokenFunction<
    TAccessToken
  >;
}

/**
 * Abstract base class for all OAuth 2.0 grant type flow implementations.
 *
 * Manages client authentication method registration, token type configuration,
 * access token lifetime, and token verification. Subclasses implement `token()`
 * and `toOpenAPISecurityScheme()` for their specific grant type.
 */
export abstract class OAuth2Flow {
  /** The grant type identifier for this flow (e.g. `"client_credentials"`). */
  abstract readonly grantType: string;

  protected readonly strategyOptions: OAuth2FlowStrategyOptions;

  protected _clientAuthMethods: Record<TokenEndpointAuthMethod, ClientAuthMethod | undefined> = {
    client_secret_basic: undefined,
    client_secret_post: undefined,
    client_secret_jwt: undefined,
    private_key_jwt: undefined,
    none: undefined,
  };

  protected _tokenType: TokenType;

  /**
   * The token type prefix used in the `Authorization` header (e.g. `"Bearer"`, `"DPoP"`).
   * Derived from the configured {@link TokenType}.
   */
  get tokenType(): string {
    return this._tokenType.prefix;
  }

  protected get clientAuthMethods(): Record<TokenEndpointAuthMethod, ClientAuthMethod | undefined> {
    const result: Record<TokenEndpointAuthMethod, ClientAuthMethod | undefined> = {
      client_secret_basic: undefined,
      client_secret_post: undefined,
      client_secret_jwt: undefined,
      private_key_jwt: undefined,
      none: undefined,
    };

    const keys = Object.keys(this._clientAuthMethods)
      .map((key) => {
        const k = key as TokenEndpointAuthMethod;
        result[k] = this._clientAuthMethods[k];
        return this._clientAuthMethods[k] ? key : undefined;
      })
      .filter((key): key is TokenEndpointAuthMethod => !!key);

    if (!keys.length) {
      result.client_secret_basic = new ClientSecretBasic();
    }

    return result;
  }

  //
  protected securitySchemeName: string = "oauth2-flow";
  /** Default lifetime (in seconds) for access tokens. @default {3600} */
  protected accessTokenLifetime: number = 3600;
  protected tokenEndpoint: string = "/token";
  protected description?: string;
  protected scopes?: Record<string, string>;

  constructor(options?: OAuth2FlowOptions) {
    this._tokenType = options?.tokenType || new BearerTokenType();

    if (options?.clientAuthenticationMethods) {
      for (const clientAuthMethod of options.clientAuthenticationMethods) {
        this.addClientAuthenticationMethod(clientAuthMethod);
      }
    }
    if (options?.description) {
      this.description = options.description;
    }
    if (options?.scopes) {
      this.scopes = { ...options.scopes };
    }

    if (options?.securitySchemeName) {
      this.securitySchemeName = options?.securitySchemeName;
    }
    if (options?.tokenEndpoint) {
      this.tokenEndpoint = options?.tokenEndpoint;
    }
    if (options?.strategyOptions) {
      this.strategyOptions = options.strategyOptions;
    } else {
      this.strategyOptions = {};
    }
    if (options?.accessTokenLifetime) {
      this.accessTokenLifetime = options.accessTokenLifetime;
    }
  }

  protected async extractClientCredentials(
    req: Request,
    authMethodsInstances: Record<TokenEndpointAuthMethod, ClientAuthMethod | undefined>,
    supported: TokenEndpointAuthMethod[],
  ): Promise<{
    clientId?: string;
    clientSecret?: string;
    error?: OAuth2Error;
    method?: TokenEndpointAuthMethod;
  }> {
    let clientId: string | undefined;
    let clientSecret: string | undefined;
    let error: OAuth2Error | undefined;
    let method: TokenEndpointAuthMethod | undefined;

    for (const am of supported) {
      const amInstance = authMethodsInstances[am];
      if (amInstance) {
        const v = await amInstance.extractClientCredentials(req.clone());
        if (v.hasAuthMethod) {
          method = amInstance.method;
          clientId = v.clientId;
          clientSecret = v.clientSecret;
          if (!v.clientId) {
            error = new InvalidRequestError(
              `${amInstance.method} authentication requires client_id`,
            );
          } else if (!amInstance.secretIsOptional && !v.clientSecret) {
            error = new InvalidRequestError(
              `${amInstance.method} authentication requires client_secret`,
            );
          }
          break;
        }
      }
    }

    return {
      error,
      clientId,
      clientSecret,
      method,
    };
  }

  protected addClientAuthenticationMethod(
    value: "client_secret_basic" | "client_secret_post" | "none" | ClientAuthMethod,
  ): this {
    if (value == "client_secret_basic") {
      this._clientAuthMethods.client_secret_basic = new ClientSecretBasic();
    } else if (value == "client_secret_post") {
      this._clientAuthMethods.client_secret_post = new ClientSecretPost();
    } else if (value == "none") {
      this._clientAuthMethods.none = new NoneAuthMethod();
    } else {
      this._clientAuthMethods[value.method] = value;
    }
    return this;
  }

  /**
   * Returns the list of active client authentication method identifiers for this flow,
   * sorted in the standard preference order.
   * Defaults to `["client_secret_basic"]` if no methods have been registered.
   */
  getTokenEndpointAuthMethods(): TokenEndpointAuthMethod[] {
    const result = Object.keys(this._clientAuthMethods)
      .map((key) => {
        return this._clientAuthMethods[key as TokenEndpointAuthMethod] ? key : undefined;
      })
      .filter((key): key is TokenEndpointAuthMethod => !!key);

    if (!result.length) {
      result.push("client_secret_basic");
    }

    return sortTokenEndpointAuthMethods(result);
  }

  /**
   * Sets the default access token lifetime for this flow.
   *
   * @param ttlSeconds - Lifetime in seconds of the access token. Defaults to 1 hour.
   */
  setAccessTokenLifetime(ttlSeconds: number = 3600): this {
    this.accessTokenLifetime = ttlSeconds;
    return this;
  }

  /**
   * Returns the configured access token lifetime in seconds.
   */
  getAccessTokenLifetime(): number | undefined {
    return this.accessTokenLifetime;
  }

  /**
   * Sets the human-readable description for the OpenAPI security scheme.
   *
   * @param description - A short description of this flow.
   */
  setDescription(description: string): this {
    this.description = description;
    return this;
  }

  /**
   * Sets the scopes advertised by this flow in the OpenAPI security scheme.
   *
   * @param scopes - A map between scope names and short descriptions.
   *   The map MAY be empty.
   */
  setScopes(scopes: Record<string, string>): this {
    this.scopes = scopes;
    return this;
  }

  /**
   * Sets the token endpoint URL used in OpenAPI security scheme generation.
   *
   * @param tokenEndpoint - The token endpoint URL (absolute or relative).
   */
  setTokenEndpoint(tokenEndpoint: string): this {
    this.tokenEndpoint = tokenEndpoint;
    return this;
  }

  /**
   * Returns the configured token endpoint URL.
   */
  getTokenEndpoint(): string {
    return this.tokenEndpoint;
  }

  /**
   * Returns the configured scopes map, or `undefined` if none have been set.
   */
  getScopes(): Record<string, string> | undefined {
    return this.scopes;
  }

  /**
   * Returns the OpenAPI security scheme name for this flow.
   */
  getSecuritySchemeName(): string {
    return this.securitySchemeName;
  }

  /**
   * Returns the human-readable description for the OpenAPI security scheme, if set.
   */
  getDescription(): string | undefined {
    return this.description;
  }

  /**
   * Verifies that the token in the request grants access to a protected resource.
   * Delegates to the configured `verifyToken` strategy handler.
   *
   * @param request - The incoming HTTP request containing the `Authorization` header.
   * @returns The strategy result - success with credentials, or a typed failure.
   */
  async verifyToken(request: Request): Promise<StrategyResult> {
    return await evaluateStrategy(request, {
      ...this.strategyOptions,
      tokenType: this._tokenType,
    });
  }

  /**
   * Returns the OpenAPI path item security requirement object for this flow.
   *
   * @param scopes - Optional list of required scopes for the path item.
   * @returns An object keyed by the security scheme name with the required scopes.
   */
  toOpenAPIPathItem(scopes?: string[]): Record<string, string[]> {
    return {
      [this.getSecuritySchemeName()]: scopes || [],
    };
  }

  /**
   * Handle a token request for the specific grant type.
   *
   * @param request - The incoming HTTP request to the token endpoint.
   * @returns The token response - success with the token body, or failure with an error.
   */
  abstract token(request: Request): Promise<OAuth2FlowTokenResponse>;

  /**
   * Returns the OpenAPI security scheme definition for this flow.
   * The returned object is keyed by the security scheme name.
   */
  abstract toOpenAPISecurityScheme(): Record<string, unknown>;
}
