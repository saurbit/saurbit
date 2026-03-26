/**
 * @module
 *
 * Implements the OAuth 2.0 Device Authorization Grant (RFC 8628), allowing
 * input-constrained devices (e.g. smart TVs, CLI tools) to obtain access tokens
 * by having the user complete authorization on a secondary device.
 *
 * @see https://datatracker.ietf.org/doc/html/rfc8628
 */

import {
  AccessDeniedError,
  AuthorizationPendingError,
  ExpiredTokenError,
  InvalidClientError,
  InvalidRequestError,
  OAuth2Error,
  ServerError,
  SlowDownError,
  UnauthorizedClientError,
  UnsupportedGrantTypeError,
} from "../errors.ts";
import { TokenTypeValidationResponse } from "../token_types/types.ts";
import { OAuth2Client, OAuth2TokenResponseBody } from "../types.ts";
import {
  OAuth2AccessTokenError,
  OAuth2AccessTokenResult,
  OAuth2Flow,
  OAuth2FlowOptions,
  OAuth2FlowTokenResponse,
  OAuth2GenerateAccessTokenFromRefreshTokenFunction,
  OAuth2GetClientFunction,
  OAuth2GrantModel,
  OAuth2RefreshTokenGrantContext,
  OAuth2RefreshTokenRequest,
} from "./flow.ts";

/**
 * Marker interface for the Device Authorization grant type.
 *
 * @see https://datatracker.ietf.org/doc/html/rfc8628
 */
export interface DeviceAuthorizationGrant {
  /** The grant type identifier. */
  readonly grantType: "urn:ietf:params:oauth:grant-type:device_code";
}

/**
 * Validation context for the device authorization grant,
 * passed to the model's `generateAccessToken()` method to produce
 * a token with appropriate lifetime, type, etc.
 */
export interface DeviceAuthorizationGrantContext {
  /** The authenticated client polling the token endpoint. */
  client: OAuth2Client;

  /** The grant type identifier. Always `"urn:ietf:params:oauth:grant-type:device_code"`. */
  grantType: "urn:ietf:params:oauth:grant-type:device_code";

  /** The token type prefix (e.g. `"Bearer"`, `"DPoP"`). */
  tokenType: string;

  /** The access token lifetime in seconds. */
  accessTokenLifetime: number;

  /** The device code being polled. */
  deviceCode: string;
}

/**
 * Raw token request parameters for the device code grant.
 */
export interface DeviceAuthorizationTokenRequest {
  /** The client identifier. */
  clientId: string;

  /** The grant type value. Always `"urn:ietf:params:oauth:grant-type:device_code"`. */
  grantType: "urn:ietf:params:oauth:grant-type:device_code";

  /** The device code previously issued by the device authorization endpoint. */
  deviceCode: string;

  /** The client secret, if the client is confidential. */
  clientSecret?: string;
}

/**
 * Validation context for the device authorization endpoint,
 * passed to the model's `generateDeviceCode()` method.
 */
export interface DeviceAuthorizationEndpointContext {
  /** The client requesting device authorization. */
  client: OAuth2Client;

  /** The validated scopes requested by the client. */
  scope: string[];
}

/**
 * Raw authentication request parameters for the device authorization endpoint.
 */
export interface DeviceAuthorizationEndpointRequest {
  /** The client identifier. */
  clientId: string;

  /** The client secret, if the client is confidential. */
  clientSecret?: string;

  /** The requested scopes, if provided. */
  scope?: string[];
}

/**
 * The successful response from `processAuthorization()`, containing the
 * device code, user code, and verification endpoints to return to the device.
 *
 * @template C - The device authorization endpoint context type.
 *
 * @see https://datatracker.ietf.org/doc/html/rfc8628#section-3.2
 */
export interface DeviceAuthorizationEndpointCodeResponse<
  C extends DeviceAuthorizationEndpointContext = DeviceAuthorizationEndpointContext,
> {
  /** The authorization endpoint context associated with this device code. */
  context: C;

  /** The device verification code. Opaque to the end-user. */
  deviceCode: string;

  /** The end-user verification code to be displayed to and entered by the user. */
  userCode: string;

  /** The verification URI the user should visit to enter the user code (`verification_uri`). */
  verificationEndpoint: string;

  /** The verification URI with the user code pre-filled (`verification_uri_complete`). */
  verificationEndpointComplete: string;

  /** Discriminator ensuring this is not an error response. */
  error?: never;

  /** Additional application-specific fields. */
  [key: string]: unknown;
}

/**
 * The union of all possible outcomes from `handleAuthorizationEndpoint()`.
 *
 * - `POST / device_code`: Device and user codes were successfully generated.
 * - `error`: A protocol error occurred.
 *
 * @template C - The device authorization endpoint context type.
 */
export type DeviceAuthorizationEndpointResponse<
  C extends DeviceAuthorizationEndpointContext = DeviceAuthorizationEndpointContext,
> =
  | {
    method: "POST";
    type: "device_code";
    deviceCodeResponse: DeviceAuthorizationEndpointCodeResponse<C>;
  }
  | {
    type: "error";
    error: OAuth2Error;
    client?: OAuth2Client;
  };

/**
 * The result of `processAuthorization()`.
 *
 * - `device_code`: Device and user codes were successfully generated.
 * - `error`: A protocol error occurred.
 *
 * @template C - The device authorization endpoint context type.
 */
export type DeviceAuthorizationProcessResponse<
  C extends DeviceAuthorizationEndpointContext = DeviceAuthorizationEndpointContext,
> =
  | {
    type: "device_code";
    deviceCodeResponse: DeviceAuthorizationEndpointCodeResponse<C>;
  }
  | {
    type: "error";
    error: OAuth2Error;
    client?: OAuth2Client;
  };

/**
 * The access token result shape for the device authorization grant.
 * Extends the base result with optional refresh token, scope, and ID token fields.
 */
export interface DeviceAuthorizationAccessTokenResult extends OAuth2AccessTokenResult {
  /**
   * The scopes granted with this token. Returned to the client in the token response.
   */
  scope?: string[];

  /** A refresh token to include in the token response, if applicable. */
  refreshToken?: string;

  /**
   * For OpenID Connect, an ID token can also be returned from the token endpoint when
   * exchanging the device code for tokens, and it should be included in the access token
   * result so that it can be returned to the client in the token response.
   *
   * @see https://openid.net/specs/openid-connect-core-1_0.html#TokenEndpoint
   */
  idToken?: string;
}

/**
 * An error result returned by `generateAccessToken()` during device code polling,
 * representing one of the RFC 8628-defined polling error states.
 *
 * Return this instead of throwing to signal transient conditions (e.g. pending, slow down)
 * that the device should handle by adjusting its polling behaviour.
 *
 * @see https://datatracker.ietf.org/doc/html/rfc8628#section-3.5
 */
export interface DeviceAuthorizationAccessTokenError extends OAuth2AccessTokenError {
  /**
   * The RFC 8628 error code describing why the token cannot be issued yet.
   *
   * - `authorization_pending`: The user has not yet completed authorization.
   * - `slow_down`: The device is polling too frequently; increase the interval.
   * - `expired_token`: The device code has expired; restart the flow.
   * - `access_denied`: The user denied the authorization request.
   * - `invalid_request`: The request is malformed.
   */
  error:
    | "authorization_pending"
    | "slow_down"
    | "expired_token"
    | "access_denied"
    | "invalid_request";
}

/**
 * A function that generates a device code and user code for a device authorization request.
 *
 * Should persist the codes along with the associated context (client, scope, etc.) for
 * later lookup when the device polls the token endpoint or the user visits the verification URI.
 *
 * @template TContext - The device authorization endpoint context type.
 *
 * @param context - The validated device authorization endpoint context.
 * @returns An object with `deviceCode` and `userCode`, or `undefined` on failure.
 *
 * @see https://datatracker.ietf.org/doc/html/rfc8628#section-3.2
 */
export interface GenerateDeviceCodeFunction<
  TContext extends DeviceAuthorizationEndpointContext = DeviceAuthorizationEndpointContext,
> {
  (
    context: TContext,
  ):
    | Promise<
      {
        deviceCode: string;
        userCode: string;
      } | undefined
    >
    | {
      deviceCode: string;
      userCode: string;
    }
    | undefined;
}

/**
 * The result of `getDeviceAuthorizationEndpointContext()` - the first step of
 * the device authorization endpoint pipeline.
 *
 * @template C - The device authorization endpoint context type.
 */
export type DeviceAuthorizationInitiationResponse<
  C extends DeviceAuthorizationEndpointContext = DeviceAuthorizationEndpointContext,
> =
  | { success: true; context: C }
  | { success: false; error: OAuth2Error };

/**
 * Model interface that must be implemented by the consuming application
 * to provide persistence for clients and tokens related to the device authorization grant.
 */
export interface DeviceAuthorizationModel extends
  OAuth2GrantModel<
    DeviceAuthorizationTokenRequest | OAuth2RefreshTokenRequest,
    DeviceAuthorizationGrantContext,
    DeviceAuthorizationAccessTokenResult | DeviceAuthorizationAccessTokenError
  > {
  /**
   * Retrieve and validate the client for a device authorization or refresh token request.
   *
   * When `tokenRequest.grantType === "urn:ietf:params:oauth:grant-type:device_code"`, implementations MUST:
   * 1. Verify the `deviceCode` is valid and has not already been used (one-time use).
   * 2. Verify the `clientId` matches the client that requested the device code.
   * 3. Optionally, verify the `clientSecret` if the client is confidential.
   */
  getClient: OAuth2GetClientFunction<DeviceAuthorizationTokenRequest | OAuth2RefreshTokenRequest>;

  /**
   * Retrieve and validate the client for a device authorization endpoint request.
   * Should verify the `clientId` is registered and permitted to use this grant type.
   */
  getClientForAuthentication: OAuth2GetClientFunction<DeviceAuthorizationEndpointRequest>;

  /**
   * Looks up the device code associated with a given user code, as entered by the
   * end-user at the verification URI.
   *
   * @param userCode - The user code entered by the end-user.
   * @returns The associated `deviceCode` and `client`, or `undefined` if the user code is invalid.
   */
  verifyUserCode: (userCode: string) =>
    | Promise<
      | { deviceCode: string; client: OAuth2Client }
      | undefined
    >
    | { deviceCode: string; client: OAuth2Client }
    | undefined;

  /**
   * Generates a device code and user code for the given device authorization context.
   * Should persist both codes for later lookup.
   * See {@link GenerateDeviceCodeFunction} for the full contract.
   */
  generateDeviceCode: GenerateDeviceCodeFunction<DeviceAuthorizationEndpointContext>;

  /**
   * Generates a new access token from a refresh token.
   * Optional - only implement if the flow supports refresh token grants.
   */
  generateAccessTokenFromRefreshToken?: OAuth2GenerateAccessTokenFromRefreshTokenFunction<
    DeviceAuthorizationAccessTokenResult
  >;
}

/**
 * Options for configuring the device authorization grant flow.
 */
export interface DeviceAuthorizationFlowOptions extends OAuth2FlowOptions {
  /** The model implementation providing client lookup, code generation, and token generation. */
  model: DeviceAuthorizationModel;

  /** The URL of the device authorization endpoint. Defaults to `"/device_authorization"`. */
  authorizationEndpoint?: string;

  /** The URL of the user code verification endpoint. Defaults to `"/verify_user_code"`. */
  verificationEndpoint?: string;
}

/**
 * Abstract base class for the Device Authorization flow.
 *
 * Provides the full request handling pipeline for the device authorization endpoint
 * (`processAuthorization`, `handleAuthorizationEndpoint`) and the token endpoint
 * (`initiateToken`, `token`), as well as a `verifyUserCode()` helper for the
 * verification endpoint.
 *
 * Subclasses must implement `toOpenAPISecurityScheme()`.
 *
 * @see https://datatracker.ietf.org/doc/html/rfc8628
 */
export abstract class AbstractDeviceAuthorizationFlow extends OAuth2Flow
  implements DeviceAuthorizationGrant {
  readonly grantType = "urn:ietf:params:oauth:grant-type:device_code" as const;
  protected readonly model: DeviceAuthorizationModel;

  protected authorizationEndpoint: string = "/device_authorization";
  protected verificationEndpoint: string = "/verify_user_code";

  constructor(options: DeviceAuthorizationFlowOptions) {
    const { model, authorizationEndpoint, verificationEndpoint, ...flowOptions } = { ...options };
    super(flowOptions);
    this.model = model;
    if (authorizationEndpoint) {
      this.authorizationEndpoint = authorizationEndpoint;
    }
    if (verificationEndpoint) {
      this.verificationEndpoint = verificationEndpoint;
    }
  }

  /**
   * Sets the URL of the device authorization endpoint.
   *
   * @param url - The device authorization endpoint URL (absolute or relative).
   */
  setAuthorizationEndpoint(url: string): this {
    this.authorizationEndpoint = url;
    return this;
  }

  /**
   * Returns the URL of the device authorization endpoint.
   */
  getAuthorizationEndpoint(): string {
    return this.authorizationEndpoint;
  }

  /**
   * Sets the URL of the user code verification endpoint.
   *
   * @param url - The verification endpoint URL (absolute or relative).
   */
  setVerificationEndpoint(url: string): this {
    this.verificationEndpoint = url;
    return this;
  }

  /**
   * Returns the URL of the user code verification endpoint.
   */
  getVerificationEndpoint(): string {
    return this.verificationEndpoint;
  }

  protected async getDeviceAuthorizationEndpointContext(
    request: Request,
  ): Promise<DeviceAuthorizationInitiationResponse> {
    const req = request.clone();

    // Validate client authentication credentials using the registered client authentication methods
    const { clientId, clientSecret } = await this
      .extractClientCredentials(
        request.clone(),
        this.clientAuthMethods,
        this.getTokenEndpointAuthMethods(),
      );

    if (!clientId) {
      return {
        success: false,
        error: new InvalidRequestError("Missing client_id parameter"),
      };
    }

    let body: unknown;
    const contentType = req.headers.get("content-type") || "";
    if (contentType.includes("application/x-www-form-urlencoded")) {
      const form = await req.formData();
      body = {
        scope: form.get("scope"),
      };
    } else if (contentType.includes("application/json")) {
      body = req.json ? await req.json() : null;
    } else {
      body = null;
    }

    let scope: string | undefined;

    if (body && typeof body === "object") {
      if ("scope" in body && typeof body.scope === "string") {
        scope = body.scope;
      }
    }

    const client = await this.model.getClientForAuthentication({
      clientId,
      clientSecret,
      scope: scope ? scope.split(" ") : undefined,
    });

    if (!client) {
      return {
        success: false,
        error: new InvalidRequestError(
          "Invalid client_id or scope",
        ),
      };
    }

    // Validate scope if provided in the request body (optional)
    let validatedScopes: string[];
    if (client.scopes) {
      const allowedScopes = client.scopes ? client.scopes : [];
      validatedScopes = scope?.split(" ")?.filter((scope) => allowedScopes.includes(scope)) ||
        [];
    } else {
      validatedScopes = [];
    }

    return {
      success: true,
      context: {
        client,
        scope: validatedScopes,
      },
    };
  }

  /**
   * Processes a `POST` request to the device authorization endpoint.
   *
   * Validates the client, resolves scopes, and calls `model.generateDeviceCode()`.
   * Returns the device code, user code, and verification endpoints on success.
   *
   * @param request - The incoming `POST` request to the device authorization endpoint.
   * @returns The process response - device codes on success, or an error.
   */
  async processAuthorization(
    request: Request,
  ): Promise<DeviceAuthorizationProcessResponse> {
    const context = await this.getDeviceAuthorizationEndpointContext(request);

    if (!context.success) {
      return {
        type: "error",
        error: context.error,
      };
    }

    const {
      client,
      scope,
    } = context.context;

    const codeResult = await this.model.generateDeviceCode(
      {
        ...context.context,
        scope: [...scope],
      },
    );

    if (!codeResult) {
      return {
        type: "error",
        error: new ServerError("Failed to generate device code"),
        client,
      };
    }

    return {
      type: "device_code",
      deviceCodeResponse: {
        context: context.context,
        scope: [...scope],
        deviceCode: codeResult.deviceCode,
        userCode: codeResult.userCode, // In a real implementation, you would generate a separate user code that is easier for the user to input, and associate it with the device code in your data store.
        verificationEndpoint: this.verificationEndpoint,
        verificationEndpointComplete: `${this.verificationEndpoint}?user_code=${
          encodeURIComponent(codeResult.userCode)
        }}`,
      },
    };
  }

  /**
   * Unified handler for `POST` requests to the device authorization endpoint.
   *
   * Delegates to `processAuthorization()` and wraps the result with the HTTP method.
   * Returns an error response for any method other than `POST`.
   *
   * @param request - The incoming HTTP request to the device authorization endpoint.
   * @returns The endpoint response - a discriminated union of all possible outcomes.
   */
  async handleAuthorizationEndpoint(
    request: Request,
  ): Promise<DeviceAuthorizationEndpointResponse> {
    if (request.method === "POST") {
      const result = await this.processAuthorization(request);

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
  }

  /**
   * Verifies a user code at the verification endpoint.
   *
   * Accepts either the raw user code string or an HTTP request with a `user_code`
   * query parameter. Delegates to `model.verifyUserCode()`.
   *
   * @param userCode - The user code string entered by the end-user.
   * @returns The associated device code and client on success, or a failure with an error.
   */
  async verifyUserCode(userCode: string): Promise<
    | { success: true; deviceCode: string; client: OAuth2Client }
    | { success: false; error: OAuth2Error }
  >;

  /**
   * Verifies a user code submitted via an HTTP request to the verification endpoint.
   *
   * Extracts the `user_code` from the request's query string and delegates to
   * `model.verifyUserCode()`.
   *
   * @param request - The incoming HTTP request with a `user_code` query parameter.
   * @returns The associated device code and client on success, or a failure with an error.
   */
  async verifyUserCode(request: Request): Promise<
    | { success: true; deviceCode: string; client: OAuth2Client }
    | { success: false; error: OAuth2Error }
  >;

  async verifyUserCode(request: Request | string): Promise<
    | { success: true; deviceCode: string; client: OAuth2Client }
    | { success: false; error: OAuth2Error }
  > {
    let userCode: string | null = null;
    if (typeof request === "string") {
      userCode = request;
    } else {
      const query = new URL(request.url).searchParams;
      userCode = query.get("user_code");
    }

    if (!userCode) {
      return {
        success: false,
        error: new InvalidRequestError("Missing user_code parameter"),
      };
    }

    const verificationResult = await this.model.verifyUserCode(userCode);

    if (!verificationResult) {
      return {
        success: false,
        error: new InvalidRequestError("Invalid user code"),
      };
    }

    return {
      success: true,
      deviceCode: verificationResult.deviceCode,
      client: verificationResult.client,
    };
  }

  /**
   * Validates the token endpoint request (both device code and refresh token grant types)
   * and returns the resolved grant context without yet generating tokens.
   *
   * Useful when you need to inspect the context before deciding how to generate tokens.
   * Most callers should use `token()` directly instead.
   *
   * @param request - The incoming token endpoint HTTP request.
   * @returns The grant context on success, or a failure with an error.
   */
  async initiateToken(request: Request): Promise<
    | {
      success: true;
      context: DeviceAuthorizationGrantContext | OAuth2RefreshTokenGrantContext;
    }
    | { success: false; error: OAuth2Error }
  > {
    const req = request.clone();
    if (req.method !== "POST") {
      return {
        success: false,
        error: new InvalidRequestError("Method Not Allowed"),
      };
    }

    let body: unknown;
    let grantTypeInBody: string | undefined;
    let deviceCodeInBody: string | undefined;

    let refreshTokenInBody: string | undefined;
    let scopeInBody: string[] | undefined;
    const contentType = req.headers.get("content-type") || "";

    if (contentType.includes("application/x-www-form-urlencoded")) {
      const form = await req.formData();
      body = {
        grant_type: form.get("grant_type"),
        device_code: form.get("device_code"),
        // for refresh token
        refresh_token: form.get("refresh_token"),
        scope: form.get("scope"),
      };
    } else if (contentType.includes("application/json")) {
      body = req.json ? await req.json() : null;
    } else {
      return {
        success: false,
        error: new InvalidRequestError("Unsupported Media Type"),
      };
    }

    if (body && typeof body === "object") {
      if ("grant_type" in body) {
        grantTypeInBody = typeof body.grant_type === "string" ? body.grant_type : undefined;
      }
      if ("device_code" in body) {
        deviceCodeInBody = typeof body.device_code === "string" ? body.device_code : undefined;
      }
      if ("refresh_token" in body) {
        refreshTokenInBody = typeof body.refresh_token === "string"
          ? body.refresh_token
          : undefined;
      }
      if ("scope" in body) {
        scopeInBody = typeof body.scope === "string" ? body.scope.split(" ") : undefined;
      }
    }

    // Validate that the grant type in the request body matches this grant type
    if (grantTypeInBody === "refresh_token" && this.model.generateAccessTokenFromRefreshToken) {
      if (!refreshTokenInBody) {
        return {
          success: false,
          error: new InvalidRequestError("Missing refresh token"),
        };
      }
    } else if (grantTypeInBody === this.grantType) {
      if (!deviceCodeInBody) {
        return {
          success: false,
          error: new InvalidRequestError("Missing device code"),
        };
      }
    } else {
      return {
        success: false,
        error: new UnsupportedGrantTypeError("Unsupported grant type"),
      };
    }

    // Validate client authentication credentials using the registered client authentication methods
    const { clientId, clientSecret, error } = await this
      .extractClientCredentials(
        request.clone(),
        this.clientAuthMethods,
        this.getTokenEndpointAuthMethods(),
      );

    // If the request contains client authentication credentials, validate them
    if (!error) {
      // If clientId is missing, return 401 error
      if (!clientId) {
        return {
          success: false,
          error: new InvalidClientError("Invalid client credentials"),
        };
      }

      // e.g. for DPoP token type, we need to validate the token request before validating client credentials
      const tokenTypeValidationResponse: TokenTypeValidationResponse = this
          ._tokenType.isValidTokenRequest
        ? await this._tokenType.isValidTokenRequest(request.clone())
        : { isValid: true };
      if (!tokenTypeValidationResponse.isValid) {
        return {
          success: false,
          error: new InvalidRequestError(
            tokenTypeValidationResponse.message || "Invalid token request",
          ),
        };
      }

      // Validate client credentials using the model's getClient() method
      let client: OAuth2Client | undefined;
      if (grantTypeInBody === "urn:ietf:params:oauth:grant-type:device_code" && deviceCodeInBody) {
        const tokenRequest: DeviceAuthorizationTokenRequest = {
          clientId,
          clientSecret,
          grantType: grantTypeInBody,
          deviceCode: deviceCodeInBody,
        };
        client = await this.model.getClient(
          tokenRequest,
        );
      } else if (grantTypeInBody === "refresh_token" && refreshTokenInBody) {
        const refreshTokenRequest: OAuth2RefreshTokenRequest = {
          clientId,
          clientSecret,
          grantType: grantTypeInBody,
          refreshToken: refreshTokenInBody,
          scope: scopeInBody ? [...scopeInBody] : undefined,
        };
        client = await this.model.getClient(
          refreshTokenRequest,
        );
      }

      // If client authentication fails, return 401 error
      if (!client) {
        return {
          success: false,
          error: new InvalidClientError("Invalid client credentials"),
        };
      }

      // validate that client is allowed to use device authorization grant type
      if (!client.grants || !client.grants.includes(this.grantType)) {
        return {
          success: false,
          error: new UnauthorizedClientError(
            "Unauthorized client for this grant type",
          ),
        };
      }

      return {
        success: true,
        context: grantTypeInBody === "urn:ietf:params:oauth:grant-type:device_code"
          ? {
            client,
            grantType: grantTypeInBody,
            tokenType: this.tokenType,
            accessTokenLifetime: this.accessTokenLifetime,
            deviceCode: deviceCodeInBody!,
          }
          : {
            client,
            grantType: grantTypeInBody,
            tokenType: this.tokenType,
            accessTokenLifetime: this.accessTokenLifetime,
            refreshToken: refreshTokenInBody!,
            scope: scopeInBody,
          },
      };
    }

    return { success: false, error };
  }

  /**
   * Handles a token endpoint request for the device code grant (or refresh token grant).
   *
   * Validates the device code and calls `model.generateAccessToken()`. For device code
   * polling, maps RFC 8628 error codes (e.g. `authorization_pending`, `slow_down`) to
   * the appropriate OAuth 2.0 error responses.
   *
   * @param request - The incoming token endpoint HTTP request.
   * @returns A token response with the generated access token, or a failure with an error.
   */
  async token(request: Request): Promise<OAuth2FlowTokenResponse> {
    const initiationResult = await this.initiateToken(request);

    if (!initiationResult.success) {
      return initiationResult;
    }

    const { context } = initiationResult;

    // generate access token from client, valid scope,
    // and any other relevant information,
    // using the model's generateAccessToken() or generateAccessTokenFromRefreshToken() methods
    const accessTokenResult = context.grantType === "urn:ietf:params:oauth:grant-type:device_code"
      ? await this.model.generateAccessToken?.(
        // avoid mutation
        { ...context },
      )
      : await this.model.generateAccessTokenFromRefreshToken?.(
        // avoid mutation
        { ...context, scope: context.scope ? [...context.scope] : undefined },
      );

    // If token generation fails
    if (!accessTokenResult) {
      return {
        success: false,
        error: new ServerError("Failed to generate access token"),
      };
    }

    // Only for device code grant, we need to handle the specific errors
    // related to the device code authorization process as defined in RFC 8628.
    // For refresh token grant, the error handling is done in the generic way in the flow token endpoint handler.
    if (accessTokenResult.type === "error") {
      switch (accessTokenResult.error) {
        case "authorization_pending":
          return {
            success: false,
            error: new AuthorizationPendingError(
              accessTokenResult.errorDescription,
              accessTokenResult.errorUri,
            ),
          };
        case "slow_down":
          return {
            success: false,
            error: new SlowDownError(
              accessTokenResult.errorDescription,
              accessTokenResult.errorUri,
            ),
          };
        case "expired_token":
          return {
            success: false,
            error: new ExpiredTokenError(
              accessTokenResult.errorDescription,
              accessTokenResult.errorUri,
            ),
          };
        case "access_denied":
          return {
            success: false,
            error: new AccessDeniedError(
              accessTokenResult.errorDescription,
              accessTokenResult.errorUri,
            ),
          };
        default:
          return {
            success: false,
            error: new InvalidRequestError(
              accessTokenResult.errorDescription || "Invalid token request",
              accessTokenResult.errorUri,
            ),
          };
      }
    }

    const tokenResponse: OAuth2TokenResponseBody = {
      access_token: typeof accessTokenResult === "string"
        ? accessTokenResult
        : accessTokenResult.accessToken,
      token_type: this.tokenType,
      expires_in: context.accessTokenLifetime,
      scope: typeof accessTokenResult === "object" && accessTokenResult.scope
        ? accessTokenResult.scope.join(" ")
        : undefined,
      id_token: typeof accessTokenResult === "object" && accessTokenResult.idToken
        ? accessTokenResult.idToken
        : undefined,
    };

    if (
      typeof accessTokenResult === "object" &&
      typeof accessTokenResult.refreshToken === "string"
    ) {
      tokenResponse.refresh_token = accessTokenResult.refreshToken;
    }

    return {
      success: true,
      tokenResponse,
      grantType: context.grantType,
    };
  }
}

/**
 * Concrete Device Authorization flow implementation.
 *
 * Extends {@link AbstractDeviceAuthorizationFlow} with an OpenAPI security scheme
 * definition for the `deviceAuthorization` OAuth 2.0 flow type.
 *
 * @see https://datatracker.ietf.org/doc/html/rfc8628
 */
export class DeviceAuthorizationFlow extends AbstractDeviceAuthorizationFlow {
  /**
   * Returns the OpenAPI security scheme definition for this flow.
   * Uses the `oauth2` scheme type with a `deviceAuthorization` flow.
   *
   * @returns An object keyed by the security scheme name with the scheme definition.
   */
  toOpenAPISecurityScheme(): Record<
    string,
    {
      type: "oauth2";
      description?: string;
      flows: {
        deviceAuthorization: {
          deviceAuthorizationUrl: string;
          scopes: Record<string, string>;
          tokenUrl: string;
        };
      };
    }
  > {
    return {
      [this.getSecuritySchemeName()]: {
        type: "oauth2" as const,
        description: this.getDescription(),
        flows: {
          deviceAuthorization: {
            deviceAuthorizationUrl: this.getAuthorizationEndpoint(),
            scopes: { ...(this.getScopes() || {}) },
            tokenUrl: this.getTokenEndpoint(),
          },
        },
      },
    };
  }
}
