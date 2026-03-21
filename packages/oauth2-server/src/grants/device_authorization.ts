import {
  InvalidClientError,
  InvalidRequestError,
  OAuth2Error,
  ServerError,
  UnauthorizedClientError,
  UnsupportedGrantTypeError,
} from "../errors.ts";
import { TokenTypeValidationResponse } from "../token_types/types.ts";
import { OAuth2Client, OAuth2TokenResponseBody } from "../types.ts";
import {
  OAuth2AccessTokenResult,
  OAuth2Flow,
  OAuth2FlowOptions,
  OAuth2FlowTokenResponse,
  OAuth2GetClientFunction,
  OAuth2GrantModel,
  OAuth2RefreshTokenGrantContext,
  OAuth2RefreshTokenRequest,
} from "./flow.ts";

export interface DeviceAuthorizationUser {
  [key: string]: unknown;
}

export interface DeviceAuthorizationReqData {
  [key: string]: unknown;
}

export interface DeviceAuthorizationGrant {
  /** The grant type identifier. */
  readonly grantType: "urn:ietf:params:oauth:grant-type:device_code";
}

export interface DeviceAuthorizationGrantContext {
  client: OAuth2Client;
  grantType: "urn:ietf:params:oauth:grant-type:device_code";
  tokenType: string;
  accessTokenLifetime: number;
  deviceCode: string;
}

/**
 * Raw token request parameters for device code grant.
 */
export interface DeviceAuthorizationTokenRequest {
  clientId: string;
  grantType: "urn:ietf:params:oauth:grant-type:device_code";
  deviceCode: string;
  clientSecret?: string;
}

export interface DeviceAuthorizationEndpointContext {
  client: OAuth2Client;
  scope: string[];
}

/**
 * Raw authentication request parameters for device code grant.
 */
export interface DeviceAuthorizationEndpointRequest {
  clientId: string;
  clientSecret?: string;
  scope?: string[];
}

export interface DeviceAuthorizationEndpointCodeResponse<
  C extends DeviceAuthorizationEndpointContext = DeviceAuthorizationEndpointContext,
> {
  context: C;
  user: DeviceAuthorizationUser;
  deviceCode: string;
  userCode: string;
  verificationEndpoint: string; // verificationUri
  verificationEndpointComplete: string; // verificationUriComplete
  error?: never;
  [key: string]: unknown;
}

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

export interface DeviceAuthorizationAccessTokenResult extends OAuth2AccessTokenResult {
  /**
   * Necessary to return the scope to the client.
   */
  scope?: string[];

  refreshToken?: string;

  /**
   * For OpenID Connect, an ID token can also be returned from the token endpoint when exchanging the authorization code for tokens, and it should be included in the access token result so that it can be returned to the client in the token response.
   * @see https://openid.net/specs/openid-connect-core-1_0.html#TokenEndpoint
   */
  idToken?: string;
}

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
        user: DeviceAuthorizationUser;
      } | undefined
    >
    | {
      deviceCode: string;
      userCode: string;
      user: DeviceAuthorizationUser;
    }
    | undefined;
}

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
    DeviceAuthorizationAccessTokenResult | string
  > {
  /**
   * Retrieve and validate the client for an authorization code or refresh token request.
   *
   * When `tokenRequest.grantType === "authorization_code"`, implementations MUST:
   * 1. Verify the `code` is valid and has not already been used (one-time use).
   * 2. Verify the `clientId` matches the client that requested the code.
   * 3. If `redirectUri` is present, verify it is identical to the `redirect_uri`
   *    used in the original authorization request (RFC 6749 §4.1.3). Omitting
   *    this check enables authorization code injection attacks.
   * 4. If `codeVerifier` is present, verify it against the stored `code_challenge`
   *    using the stored `code_challenge_method` (RFC 7636 §4.6).
   *
   * @see https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.3
   * @see https://datatracker.ietf.org/doc/html/rfc7636#section-4.6
   */
  getClient: OAuth2GetClientFunction<DeviceAuthorizationTokenRequest | OAuth2RefreshTokenRequest>;

  getClientForAuthentication: OAuth2GetClientFunction<DeviceAuthorizationEndpointRequest>;

  /*
  getUser()
  getUserForAuthentication: GetUserForAuthenticationFunction<
    DeviceAuthorizationEndpointContext,
    AuthReqData
  >;
  */

  verifyUserCode: (userCode: string) =>
    | Promise<
      | { /*success: true;*/ deviceCode: string; /*userCode: string,*/ client: OAuth2Client }
      | undefined
    >
    | { /*success: true;*/ deviceCode: string; /*userCode: string,*/ client: OAuth2Client }
    | undefined;

  generateDeviceCode: GenerateDeviceCodeFunction<DeviceAuthorizationEndpointContext>;
}

/**
 * Options for configuring the device authorization grant flow.
 */
export interface DeviceAuthorizationFlowOptions extends OAuth2FlowOptions {
  model: DeviceAuthorizationModel;
  authorizationEndpoint?: string;
  verificationEndpoint?: string;
}

export abstract class AbstractDeviceAuthorizationFlow extends OAuth2Flow
  implements DeviceAuthorizationGrant {
  readonly grantType = "urn:ietf:params:oauth:grant-type:device_code" as const;
  protected readonly model: DeviceAuthorizationModel;

  protected authorizationEndpoint: string = "/authorize";
  protected verificationEndpoint: string = "/verify";

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

  setAuthorizationEndpoint(url: string): this {
    this.authorizationEndpoint = url;
    return this;
  }

  getAuthorizationEndpoint(): string {
    return this.authorizationEndpoint;
  }

  setVerificationEndpoint(url: string): this {
    this.verificationEndpoint = url;
    return this;
  }

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
        user: codeResult.user,
        deviceCode: codeResult.deviceCode,
        userCode: codeResult.userCode, // In a real implementation, you would generate a separate user code that is easier for the user to input, and associate it with the device code in your data store.
        verificationEndpoint: this.verificationEndpoint,
        verificationEndpointComplete: `${this.verificationEndpoint}?user_code=${
          encodeURIComponent(codeResult.userCode)
        }}`,
      },
    };
  }

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
    const { clientId, clientSecret, error, method: clientAuthMethod } = await this
      .extractClientCredentials(
        request.clone(),
        this.clientAuthMethods,
        this.getTokenEndpointAuthMethods(),
      );

    // If the request contains client authentication credentials, validate them
    if (!error) {
      // If clientId is missing, return 401 error
      if (!clientId || !clientSecret) {
        return {
          success: false,
          error: new InvalidClientError("Invalid client credentials"),
        };
      }

      if (
        grantTypeInBody === "urn:ietf:params:oauth:grant-type:device_code" &&
        clientAuthMethod === "none"
      ) {
        // If the client authentication method is "none", then PKCE verification is required for public clients (RFC 7636 §4.1.2).
        return {
          success: false,
          error: new InvalidRequestError(
            "Public clients must use PKCE with the device code grant",
          ),
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

      // validate that client is allowed to use authorization code grant type
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
