// grants/authorization_code.ts

import {
  AccessDeniedError,
  InvalidClientError,
  InvalidRequestError,
  OAuth2Error,
  ServerError,
  UnauthorizedClientError,
  UnsupportedGrantTypeError,
  UnsupportedResponseTypeError,
} from "../errors.ts";
import { TokenTypeValidationResponse } from "../token_types/types.ts";
import type { OAuth2Client, OAuth2TokenResponseBody } from "../types.ts";
import {
  type OAuth2AccessTokenResult,
  OAuth2Flow,
  type OAuth2FlowOptions,
  type OAuth2FlowTokenResponse,
  OAuth2GetClientFunction,
  type OAuth2GrantModel,
  OAuth2RefreshTokenGrantContext,
  OAuth2RefreshTokenRequest,
} from "./flow.ts";

export interface AuthorizationCodeUser {
  [key: string]: unknown;
}

export interface AuthorizationCodeReqBody {
  [key: string]: unknown;
}

/**
 * Handles the Authorization Code grant type.
 *
 * @see https://datatracker.ietf.org/doc/html/rfc6749#section-4.1
 */
export interface AuthorizationCodeGrant {
  /** The grant type identifier. */
  readonly grantType: "authorization_code";
}

/**
 * Validation context for authorization code grant,
 * which can be used by the model's generateAccessToken() method
 * to generate tokens with appropriate lifetimes, etc.
 */
export interface AuthorizationCodeGrantContext {
  client: OAuth2Client;
  grantType: "authorization_code";
  tokenType: string;
  accessTokenLifetime: number;
  code: string;
  codeVerifier?: string;
  redirectUri?: string;
}

/**
 * Raw token request parameters for authorization code grant.
 */
export interface AuthorizationCodeTokenRequest {
  clientId: string;
  grantType: "authorization_code";
  code: string;
  codeVerifier?: string;
  clientSecret?: string;
  /**
   * The redirect URI presented at the token endpoint.
   *
   * Per RFC 6749 §4.1.3, if a `redirect_uri` was included in the authorization
   * request, the same value MUST be provided here and your `getClient()`
   * implementation MUST verify that it matches the URI stored with the
   * authorization code. Failing to do so allows authorization code injection
   * across redirect URIs.
   *
   * @see https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.3
   */
  redirectUri?: string;
}

/**
 * Validation context for authorization code authentication (authorization endpoint request),
 * which can be used by the model's generateAuthorizationCode() method
 * to generate an authorization code with appropriate scope, etc.
 */
export interface AuthorizationCodeEndpointContext {
  client: OAuth2Client;
  responseType: "code"; // should be "code" for authorization code grant
  redirectUri: string;
  scope: string[];
  state?: string;
  /** PKCE code challenge (if provided). */
  codeChallenge?: string;
  /** PKCE code challenge method (`plain` | `S256`). */
  codeChallengeMethod?: "plain" | "S256";
}

/**
 * Raw authentication request parameters for authorization code grant.
 */
export interface AuthorizationCodeEndpointRequest {
  clientId: string;
  responseType: "code"; // should be "code" for authorization code grant
  redirectUri: string;
  scope?: string[];
  state?: string;
  /** PKCE code challenge (if provided). */
  codeChallenge?: string;
  /** PKCE code challenge method (`plain` | `S256`). */
  codeChallengeMethod?: "plain" | "S256";
}

export interface AuthorizationCodeEndpointContinueResponse<
  C extends AuthorizationCodeEndpointContext = AuthorizationCodeEndpointContext,
> {
  context: C;
  user: AuthorizationCodeUser;
  message?: string;
  error?: never;
  [key: string]: unknown;
}

export interface AuthorizationCodeEndpointCodeResponse<
  C extends AuthorizationCodeEndpointContext = AuthorizationCodeEndpointContext,
> {
  context: C;
  user: AuthorizationCodeUser;
  code: string;
  error?: never;
  [key: string]: unknown;
}

export type AuthorizationCodeEndpointResponse<
  C extends AuthorizationCodeEndpointContext = AuthorizationCodeEndpointContext,
> =
  | { method: "GET"; type: "initiated"; context: C }
  | {
    method: "POST";
    type: "code";
    authorizationCodeResponse: AuthorizationCodeEndpointCodeResponse<C>;
  }
  | {
    method: "POST";
    type: "continue";
    continueResponse: AuthorizationCodeEndpointContinueResponse<C>;
  }
  | {
    method: "POST";
    type: "unauthenticated";
    context: C;
    message?: string;
  }
  | {
    type: "error";
    error: OAuth2Error;
    redirectable: boolean;
    client?: OAuth2Client;
    redirectUri?: string;
    state?: string;
  };

export type AuthorizationCodeInitiationResponse<
  C extends AuthorizationCodeEndpointContext = AuthorizationCodeEndpointContext,
> =
  | { success: true; context: C }
  | { success: false; error: OAuth2Error; redirectable: false };

export type AuthorizationCodeProcessResponse<
  C extends AuthorizationCodeEndpointContext = AuthorizationCodeEndpointContext,
> =
  | {
    type: "continue";
    continueResponse: AuthorizationCodeEndpointContinueResponse<C>;
  }
  | {
    type: "code";
    authorizationCodeResponse: AuthorizationCodeEndpointCodeResponse<C>;
  }
  | {
    type: "unauthenticated";
    context: C;
    message?: string;
  }
  | {
    type: "error";
    error: OAuth2Error;
    redirectable: boolean;
    client?: OAuth2Client;
    redirectUri?: string;
    state?: string;
  };

export interface AuthorizationCodeAccessTokenResult extends OAuth2AccessTokenResult {
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

export type GetUserForAuthenticationResult =
  | { type: "authenticated"; user: AuthorizationCodeUser }
  | { type: "unauthenticated"; message?: string };

export interface GetUserForAuthenticationFunction<
  TContext extends AuthorizationCodeEndpointContext = AuthorizationCodeEndpointContext,
  AuthReqBody extends AuthorizationCodeReqBody = AuthorizationCodeReqBody,
> {
  (
    context: TContext,
    reqBody: AuthReqBody,
    request: Request,
  ):
    | Promise<
      | GetUserForAuthenticationResult
      | undefined
    >
    | GetUserForAuthenticationResult
    | undefined;
}

export type GenerateAuthorizationCodeResult =
  | { type: "code"; code: string }
  | { type: "continue"; message?: string }
  | { type: "deny"; message?: string };

export interface GenerateAuthorizationCodeFunction<
  TContext extends AuthorizationCodeEndpointContext = AuthorizationCodeEndpointContext,
> {
  (
    context: TContext,
    user: AuthorizationCodeUser,
  ):
    | Promise<GenerateAuthorizationCodeResult | undefined>
    | GenerateAuthorizationCodeResult
    | undefined;
}

/**
 * Model interface that must be implemented by the consuming application
 * to provide persistence for clients and tokens related to the authorization code grant.
 */
export interface AuthorizationCodeModel<
  AuthReqBody extends AuthorizationCodeReqBody = AuthorizationCodeReqBody,
> extends
  OAuth2GrantModel<
    AuthorizationCodeTokenRequest | OAuth2RefreshTokenRequest,
    AuthorizationCodeGrantContext,
    AuthorizationCodeAccessTokenResult | string
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
  getClient: OAuth2GetClientFunction<AuthorizationCodeTokenRequest | OAuth2RefreshTokenRequest>;

  getClientForAuthentication: OAuth2GetClientFunction<AuthorizationCodeEndpointRequest>;

  getUserForAuthentication: GetUserForAuthenticationFunction<
    AuthorizationCodeEndpointContext,
    AuthReqBody
  >;

  generateAuthorizationCode: GenerateAuthorizationCodeFunction<AuthorizationCodeEndpointContext>;
}

/**
 * Options for configuring the authorization code grant flow.
 */
export interface AuthorizationCodeFlowOptions<
  AuthReqBody extends AuthorizationCodeReqBody = AuthorizationCodeReqBody,
> extends OAuth2FlowOptions {
  model: AuthorizationCodeModel<AuthReqBody>;
  authorizationEndpoint?: string;
}

export abstract class AbstractAuthorizationCodeFlow<
  AuthReqBody extends AuthorizationCodeReqBody = AuthorizationCodeReqBody,
> extends OAuth2Flow implements AuthorizationCodeGrant {
  readonly grantType = "authorization_code" as const;
  protected readonly model: AuthorizationCodeModel<AuthReqBody>;

  protected authorizationEndpoint: string = "/authorize";

  constructor(options: AuthorizationCodeFlowOptions<AuthReqBody>) {
    const { model, authorizationEndpoint, ...flowOptions } = { ...options };
    super(flowOptions);
    this.model = model;
    if (authorizationEndpoint) {
      this.authorizationEndpoint = authorizationEndpoint;
    }
  }

  setAuthorizationEndpoint(url: string): this {
    this.authorizationEndpoint = url;
    return this;
  }

  getAuthorizationEndpoint(): string {
    return this.authorizationEndpoint;
  }

  protected async getAuthorizationCodeEndpointContext(
    request: Request,
  ): Promise<AuthorizationCodeInitiationResponse> {
    const query = new URL(request.url).searchParams;
    const clientId = query.get("client_id") || undefined;
    const responseType = query.get("response_type") || undefined;
    const redirectUri = query.get("redirect_uri") || undefined;
    const scope = query.get("scope") || undefined;
    const state = query.get("state") || undefined;
    const codeChallenge = query.get("code_challenge") || undefined;
    const tmpCodeChallengeMethod = query.get("code_challenge_method");
    const codeChallengeMethod: "S256" | "plain" | undefined = tmpCodeChallengeMethod === "S256"
      ? "S256"
      : tmpCodeChallengeMethod === "plain"
      ? "plain"
      : codeChallenge
      ? "plain" // RFC 7636 §4.3 default
      : undefined;

    if (!clientId) {
      return {
        success: false,
        error: new InvalidRequestError("Missing client_id parameter"),
        redirectable: false,
      };
    }

    if (responseType !== "code") {
      return {
        success: false,
        error: new UnsupportedResponseTypeError("Unsupported response type"),
        redirectable: false,
      };
    }

    if (!redirectUri) {
      return {
        success: false,
        error: new InvalidRequestError("Missing redirect_uri parameter"),
        redirectable: false,
      };
    }

    // In a real implementation, you would validate the client_id and redirect_uri here,
    // and then generate an authorization code and redirect the user to the redirect_uri with the code and state as query parameters.

    const client = await this.model.getClientForAuthentication({
      clientId,
      responseType,
      redirectUri,
      scope: scope ? scope.split(" ") : undefined,
      state,
      codeChallenge,
      codeChallengeMethod,
    });

    if (!client) {
      return {
        success: false,
        error: new InvalidRequestError(
          "Invalid client_id or redirect_uri or scope",
        ),
        redirectable: false,
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
        responseType,
        redirectUri,
        scope: validatedScopes,
        state,
        codeChallenge,
        codeChallengeMethod,
      },
    };
  }

  async initiateAuthorization(
    request: Request,
  ): Promise<AuthorizationCodeInitiationResponse> {
    if (request.method !== "GET") {
      return {
        success: false,
        error: new InvalidRequestError("Method Not Allowed"),
        redirectable: false,
      };
    }

    return await this.getAuthorizationCodeEndpointContext(request);
  }

  async processAuthorization(
    request: Request,
    reqBody: AuthReqBody,
  ): Promise<AuthorizationCodeProcessResponse> {
    if (request.method !== "POST") {
      return {
        type: "error",
        error: new InvalidRequestError("Method Not Allowed"),
        redirectable: false,
      };
    }

    const context = await this.getAuthorizationCodeEndpointContext(request);

    if (!context.success) {
      return {
        type: "error",
        redirectable: context.redirectable,
        error: context.error,
      };
    }

    const {
      client,
      redirectUri,
      scope,
      state,
    } = context.context;

    const userResult = await this.model.getUserForAuthentication(
      // avoid mutation
      {
        ...context.context,
        scope: [...scope],
      },
      reqBody,
      request.clone(),
    );

    if (!userResult || userResult.type === "unauthenticated") {
      return {
        type: "unauthenticated",
        //error: new InvalidClientError(userResult.message || "Invalid user credentials"),
        context: {
          ...context.context,
          scope: [...scope],
        },
        message: userResult?.message,
      };
    }

    const codeResult = await this.model.generateAuthorizationCode(
      {
        ...context.context,
        scope: [...scope],
      },
      userResult.user,
    );

    if (!codeResult) {
      return {
        type: "error",
        error: new ServerError("Failed to generate authorization code"),
        redirectable: true,
        client,
        redirectUri,
        state,
      };
    }

    if (codeResult.type === "deny") {
      return {
        type: "error",
        error: new AccessDeniedError(codeResult.message),
        redirectable: true,
        client,
        state,
        redirectUri,
      };
    }

    if (codeResult.type === "continue") {
      return {
        type: codeResult.type,
        continueResponse: {
          context: context.context,
          message: codeResult.message,
          user: userResult.user,
          scope: [...scope],
        },
      };
    }

    return {
      type: codeResult.type,
      authorizationCodeResponse: {
        context: context.context,
        scope: [...scope],
        user: userResult.user,
        code: codeResult.code,
      },
    };
  }

  async handleAuthorizationEndpoint(
    request: Request,
    reqBody: AuthReqBody,
  ): Promise<AuthorizationCodeEndpointResponse> {
    if (request.method === "GET") {
      // In a real implementation, you would render a login page
      // or consent page here for the user
      // to authenticate and authorize the client.
      const result = await this.initiateAuthorization(request);

      if (!result.success) {
        return {
          ...result,
          type: "error",
        };
      }

      return {
        ...result,
        type: "initiated",
        method: "GET",
      };
    }

    if (request.method === "POST") {
      // In a real implementation, you would authenticate the user here,
      // and if authentication is successful, generate an authorization code,
      // and redirect the user to the redirect_uri with the code and state as query parameters.

      const result = await this.processAuthorization(request, reqBody);

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
  }

  async initiateToken(request: Request): Promise<
    | {
      success: true;
      context: AuthorizationCodeGrantContext | OAuth2RefreshTokenGrantContext;
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
    let codeInBody: string | undefined;
    let codeVerifierInBody: string | undefined;
    let redirectUriInBody: string | undefined;

    let refreshTokenInBody: string | undefined;
    let scopeInBody: string[] | undefined;
    const contentType = req.headers.get("content-type") || "";

    if (contentType.includes("application/x-www-form-urlencoded")) {
      const form = await req.formData();
      body = {
        grant_type: form.get("grant_type"),
        code: form.get("code"),
        code_verifier: form.get("code_verifier"),
        redirect_uri: form.get("redirect_uri"),

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
      if ("code" in body) {
        codeInBody = typeof body.code === "string" ? body.code : undefined;
      }
      if ("code_verifier" in body) {
        codeVerifierInBody = typeof body.code_verifier === "string"
          ? body.code_verifier
          : undefined;
      }
      if ("redirect_uri" in body) {
        redirectUriInBody = typeof body.redirect_uri === "string" ? body.redirect_uri : undefined;
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
      if (!codeInBody) {
        return {
          success: false,
          error: new InvalidRequestError("Missing authorization code"),
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
      if (!clientId) {
        return {
          success: false,
          error: new InvalidClientError("Invalid client credentials"),
        };
      }

      if (
        grantTypeInBody === "authorization_code" && clientAuthMethod === "none" &&
        !codeVerifierInBody
      ) {
        // If the client authentication method is "none", then PKCE verification is required for public clients (RFC 7636 §4.1.2).
        return {
          success: false,
          error: new InvalidRequestError(
            "Public clients must use PKCE with the authorization code grant",
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
      if (grantTypeInBody === "authorization_code" && codeInBody) {
        const tokenRequest: AuthorizationCodeTokenRequest = {
          clientId,
          clientSecret,
          grantType: grantTypeInBody,
          code: codeInBody,
          codeVerifier: codeVerifierInBody,
          redirectUri: redirectUriInBody,
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
        context: grantTypeInBody === "authorization_code"
          ? {
            client,
            grantType: grantTypeInBody,
            tokenType: this.tokenType,
            accessTokenLifetime: this.accessTokenLifetime,
            code: codeInBody!,
            codeVerifier: codeVerifierInBody,
            redirectUri: redirectUriInBody,
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
   * Handle a token request for the authorization code grant type.
   * Validates the authorization code and generates an access token if valid.
   * Returns an appropriate error response if validation fails.
   * @param request The incoming HTTP request.
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
    const accessTokenResult = context.grantType === "authorization_code"
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

export class AuthorizationCodeFlow<
  AuthReqBody extends AuthorizationCodeReqBody = AuthorizationCodeReqBody,
> extends AbstractAuthorizationCodeFlow<AuthReqBody> {
  toOpenAPISecurityScheme() {
    return {
      [this.getSecuritySchemeName()]: {
        type: "oauth2" as const,
        description: this.getDescription(),
        flows: {
          authorizationCode: {
            authorizationUrl: this.getAuthorizationEndpoint(),
            scopes: { ...(this.getScopes() || {}) },
            tokenUrl: this.getTokenEndpoint(),
          },
        },
      },
    };
  }
}
