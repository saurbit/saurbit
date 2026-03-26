/**
 * @module
 *
 * Implements the OpenID Connect Authorization Code flow, extending the base
 * OAuth 2.0 Authorization Code grant with OIDC-specific request parameters,
 * ID token enforcement, UserInfo support, and a discovery document.
 *
 * @see https://openid.net/specs/openid-connect-core-1_0.html#CodeFlowAuth
 */

import { InvalidRequestError, ServerError, UnsupportedResponseTypeError } from "../errors.ts";
import {
  OAuth2FlowTokenResponse,
  OAuth2GenerateAccessTokenFromRefreshTokenFunction,
  OAuth2GenerateAccessTokenFunction,
  OAuth2GetClientFunction,
} from "../grants/flow.ts";
import {
  AbstractAuthorizationCodeFlow,
  AuthorizationCodeAccessTokenResult,
  AuthorizationCodeEndpointContext,
  AuthorizationCodeEndpointRequest,
  AuthorizationCodeEndpointResponse,
  AuthorizationCodeFlowOptions,
  AuthorizationCodeGrantContext,
  AuthorizationCodeInitiationResponse,
  AuthorizationCodeModel,
  AuthorizationCodeProcessResponse,
  AuthorizationCodeReqData,
  GenerateAuthorizationCodeFunction,
  GetUserForAuthenticationFunction,
} from "../grants/authorization_code.ts";
import { getOriginFromUrl, normalizeUrl } from "../utils/url_tools.ts";
import { OIDCFlow, OIDCFlowExtendedOptions, OIDCUserInfo } from "./types.ts";

function isPrompt(value?: string | null): value is "none" | "login" | "consent" | "select_account" {
  return value === "none" || value === "login" || value === "consent" || value === "select_account";
}

function isDisplay(value?: string | null): value is "page" | "popup" | "touch" | "wap" {
  return value === "page" || value === "popup" || value === "touch" || value === "wap";
}

/**
 * OIDC-specific authentication request parameters that extend the base OAuth 2.0
 * authorization request. These correspond to the additional query parameters
 * defined by the OpenID Connect Core specification.
 *
 * @see https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
 */
export interface OIDCAuthenticationRequestParams {
  /**
   * The `nonce` parameter is a string value used to associate a client session with an ID token,
   * and to mitigate replay attacks. It is included in the authorization request and should be
   * returned in the ID token.
   */
  nonce?: string;

  /**
   * The `display` parameter specifies how the authorization server should display the
   * authentication and consent UI:
   * - `page`: Full-page view (default).
   * - `popup`: Popup window.
   * - `touch`: Optimized for touch devices.
   * - `wap`: Optimized for feature phones.
   */
  display?: "page" | "popup" | "touch" | "wap";

  /**
   * The `prompt` parameter controls whether the authorization server prompts the user
   * for re-authentication and/or consent:
   * - `none`: Must not display any UI; fails if user is not already authenticated.
   * - `login`: Prompt the user to re-authenticate.
   * - `consent`: Prompt the user for consent before issuing tokens.
   * - `select_account`: Prompt the user to select an account.
   *
   * Multiple values may be combined (e.g. `["login", "consent"]`).
   */
  prompt?: ("none" | "login" | "consent" | "select_account")[];

  /**
   * The `max_age` parameter specifies the maximum age in seconds of the user's authentication.
   * If the user's last authentication is older than this value, the server should prompt
   * re-authentication.
   */
  maxAge?: number;

  /**
   * The `ui_locales` parameter specifies the client's preferred languages and scripts
   * for the authorization server UI, as a list of BCP47 language tags
   * (e.g. `["en-US", "fr"]`).
   */
  uiLocales?: string[];

  /**
   * The `id_token_hint` parameter passes an existing ID token as a hint to the authorization
   * server about the user's current authentication state, potentially skipping re-authentication.
   */
  idTokenHint?: string;

  /**
   * The `login_hint` parameter provides a hint to the authorization server about the user's
   * identifier (e.g. email address or username) to pre-fill login forms.
   */
  loginHint?: string;

  /**
   * The `acr_values` parameter specifies desired Authentication Class Reference values,
   * indicating the authentication methods or levels of assurance the client requires.
   */
  acrValues?: string[];
}

/**
 * Raw OIDC authorization endpoint request parameters, combining the base OAuth 2.0
 * authorization endpoint request with OIDC-specific parameters.
 */
export interface OIDCAuthorizationCodeEndpointRequest
  extends AuthorizationCodeEndpointRequest, OIDCAuthenticationRequestParams {
}

/**
 * Validation context for the OpenID Connect authorization code flow,
 * passed to `getUserForAuthentication()` and `generateAuthorizationCode()`.
 *
 * Extends the base authorization code endpoint context with OIDC-specific parameters.
 *
 * @see https://openid.net/specs/openid-connect-core-1_0.html#AuthorizationEndpoint
 */
export interface OIDCAuthorizationCodeEndpointContext
  extends AuthorizationCodeEndpointContext, OIDCAuthenticationRequestParams {
}

/**
 * The result of `initiateAuthorization()` for the OIDC Authorization Code flow.
 * On success, contains the validated {@link OIDCAuthorizationCodeEndpointContext}.
 */
export type OIDCAuthorizationCodeInitiationResponse = AuthorizationCodeInitiationResponse<
  OIDCAuthorizationCodeEndpointContext
>;

/**
 * The result of `processAuthorization()` for the OIDC Authorization Code flow.
 * A discriminated union of all possible outcomes after the user submits credentials.
 */
export type OIDCAuthorizationCodeProcessResponse = AuthorizationCodeProcessResponse<
  OIDCAuthorizationCodeEndpointContext
>;

/**
 * The union of all possible outcomes from `handleAuthorizationEndpoint()` for the
 * OIDC Authorization Code flow.
 */
export type OIDCAuthorizationCodeEndpointResponse = AuthorizationCodeEndpointResponse<
  OIDCAuthorizationCodeEndpointContext
>;

/**
 * The access token result shape for the OIDC Authorization Code flow.
 * Extends the base result to make `idToken` required, as the OpenID Connect
 * specification requires an ID token in the token response.
 *
 * @see https://openid.net/specs/openid-connect-core-1_0.html#TokenEndpoint
 */
export interface OIDCAuthorizationCodeAccessTokenResult extends AuthorizationCodeAccessTokenResult {
  /**
   * The ID token issued by the authorization server for this authentication.
   * Required for the OIDC Authorization Code flow token response.
   *
   * @see https://openid.net/specs/openid-connect-core-1_0.html#TokenEndpoint
   */
  idToken: string;
}

/**
 * Model interface for the OIDC Authorization Code flow.
 *
 * Extends {@link AuthorizationCodeModel} to use OIDC-specific context and request types,
 * and adds an optional `getUserInfo()` method for the UserInfo endpoint.
 *
 * @template AuthReqData - The shape of user-submitted data at the authorization endpoint.
 */
export interface OIDCAuthorizationCodeModel<
  AuthReqData extends AuthorizationCodeReqData = AuthorizationCodeReqData,
> extends AuthorizationCodeModel<AuthReqData> {
  /**
   * Retrieves and validates the client for an OIDC authorization endpoint request.
   * Should verify `clientId`, `redirectUri`, and any requested scopes.
   */
  getClientForAuthentication: OAuth2GetClientFunction<OIDCAuthorizationCodeEndpointRequest>;

  /**
   * Generates an access token (and required ID token) for the authenticated grant context.
   * The returned result MUST include an `idToken` for OIDC compliance.
   */
  generateAccessToken: OAuth2GenerateAccessTokenFunction<
    AuthorizationCodeGrantContext,
    OIDCAuthorizationCodeAccessTokenResult
  >;

  /**
   * Generates a new access token from a refresh token.
   * Optional - only implement if the flow supports refresh token grants.
   * The ID token is optional in refresh token responses per the OIDC specification.
   */
  generateAccessTokenFromRefreshToken?: OAuth2GenerateAccessTokenFromRefreshTokenFunction<
    AuthorizationCodeAccessTokenResult
  >;

  /**
   * Authenticates the end-user from the submitted OIDC authorization request data.
   * Receives the full OIDC context including `nonce`, `prompt`, `max_age`, etc.
   */
  getUserForAuthentication: GetUserForAuthenticationFunction<
    OIDCAuthorizationCodeEndpointContext,
    AuthReqData
  >;

  /**
   * Generates (or denies) an authorization code for the authenticated user.
   * Receives the full OIDC context so the code can be associated with OIDC parameters
   * (e.g. `nonce`) for later inclusion in the ID token.
   */
  generateAuthorizationCode: GenerateAuthorizationCodeFunction<
    OIDCAuthorizationCodeEndpointContext
  >;

  /**
   * Retrieves the user information associated with the given access token.
   * Implement to support the UserInfo endpoint in the OpenID Connect flow.
   *
   * @param accessToken - The access token for which to retrieve user information.
   * @returns The UserInfo claims, or `undefined` if not supported.
   *
   * @see https://openid.net/specs/openid-connect-core-1_0.html#UserInfo
   */
  getUserInfo?: (
    accessToken: string,
  ) => Promise<OIDCUserInfo | undefined> | OIDCUserInfo | undefined;
}

/**
 * Options for configuring the OpenID Connect Authorization Code flow.
 */
export interface OIDCAuthorizationCodeFlowOptions<
  AuthReqData extends AuthorizationCodeReqData = AuthorizationCodeReqData,
> extends AuthorizationCodeFlowOptions<AuthReqData>, OIDCFlowExtendedOptions {
  /** The OIDC model implementation. */
  model: OIDCAuthorizationCodeModel<AuthReqData>;

  /**
   * The URL of the JWKS endpoint used for token validation.
   * Can be an absolute URL or a relative path (e.g. `"/jwks"`) resolved against
   * the discovery URL's origin.
   */
  jwksEndpoint: string;

  /**
   * The URL of the UserInfo endpoint.
   * Included in the discovery document if provided.
   *
   * @see https://openid.net/specs/openid-connect-core-1_0.html#UserInfo
   */
  userInfoEndpoint?: string;

  /**
   * The URL of the dynamic client registration endpoint.
   * Included in the discovery document if provided.
   *
   * @see https://openid.net/specs/openid-connect-registration-1_0.html
   */
  registrationEndpoint?: string;
}

/**
 * OpenID Connect Authorization Code flow implementation.
 *
 * Extends {@link AbstractAuthorizationCodeFlow} with:
 * - OIDC-specific request parameter parsing (`nonce`, `prompt`, `max_age`, etc.)
 * - Enforcement of the `openid` scope
 * - ID token requirement in the token response
 * - OpenID Connect discovery document generation
 * - Optional UserInfo endpoint support
 *
 * @template AuthReqData - The shape of user-submitted data at the authorization endpoint.
 *
 * @see https://openid.net/specs/openid-connect-core-1_0.html#CodeFlowAuth
 */
export class OIDCAuthorizationCodeFlow<
  AuthReqData extends AuthorizationCodeReqData = AuthorizationCodeReqData,
> extends AbstractAuthorizationCodeFlow<AuthReqData> implements OIDCFlow {
  protected discoveryUrl: string;
  protected jwksEndpoint: string;
  protected userInfoEndpoint?: string;
  protected registrationEndpoint?: string;
  protected openIdConfiguration?: Record<string, string | string[] | undefined>;

  constructor(options: OIDCAuthorizationCodeFlowOptions<AuthReqData>) {
    const {
      discoveryUrl,
      jwksEndpoint,
      userInfoEndpoint,
      registrationEndpoint,
      openIdConfiguration,
      ...baseOptions
    } = options;
    super(baseOptions);
    this.discoveryUrl = discoveryUrl;
    this.jwksEndpoint = jwksEndpoint;
    this.userInfoEndpoint = userInfoEndpoint;
    this.registrationEndpoint = registrationEndpoint;
    this.openIdConfiguration = openIdConfiguration;
  }

  /**
   * Returns the URL of the OpenID Connect discovery document.
   */
  getDiscoveryUrl(): string {
    return this.discoveryUrl;
  }

  /**
   * Returns the URL of the JWKS endpoint.
   */
  getJwksEndpoint(): string {
    return this.jwksEndpoint;
  }

  /**
   * Returns the static OpenID configuration overrides merged into the discovery document,
   * or `undefined` if none were set.
   */
  getOpenIdConfiguration(): Record<string, string | string[] | undefined> | undefined {
    return this.openIdConfiguration;
  }

  /**
   * Returns the URL of the UserInfo endpoint, or `undefined` if not configured.
   */
  getUserInfoEndpoint(): string | undefined {
    return this.userInfoEndpoint;
  }

  /**
   * Returns the URL of the dynamic client registration endpoint, or `undefined` if not configured.
   */
  getRegistrationEndpoint(): string | undefined {
    return this.registrationEndpoint;
  }

  /**
   * Retrieves the UserInfo claims for the given access token by delegating to
   * `model.getUserInfo()`. Returns `undefined` if the model does not implement `getUserInfo`.
   *
   * @param accessToken - The access token for which to retrieve user information.
   * @returns The UserInfo claims, or `undefined`.
   *
   * @see https://openid.net/specs/openid-connect-core-1_0.html#UserInfo
   */
  async getUserInfo(accessToken: string): Promise<OIDCUserInfo | undefined> {
    const model = this.model as OIDCAuthorizationCodeModel<AuthReqData>;
    if (typeof model.getUserInfo === "function") {
      return await model.getUserInfo(accessToken);
    }
    return undefined;
  }

  /**
   * Returns the OpenAPI security scheme definition for this flow.
   * Uses the `openIdConnect` scheme type pointing to the discovery URL.
   *
   * @returns An object keyed by the security scheme name with the scheme definition.
   */
  toOpenAPISecurityScheme(): Record<
    string,
    { type: "openIdConnect"; description?: string; openIdConnectUrl: string }
  > {
    return {
      [this.getSecuritySchemeName()]: {
        type: "openIdConnect" as const,
        description: this.getDescription(),
        openIdConnectUrl: this.getDiscoveryUrl(),
      },
    };
  }

  /**
   * Retrieves the OpenID Connect discovery configuration document.
   *
   * Builds the standard provider metadata fields from the flow's configuration and
   * merges in any static overrides set via `openIdConfiguration`. Relative endpoint
   * URLs are resolved against the request's origin (or the discovery URL's origin if
   * no request is provided).
   *
   * @param req - Optional request used to determine the full base URL for relative endpoints.
   * @returns The OpenID Connect discovery document fields.
   * @see https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata
   */
  getDiscoveryConfiguration(req?: Request): Record<string, string | string[] | undefined> {
    const supported = this.getTokenEndpointAuthMethods();
    const scopes = this.getScopes() || {};

    let fullUrl: string | undefined;
    if (req) {
      const url = new URL(req.url);
      const forwardedProto = req.headers.get("x-forwarded-proto");
      const protocol = forwardedProto ? forwardedProto : url.protocol.replace(":", "");
      fullUrl = protocol + "://" + url.host;
    }

    const host = typeof fullUrl === "string"
      ? fullUrl
      : getOriginFromUrl(this.getDiscoveryUrl()) || "";

    // Format jwks_uri if it's a relative path
    let jwksEndpoint = this.getJwksEndpoint();
    if (jwksEndpoint) {
      jwksEndpoint = normalizeUrl(jwksEndpoint, host);
    }
    // Format token endpoint if it's a relative path
    let tokenEndpoint = this.getTokenEndpoint();
    if (tokenEndpoint) {
      tokenEndpoint = normalizeUrl(tokenEndpoint, host);
    }
    let authorizationEndpoint = this.getAuthorizationEndpoint();
    if (authorizationEndpoint) {
      authorizationEndpoint = normalizeUrl(authorizationEndpoint, host);
    }

    const wellKnownOpenIDConfig: Record<string, string | string[] | undefined> = {
      issuer: host,
      authorization_endpoint: authorizationEndpoint,
      token_endpoint: tokenEndpoint,
      jwks_uri: jwksEndpoint,
      userinfo_endpoint: this.getUserInfoEndpoint(),
      registration_endpoint: this.getRegistrationEndpoint(),
      claims_supported: ["sub"],
      grant_types_supported: [this.grantType],
      response_types_supported: ["code"],
      scopes_supported: Object.keys(scopes),
      subject_types_supported: ["public"],
      id_token_signing_alg_values_supported: ["RS256"],
      token_endpoint_auth_methods_supported: supported,
    };

    if (this.clientAuthMethods.client_secret_jwt?.algorithms?.length) {
      wellKnownOpenIDConfig.token_endpoint_auth_signing_alg_values_supported =
        wellKnownOpenIDConfig.token_endpoint_auth_signing_alg_values_supported || [];
      wellKnownOpenIDConfig.token_endpoint_auth_signing_alg_values_supported = [
        ...wellKnownOpenIDConfig.token_endpoint_auth_signing_alg_values_supported,
        ...this.clientAuthMethods.client_secret_jwt.algorithms,
      ];
    }
    if (this.clientAuthMethods.private_key_jwt?.algorithms?.length) {
      wellKnownOpenIDConfig.token_endpoint_auth_signing_alg_values_supported =
        wellKnownOpenIDConfig.token_endpoint_auth_signing_alg_values_supported || [];
      wellKnownOpenIDConfig.token_endpoint_auth_signing_alg_values_supported = [
        ...wellKnownOpenIDConfig.token_endpoint_auth_signing_alg_values_supported,
        ...this.clientAuthMethods.private_key_jwt.algorithms,
      ];
    }

    const result = { ...wellKnownOpenIDConfig, ...(this.getOpenIdConfiguration() || {}) };

    // Format unhandled endpoints
    if (typeof result.userinfo_endpoint === "string") {
      result.userinfo_endpoint = normalizeUrl(result.userinfo_endpoint, host);
    }
    if (typeof result.registration_endpoint === "string") {
      result.registration_endpoint = normalizeUrl(result.registration_endpoint, host);
    }

    return result;
  }

  protected override async getAuthorizationCodeEndpointContext(
    request: Request,
  ): Promise<OIDCAuthorizationCodeInitiationResponse> {
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

    const nonce = query.get("nonce") || undefined;
    const tmpPrompt = query.get("prompt") || undefined;
    const prompt = typeof tmpPrompt === "undefined"
      ? undefined
      : tmpPrompt.split(" ").filter(isPrompt);
    const rawMaxAge = query.get("max_age");
    const maxAge = rawMaxAge
      ? (Number.isFinite(parseInt(rawMaxAge, 10)) ? parseInt(rawMaxAge, 10) : undefined)
      : undefined;
    const uiLocales = query.get("ui_locales")
      ? query.get("ui_locales")!.split(" ").filter((l) => l)
      : undefined;
    const idTokenHint = query.get("id_token_hint") || undefined;
    const loginHint = query.get("login_hint") || undefined;
    const acrValues = query.get("acr_values")
      ? query.get("acr_values")!.split(" ").filter((v) => v)
      : undefined;
    const tmpDisplay = query.get("display") || undefined;
    const display = isDisplay(tmpDisplay) ? tmpDisplay : undefined;

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

    if (!scope || !scope.split(" ").includes("openid")) {
      return {
        success: false,
        error: new InvalidRequestError(
          "The 'openid' scope is required for OpenID Connect authorization code flow",
        ),
        redirectable: false,
      };
    }

    // In a real implementation, you would validate the client_id and redirect_uri here,
    // and then generate an authorization code and redirect the user to the redirect_uri with the code and state as query parameters.

    const reqParams: OIDCAuthorizationCodeEndpointRequest = {
      clientId,
      responseType,
      redirectUri,
      scope: scope ? scope.split(" ") : undefined,
      state,
      codeChallenge,
      codeChallengeMethod,
      nonce,
      prompt,
      maxAge,
      uiLocales: uiLocales ? [...uiLocales] : undefined,
      idTokenHint,
      loginHint,
      acrValues: acrValues ? [...acrValues] : undefined,
      display,
    };

    const client = await this.model.getClientForAuthentication(reqParams);

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
        nonce,
        prompt,
        maxAge,
        uiLocales,
        idTokenHint,
        loginHint,
        acrValues,
        display,
      },
    };
  }

  /**
   * Validates an incoming OIDC authorization endpoint `GET` request and returns the
   * OIDC authorization context including all OIDC-specific parameters.
   *
   * Enforces that the `openid` scope is present.
   *
   * @param request - The incoming `GET` request to the authorization endpoint.
   * @returns The initiation response with the OIDC context, or a non-redirectable error.
   */
  override async initiateAuthorization(
    request: Request,
  ): Promise<OIDCAuthorizationCodeInitiationResponse> {
    return await super.initiateAuthorization(request);
  }

  /**
   * Processes the user's submitted credentials at the OIDC authorization endpoint.
   *
   * Delegates to the base implementation with the OIDC-typed context.
   *
   * @param request - The incoming HTTP request to the authorization endpoint.
   * @param reqData - The user-submitted data (e.g. login form fields).
   * @returns The OIDC process response - code, continue, unauthenticated, or error.
   */
  override async processAuthorization(
    request: Request,
    reqData: AuthReqData,
  ): Promise<OIDCAuthorizationCodeProcessResponse> {
    return await super.processAuthorization(request, reqData);
  }

  /**
   * Unified handler for `GET` and `POST` requests to the OIDC authorization endpoint.
   *
   * Delegates to `initiateAuthorization()` (`GET`) or `processAuthorization()` (`POST`).
   *
   * @param request - The incoming HTTP request to the authorization endpoint.
   * @param reqData - The user-submitted data (used for `POST` requests only).
   * @returns The OIDC endpoint response - a discriminated union of all possible outcomes.
   */
  override async handleAuthorizationEndpoint(
    request: Request,
    reqData: AuthReqData,
  ): Promise<OIDCAuthorizationCodeEndpointResponse> {
    return await super.handleAuthorizationEndpoint(request, reqData);
  }

  /**
   * Returns the scopes for this flow, always ensuring the `openid` scope is present
   * as required by the OpenID Connect specification.
   *
   * @returns The scopes map with `openid` guaranteed to be included.
   */
  override getScopes(): Record<string, string> | undefined {
    // Ensure that the openid scope is always included for OpenID Connect flows
    const baseScopes = super.getScopes() || {};
    return {
      openid: baseScopes["openid"] || "Authenticate using OpenID Connect",
      ...baseScopes,
    };
  }

  /**
   * Handles a token endpoint request for the OIDC Authorization Code flow.
   *
   * Enforces OIDC compliance by verifying that the `openid` scope is present and
   * that the token response includes an ID token. For refresh token grants, the ID
   * token is optional per the OIDC specification.
   *
   * @param request - The incoming token endpoint HTTP request.
   * @returns A token response with the access token and ID token, or a failure with an error.
   */
  override async token(request: Request): Promise<OAuth2FlowTokenResponse> {
    const r = await super.token(request);
    if (r.success) {
      const tokenResponse = r.tokenResponse;
      const scope = tokenResponse.scope ? tokenResponse.scope.split(" ") : [];
      if (!scope.includes("openid")) {
        return {
          success: false,
          error: new ServerError("The 'openid' scope is required when an ID Token is returned"),
        };
      }
      if (tokenResponse.id_token && typeof tokenResponse.id_token === "string") {
        return {
          success: true,
          tokenResponse: {
            ...tokenResponse,
            id_token: tokenResponse.id_token,
          },
          grantType: r.grantType,
        };
      } else if (r.grantType === "refresh_token") {
        // For refresh token grant, the ID token is optional according to the OpenID Connect specification, so we can allow the token response to succeed even if the ID token is not included. However, if the openid scope is included in the refresh token request, we should ideally return a new ID token in the response. If the model's generateAccessTokenFromRefreshToken method does not return an ID token, we can still return a successful response but without the ID token.
        return r;
      } else {
        return {
          success: false,
          error: new ServerError("ID Token is required for OpenID Connect authorization code flow"),
        };
      }
    }
    return r;
  }
}
