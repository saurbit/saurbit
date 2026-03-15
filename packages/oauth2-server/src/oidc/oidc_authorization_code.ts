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

/*---
OIDC requires:
- by library:
  - ID Token - implemented by the model's generateAccessToken() method and included in the token response - DONE
  - Discovery document (well-known OpenID configuration) - implemented by the flow and can be customized with openIdConfiguration option - DONE
  - openid scope (profile, email, address, phone are optional but standardized) - enforced by the flow and included in the discovery document - DONE

- by end developer:
  - UserInfo endpoint - can be implemented by the model's getUserInfo method and included in the discovery document
  - Standard claims (at least sub) - to implement by the end developer to include in the ID token, in UserInfo response and optionally in the model's getUserInfo method
  - JWKS endpoint (JSON Web Key Set) - can be implemented by the end developer and included in the discovery document
  - nonce parameter for authorization code flow with response_type=code id_token - can be implemented by the model and included in the discovery document, but it's optional for authorization code flow without id_token in the response type
---*/

function isPrompt(value?: string | null): value is "none" | "login" | "consent" | "select_account" {
  return value === "none" || value === "login" || value === "consent" || value === "select_account";
}

function isDisplay(value?: string | null): value is "page" | "popup" | "touch" | "wap" {
  return value === "page" || value === "popup" || value === "touch" || value === "wap";
}

export interface OIDCAuthenticationRequestParams {
  /**
   * The `nonce` parameter is a string value used to associate a client session with an ID token, and to mitigate replay attacks.
   * It is included in the authorization request and should be returned in the ID token.
   */
  nonce?: string;

  /**
   * The `display` parameter is used to specify how the authorization server should display the authentication and consent user interface. It allows clients to optimize the user experience for different device types and contexts. The `display` parameter can take the following values:
   * - `page`: The authorization server should display the authentication and consent user interface in a full-page view. This is the default behavior if the `display` parameter is not specified.
   * - `popup`: The authorization server should display the authentication and consent user interface in a popup window. This can be used to provide a more seamless user experience without navigating away from the client's application.
   * - `touch`: The authorization server should display a user interface optimized for touch devices, such as smartphones and tablets. This can help improve usability on mobile devices.
   * - `wap`: The authorization server should display a user interface optimized for feature phones and other devices with limited capabilities. This can help ensure that users on older or less capable devices can still authenticate successfully.
   * By including the `display` parameter in the authorization request, clients can enhance the user experience by providing an appropriate interface for the user's device and context. The `display` parameter is part of the OpenID Connect specification and can be included in the authorization request to optimize the authentication and consent user interface for different scenarios.
   */
  display?: "page" | "popup" | "touch" | "wap";

  /**
   * The `prompt` parameter is used to specify whether the authorization server should prompt the user for re-authentication and/or consent. It can take the following values:
   * - `none`: The authorization server must not display any authentication or consent user interface pages. If the user is not already authenticated and has not previously given consent, the authorization request will fail with an error.
   * - `login`: The authorization server should prompt the user to re-authenticate, even if they are already authenticated. This can be used to ensure that the user is actively involved in the authentication process.
   * - `consent`: The authorization server should prompt the user for consent before issuing tokens. This can be used to ensure that the user is aware of and agrees to the scopes being requested by the client.
   * - `select_account`: The authorization server should prompt the user to select an account if they are authenticated with multiple accounts. This can be used to allow users to choose which account they want to use for the authentication request.
   * Multiple values can be included in a space-separated list if more than one behavior is desired (e.g., `prompt=login consent` would require the user to both re-authenticate and provide consent). The `prompt` parameter is an important part of the OpenID Connect authentication flow, as it allows clients to control the user experience and ensure that users are properly authenticated and have given consent for the requested scopes.
   */
  prompt?: ("none" | "login" | "consent" | "select_account")[];

  /**
   * The `max_age` parameter specifies the maximum age of the user's authentication in seconds. If the user's authentication is older than the specified time, the authorization server should prompt the user to re-authenticate. This parameter can be used by clients to ensure that users are recently authenticated, which can be important for security-sensitive applications. For example, a client might set `max_age=3600` to require users to re-authenticate if their last authentication was more than an hour ago. The `max_age` parameter is part of the OpenID Connect specification and can be included in the authorization request to enhance security by enforcing re-authentication when necessary.
   */
  maxAge?: number;

  /**
   * The `ui_locales` parameter is used by clients to specify their preferred languages and scripts for the user interface of the authorization server. It is a space-separated list of BCP47 language tag values (e.g., `en`, `en-US`, `fr`, `fr-CA`, `zh-Hans`, `zh-Hant`). By including this parameter in the authorization request, clients can indicate to the authorization server which languages and scripts they prefer for displaying authentication and consent user interfaces. This allows the authorization server to provide a localized experience for users, improving usability and accessibility for a global audience. The `ui_locales` parameter is part of the OpenID Connect specification and can be included in the authorization request to enhance localization and user experience.
   */
  uiLocales?: string[];

  /**
   * The `id_token_hint` parameter is used to pass an existing ID token as a hint to the authorization server about the user's current authentication state. This can help streamline the authentication process by allowing the authorization server to recognize that the user is already authenticated and potentially skip additional authentication steps. The `id_token_hint` parameter is typically included in the authorization request when the client has an existing ID token for the user, such as from a previous authentication session. By providing this hint, the client can improve the user experience by reducing unnecessary prompts for authentication, while still allowing the authorization server to enforce security policies as needed. The `id_token_hint` parameter is part of the OpenID Connect specification and can be included in the authorization request to enhance user experience and streamline authentication.
   */
  idTokenHint?: string;

  /**
   * The `login_hint` parameter is used to provide a hint to the authorization server about the user's identifier, such as their email address or username. This can help pre-fill login forms and improve the user experience by reducing the amount of information the user needs to enter during authentication. The `login_hint` parameter is typically included in the authorization request when the client has some information about the user that can be used to assist with authentication. By providing this hint, the client can enhance the user experience while still allowing the authorization server to enforce security policies and ensure proper authentication. The `login_hint` parameter is part of the OpenID Connect specification and can be included in the authorization request to improve user experience during authentication.
   */
  loginHint?: string;

  /**
   * The `acr_values` parameter allows clients to specify desired Authentication Class References (ACR) values, which can be used by the authorization server to determine the appropriate level of authentication required for the request. ACR values are identifiers that represent different authentication methods or levels of assurance (e.g., password-based authentication, multi-factor authentication, biometric authentication). By including the `acr_values` parameter in the authorization request, clients can indicate their preferences for the authentication methods that should be used to authenticate the user. The authorization server can then use this information to select an appropriate authentication method based on the client's preferences and the user's available authentication options. The `acr_values` parameter is part of the OpenID Connect specification and can be included in the authorization request to enhance security by allowing clients to specify their desired authentication requirements.
   */
  acrValues?: string[];
}

export interface OIDCAuthorizationCodeEndpointRequest
  extends AuthorizationCodeEndpointRequest, OIDCAuthenticationRequestParams {
}

/**
 * Validation context for OpenID Connect authorization code flow.
 * @see https://openid.net/specs/openid-connect-core-1_0.html#AuthorizationEndpoint
 */
export interface OIDCAuthorizationCodeEndpointContext
  extends AuthorizationCodeEndpointContext, OIDCAuthenticationRequestParams {
}

export type OIDCAuthorizationCodeInitiationResponse = AuthorizationCodeInitiationResponse<
  OIDCAuthorizationCodeEndpointContext
>;
export type OIDCAuthorizationCodeProcessResponse = AuthorizationCodeProcessResponse<
  OIDCAuthorizationCodeEndpointContext
>;

export type OIDCAuthorizationCodeEndpointResponse = AuthorizationCodeEndpointResponse<
  OIDCAuthorizationCodeEndpointContext
>;

export interface OIDCAuthorizationCodeAccessTokenResult extends AuthorizationCodeAccessTokenResult {
  /**
   * For OpenID Connect, an ID token can also be returned from the token endpoint when exchanging the authorization code for tokens, and it should be included in the access token result so that it can be returned to the client in the token response.
   * @see https://openid.net/specs/openid-connect-core-1_0.html#TokenEndpoint
   */
  idToken: string;
}

export interface OIDCAuthorizationCodeModel<
  AuthReqData extends AuthorizationCodeReqData = AuthorizationCodeReqData,
> extends AuthorizationCodeModel<AuthReqData> {
  getClientForAuthentication: OAuth2GetClientFunction<OIDCAuthorizationCodeEndpointRequest>;

  generateAccessToken: OAuth2GenerateAccessTokenFunction<
    AuthorizationCodeGrantContext,
    OIDCAuthorizationCodeAccessTokenResult
  >;

  generateAccessTokenFromRefreshToken?: OAuth2GenerateAccessTokenFromRefreshTokenFunction<
    AuthorizationCodeAccessTokenResult
  >;

  getUserForAuthentication: GetUserForAuthenticationFunction<
    OIDCAuthorizationCodeEndpointContext,
    AuthReqData
  >;

  generateAuthorizationCode: GenerateAuthorizationCodeFunction<
    OIDCAuthorizationCodeEndpointContext
  >;

  /**
   * Retrieves the user information associated with the given access token.
   * This method can be implemented to provide user information
   * for the UserInfo endpoint in the OpenID Connect flow.
   * @param accessToken The access token for which to retrieve user information.
   */
  getUserInfo?: (
    accessToken: string,
  ) => Promise<OIDCUserInfo | undefined> | OIDCUserInfo | undefined;
}

/**
 * Options for configuring the OpenID Connect authorization code flow.
 */
export interface OIDCAuthorizationCodeFlowOptions<
  AuthReqData extends AuthorizationCodeReqData = AuthorizationCodeReqData,
> extends AuthorizationCodeFlowOptions<AuthReqData>, OIDCFlowExtendedOptions {
  model: OIDCAuthorizationCodeModel<AuthReqData>;
  /**
   * The URL where the OpenID Provider's JSON Web Key Set (JWKS) can be found.
   * This is used for validating tokens issued by the provider. If not provided, it will be derived from the discovery document.
   * It can be an absolute URL or a relative path (e.g., /jwks) which will be resolved against the discovery URL's origin.
   */
  jwksEndpoint: string;
}

export class OIDCAuthorizationCodeFlow<
  AuthReqData extends AuthorizationCodeReqData = AuthorizationCodeReqData,
> extends AbstractAuthorizationCodeFlow<AuthReqData> implements OIDCFlow {
  protected discoveryUrl: string;
  protected jwksEndpoint: string;
  protected openIdConfiguration?: Record<string, string | string[] | undefined>;

  constructor(options: OIDCAuthorizationCodeFlowOptions<AuthReqData>) {
    const { discoveryUrl, jwksEndpoint, openIdConfiguration, ...baseOptions } = options;
    super(baseOptions);
    this.discoveryUrl = discoveryUrl;
    this.jwksEndpoint = jwksEndpoint;
    this.openIdConfiguration = openIdConfiguration;
  }

  getDiscoveryUrl(): string {
    return this.discoveryUrl;
  }

  getJwksEndpoint(): string {
    return this.jwksEndpoint;
  }

  getOpenIdConfiguration(): Record<string, string | string[] | undefined> | undefined {
    return this.openIdConfiguration;
  }

  async getUserInfo(accessToken: string): Promise<OIDCUserInfo | undefined> {
    const model = this.model as OIDCAuthorizationCodeModel<AuthReqData>;
    if (typeof model.getUserInfo === "function") {
      return await model.getUserInfo(accessToken);
    }
    return undefined;
  }

  toOpenAPISecurityScheme() {
    return {
      [this.getSecuritySchemeName()]: {
        type: "openIdConnect" as const,
        description: this.getDescription(),
        openIdConnectUrl: this.getDiscoveryUrl(),
      },
    };
  }

  /**
   * Retrieves the OpenID Connect discovery configuration.
   * @param req - Optional request object to help determine the full URL for relative endpoints in the discovery document. If not provided, relative endpoints will be resolved against the discovery URL's origin.
   * @returns The OpenID Connect discovery configuration.
   * @link https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata
   */
  getDiscoveryConfiguration(req?: Request) {
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
      userinfo_endpoint: undefined, // This can be added to openIdConfiguration if needed
      registration_endpoint: undefined,
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

  override async initiateAuthorization(
    request: Request,
  ): Promise<OIDCAuthorizationCodeInitiationResponse> {
    return await super.initiateAuthorization(request);
  }

  override async processAuthorization(
    request: Request,
    reqData: AuthReqData,
  ): Promise<OIDCAuthorizationCodeProcessResponse> {
    return await super.processAuthorization(request, reqData);
  }

  override async handleAuthorizationEndpoint(
    request: Request,
    reqData: AuthReqData,
  ): Promise<OIDCAuthorizationCodeEndpointResponse> {
    return await super.handleAuthorizationEndpoint(request, reqData);
  }

  override getScopes(): Record<string, string> | undefined {
    // Ensure that the openid scope is always included for OpenID Connect flows
    const baseScopes = super.getScopes() || {};
    return {
      openid: baseScopes["openid"] || "Authenticate using OpenID Connect",
      ...baseScopes,
    };
  }

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
