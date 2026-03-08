import { InvalidRequestError, ServerError } from "../errors.ts";
import {
  OAuth2AuthFlowTokenResponse,
  OAuth2RefreshTokenGrantContext,
} from "../grants/auth_flow.ts";
import {
  AbstractAuthorizationCodeGrantFlow,
  AuthorizationCodeAccessTokenResult,
  AuthorizationCodeGrantContext,
  AuthorizationCodeGrantFlowOptions,
  AuthorizationCodeInitiationResponse,
  AuthorizationCodeModel,
  AuthorizationCodeReqBody,
} from "../grants/authorization_code.ts";
import { normalizeUrl } from "../utils/normalize_url.ts";
import { OpenIDUserInfo } from "./types.ts";

/*
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
*/

export interface OpenIDAuthorizationCodeAccessTokenResult
  extends AuthorizationCodeAccessTokenResult {
  /**
   * For OpenID Connect, an ID token can also be returned from the token endpoint when exchanging the authorization code for tokens, and it should be included in the access token result so that it can be returned to the client in the token response.
   * @see https://openid.net/specs/openid-connect-core-1_0.html#TokenEndpoint
   */
  idToken: string;
}

export interface OpenIDAuthorizationCodeModel<
  AuthReqBody extends AuthorizationCodeReqBody = AuthorizationCodeReqBody,
> extends AuthorizationCodeModel<AuthReqBody> {
  generateAccessToken(
    context: AuthorizationCodeGrantContext,
  ):
    | Promise<OpenIDAuthorizationCodeAccessTokenResult | undefined>
    | OpenIDAuthorizationCodeAccessTokenResult
    | undefined;

  generateAccessTokenFromRefreshToken?(
    context: OAuth2RefreshTokenGrantContext,
  ):
    | Promise<AuthorizationCodeAccessTokenResult | undefined>
    | AuthorizationCodeAccessTokenResult
    | undefined;

  /**
   * Retrieves the user information associated with the given access token.
   * This method can be implemented to provide user information
   * for the UserInfo endpoint in the OpenID Connect flow.
   * @param accessToken The access token for which to retrieve user information.
   */
  getUserInfo?(
    accessToken: string,
  ): Promise<OpenIDUserInfo | undefined> | OpenIDUserInfo | undefined;
}

/**
 * Options for configuring the OpenID Connect authorization code flow.
 */
export interface OpenIDAuthorizationCodeFlowOptions<
  AuthReqBody extends AuthorizationCodeReqBody = AuthorizationCodeReqBody,
> extends AuthorizationCodeGrantFlowOptions<AuthReqBody> {
  model: OpenIDAuthorizationCodeModel<AuthReqBody>;
  /**
   * The URL where the OpenID Provider's discovery document can be found.
   * This is a required field and should point to the well-known OpenID configuration endpoint
   * (e.g., https://example.com/.well-known/openid-configuration).
   */
  discoveryUrl: string;
  /**
   * The URL where the OpenID Provider's JSON Web Key Set (JWKS) can be found.
   * This is used for validating tokens issued by the provider. If not provided, it will be derived from the discovery document.
   * It can be an absolute URL or a relative path (e.g., /jwks) which will be resolved against the discovery URL's origin.
   */
  jwksUri: string;
  /**
   * Additional OpenID configuration parameters to include in the discovery document.
   * This allows for customization of the discovery document beyond the standard fields.
   * The provided configuration will be merged with the default values derived from the flow's settings.
   * This is useful for adding custom fields or overriding defaults when necessary.
   */
  openIdConfiguration?: Record<string, string | string[] | undefined>;
}

export class OpenIDAuthorizationCodeFlow<
  AuthReqBody extends AuthorizationCodeReqBody = AuthorizationCodeReqBody,
> extends AbstractAuthorizationCodeGrantFlow<AuthReqBody> {
  protected discoveryUrl: string;
  protected jwksUri: string;
  protected openIdConfiguration?: Record<string, string | string[] | undefined>;

  constructor(options: OpenIDAuthorizationCodeFlowOptions) {
    const { discoveryUrl, jwksUri, openIdConfiguration, ...baseOptions } = options;
    super(baseOptions);
    this.discoveryUrl = discoveryUrl;
    this.jwksUri = jwksUri;
    this.openIdConfiguration = openIdConfiguration;
  }

  protected normalizeUrl(url: string, origin?: string): string {
    return normalizeUrl(url, origin || new URL(this.discoveryUrl).origin);
  }

  getDiscoveryUrl(): string {
    return this.discoveryUrl;
  }

  getJwksUri(): string {
    return this.jwksUri;
  }

  getOpenIdConfiguration(): Record<string, string | string[] | undefined> | undefined {
    return this.openIdConfiguration;
  }

  async getUserInfo(accessToken: string): Promise<OpenIDUserInfo | undefined> {
    const model = this.model as OpenIDAuthorizationCodeModel<AuthReqBody>;
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

  getDiscoveryConfiguration() {
    const supported = this.getTokenEndpointAuthMethods();
    const scopes = this.getScopes() || {};

    const host = new URL(this.getDiscoveryUrl()).origin;

    // Format jwks_uri if it's a relative path
    let jwksUri = this.getJwksUri();
    if (jwksUri) {
      jwksUri = this.normalizeUrl(jwksUri, host);
    }
    // Format token endpoint if it's a relative path
    let tokenEndpoint = this.getTokenUrl();
    if (tokenEndpoint) {
      tokenEndpoint = this.normalizeUrl(tokenEndpoint, host);
    }
    let authorizationEndpoint = this.getAuthorizationUrl();
    if (authorizationEndpoint) {
      authorizationEndpoint = this.normalizeUrl(authorizationEndpoint, host);
    }

    const wellKnownOpenIDConfig: Record<string, string | string[] | undefined> = {
      issuer: host,
      authorization_endpoint: authorizationEndpoint,
      token_endpoint: tokenEndpoint,
      userinfo_endpoint: undefined, // This can be added to openIdConfiguration if needed
      jwks_uri: jwksUri,
      registration_endpoint: undefined,
      claims_supported: ["aud", "exp", "iat", "iss", "sub"],
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
      result.userinfo_endpoint = this.normalizeUrl(result.userinfo_endpoint, host);
    }
    if (typeof result.registration_endpoint === "string") {
      result.registration_endpoint = this.normalizeUrl(result.registration_endpoint, host);
    }

    return result;
  }

  protected override async getAuthorizationCodeEndpointContext(
    request: Request,
  ): Promise<AuthorizationCodeInitiationResponse> {
    const query = new URL(request.url).searchParams;
    const scope = query.get("scope") || undefined;
    if (!scope || !scope.split(" ").includes("openid")) {
      return {
        success: false,
        error: new InvalidRequestError(
          "The 'openid' scope is required for OpenID Connect authorization code flow",
        ),
        redirectable: false,
      };
    }
    return await super.getAuthorizationCodeEndpointContext(request);
  }

  override getScopes(): Record<string, string> | undefined {
    // Ensure that the openid scope is always included for OpenID Connect flows
    const baseScopes = super.getScopes() || {};
    return {
      openid: baseScopes["openid"] || "Authenticate using OpenID Connect",
      ...baseScopes,
    };
  }

  override async token(request: Request): Promise<OAuth2AuthFlowTokenResponse> {
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
