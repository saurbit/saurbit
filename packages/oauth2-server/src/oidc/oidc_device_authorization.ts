import { ServerError } from "../errors.ts";
import {
  AbstractDeviceAuthorizationFlow,
  DeviceAuthorizationAccessTokenError,
  DeviceAuthorizationAccessTokenResult,
  DeviceAuthorizationFlowOptions,
  DeviceAuthorizationGrantContext,
  DeviceAuthorizationModel,
} from "../grants/device_authorization.ts";
import { OAuth2FlowTokenResponse, OAuth2GenerateAccessTokenFunction } from "../grants/flow.ts";
import { getOriginFromUrl, normalizeUrl } from "../utils/url_tools.ts";
import { OIDCFlow, OIDCFlowExtendedOptions, OIDCUserInfo } from "./types.ts";

export interface OIDCDeviceAuthorizationAccessTokenResult
  extends DeviceAuthorizationAccessTokenResult {
  /**
   * For OpenID Connect, an ID token can also be returned from the token endpoint when exchanging the authorization code for tokens, and it should be included in the access token result so that it can be returned to the client in the token response.
   * @see https://openid.net/specs/openid-connect-core-1_0.html#TokenEndpoint
   */
  idToken: string;
}

export interface OIDCDeviceAuthorizationModel extends DeviceAuthorizationModel {
  generateAccessToken: OAuth2GenerateAccessTokenFunction<
    DeviceAuthorizationGrantContext,
    OIDCDeviceAuthorizationAccessTokenResult | DeviceAuthorizationAccessTokenError
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

export interface OIDCDeviceAuthorizationFlowOptions
  extends DeviceAuthorizationFlowOptions, OIDCFlowExtendedOptions {
  model: OIDCDeviceAuthorizationModel;
  /**
   * The URL where the OpenID Provider's JSON Web Key Set (JWKS) can be found.
   * This is used for validating tokens issued by the provider. If not provided, it will be derived from the discovery document.
   * It can be an absolute URL or a relative path (e.g., /jwks) which will be resolved against the discovery URL's origin.
   */
  jwksEndpoint: string;

  userInfoEndpoint?: string;

  registrationEndpoint?: string;
}

export class OIDCDeviceAuthorizationFlow extends AbstractDeviceAuthorizationFlow
  implements OIDCFlow {
  protected discoveryUrl: string;
  protected jwksEndpoint: string;
  protected userInfoEndpoint?: string;
  protected registrationEndpoint?: string;
  protected openIdConfiguration?: Record<string, string | string[] | undefined>;

  constructor(options: OIDCDeviceAuthorizationFlowOptions) {
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

  getDiscoveryUrl(): string {
    return this.discoveryUrl;
  }

  getJwksEndpoint(): string {
    return this.jwksEndpoint;
  }

  getOpenIdConfiguration(): Record<string, string | string[] | undefined> | undefined {
    return this.openIdConfiguration;
  }

  getUserInfoEndpoint(): string | undefined {
    return this.userInfoEndpoint;
  }

  getRegistrationEndpoint(): string | undefined {
    return this.registrationEndpoint;
  }

  async getUserInfo(accessToken: string): Promise<OIDCUserInfo | undefined> {
    const model = this.model as OIDCDeviceAuthorizationModel;
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
