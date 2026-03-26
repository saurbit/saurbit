/**
 * @module oidc_device_authorization
 * @description OpenID Connect extension of the Device Authorization Grant flow (RFC 8628).
 * Adds ID token enforcement, UserInfo endpoint support, and OIDC discovery document generation
 * to the base {@link AbstractDeviceAuthorizationFlow}.
 */

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

/**
 * Extends the base device authorization access token result with an OIDC ID token.
 * The ID token is required for all device authorization token responses when the
 * `openid` scope is requested.
 * @see https://openid.net/specs/openid-connect-core-1_0.html#TokenEndpoint
 */
export interface OIDCDeviceAuthorizationAccessTokenResult
  extends DeviceAuthorizationAccessTokenResult {
  /**
   * The OIDC ID token returned from the token endpoint when exchanging the device code
   * for tokens. Must be included in the token response to the client.
   * @see https://openid.net/specs/openid-connect-core-1_0.html#TokenEndpoint
   */
  idToken: string;
}

/**
 * Model interface for the OIDC Device Authorization flow.
 * Extends the base {@link DeviceAuthorizationModel} with an optional UserInfo retrieval method
 * and requires `generateAccessToken` to return an ID token in the result.
 */
export interface OIDCDeviceAuthorizationModel extends DeviceAuthorizationModel {
  /**
   * Generates an access token (and required ID token) for the device authorization grant.
   * The result must include an `idToken` field when the `openid` scope is present.
   */
  generateAccessToken: OAuth2GenerateAccessTokenFunction<
    DeviceAuthorizationGrantContext,
    OIDCDeviceAuthorizationAccessTokenResult | DeviceAuthorizationAccessTokenError
  >;

  /**
   * Retrieves the user information associated with the given access token.
   * This method can be implemented to provide user information
   * for the UserInfo endpoint in the OpenID Connect flow.
   * @param accessToken The access token for which to retrieve user information.
   * @returns The user info object, or `undefined` if not available.
   */
  getUserInfo?: (
    accessToken: string,
  ) => Promise<OIDCUserInfo | undefined> | OIDCUserInfo | undefined;
}

/**
 * Configuration options for the {@link OIDCDeviceAuthorizationFlow}.
 * Extends the base device authorization options with OIDC-specific endpoints
 * required for discovery, token validation, and user info.
 */
export interface OIDCDeviceAuthorizationFlowOptions
  extends DeviceAuthorizationFlowOptions, OIDCFlowExtendedOptions {
  /** The OIDC-aware model providing token generation and optional user info callbacks. */
  model: OIDCDeviceAuthorizationModel;

  /**
   * The URL where the OpenID Provider's JSON Web Key Set (JWKS) can be retrieved.
   * Used to validate tokens issued by the provider. May be an absolute URL or a
   * relative path (e.g. `/jwks`) resolved against the discovery URL's origin.
   */
  jwksEndpoint: string;

  /**
   * The URL of the UserInfo endpoint. If provided, it will be included in the
   * OIDC discovery document. May be an absolute URL or a relative path.
   */
  userInfoEndpoint?: string;

  /**
   * The URL of the dynamic client registration endpoint. If provided, it will be
   * included in the OIDC discovery document. May be an absolute URL or a relative path.
   */
  registrationEndpoint?: string;
}

/**
 * OpenID Connect Device Authorization flow implementation.
 *
 * Extends {@link AbstractDeviceAuthorizationFlow} with OIDC capabilities:
 * - Enforces the presence of an `id_token` in token responses when the `openid` scope is requested.
 * - Exposes a `getUserInfo()` method backed by the model for the UserInfo endpoint.
 * - Generates an OIDC discovery document via `getDiscoveryConfiguration()`.
 * - Implements `toOpenAPISecurityScheme()` with the `openIdConnect` type.
 * - Ensures the `openid` scope is always present when listing supported scopes.
 */
export class OIDCDeviceAuthorizationFlow extends AbstractDeviceAuthorizationFlow
  implements OIDCFlow {
  protected discoveryUrl: string;
  protected jwksEndpoint: string;
  protected userInfoEndpoint?: string;
  protected registrationEndpoint?: string;
  protected openIdConfiguration?: Record<string, string | string[] | undefined>;

  /**
   * Creates a new `OIDCDeviceAuthorizationFlow` instance.
   * @param options - Configuration options including OIDC-specific endpoints and the model.
   */
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

  /**
   * Returns the OIDC discovery document URL (the `/.well-known/openid-configuration` endpoint).
   * @returns The discovery URL as configured.
   */
  getDiscoveryUrl(): string {
    return this.discoveryUrl;
  }

  /**
   * Returns the JWKS endpoint URL used for token validation.
   * @returns The JWKS endpoint URL as configured.
   */
  getJwksEndpoint(): string {
    return this.jwksEndpoint;
  }

  /**
   * Returns any static OpenID Connect configuration overrides that will be merged into
   * the discovery document produced by {@link getDiscoveryConfiguration}.
   * @returns The static OpenID configuration map, or `undefined` if none was provided.
   */
  getOpenIdConfiguration(): Record<string, string | string[] | undefined> | undefined {
    return this.openIdConfiguration;
  }

  /**
   * Returns the UserInfo endpoint URL, if configured.
   * @returns The UserInfo endpoint URL, or `undefined` if not set.
   */
  getUserInfoEndpoint(): string | undefined {
    return this.userInfoEndpoint;
  }

  /**
   * Returns the dynamic client registration endpoint URL, if configured.
   * @returns The registration endpoint URL, or `undefined` if not set.
   */
  getRegistrationEndpoint(): string | undefined {
    return this.registrationEndpoint;
  }

  /**
   * Retrieves the user info for the given access token by delegating to the model's
   * `getUserInfo` method, if implemented.
   * @param accessToken - The access token to look up.
   * @returns A promise resolving to the {@link OIDCUserInfo} claims, or `undefined`.
   */
  async getUserInfo(accessToken: string): Promise<OIDCUserInfo | undefined> {
    const model = this.model as OIDCDeviceAuthorizationModel;
    if (typeof model.getUserInfo === "function") {
      return await model.getUserInfo(accessToken);
    }
    return undefined;
  }

  /**
   * Returns the OpenAPI security scheme descriptor for this flow using the
   * `openIdConnect` scheme type, referencing the discovery URL.
   * @returns A record keyed by the security scheme name.
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

  /**
   * Returns the scopes supported by this flow, always including the `openid` scope
   * required by the OpenID Connect specification.
   * @returns The merged scopes map with `openid` guaranteed to be present.
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
   * Handles the token endpoint request for the OIDC Device Authorization flow.
   * Delegates to the base implementation and then enforces OIDC requirements:
   * - The `openid` scope must be present in the token response.
   * - An `id_token` must be present in the token response (except for refresh token grants,
   *   where it is optional per the OIDC specification).
   * @param request - The incoming HTTP request to the token endpoint.
   * @returns A promise resolving to the token response, or an error if OIDC requirements are not met.
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
          error: new ServerError(
            "ID Token is required for OpenID Connect device authorization flow",
          ),
        };
      }
    }
    return r;
  }
}
