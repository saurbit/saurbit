import { OAuth2Flow } from "../grants/flow.ts";

/**
 * Additional constructor options shared by all OIDC flow implementations,
 * on top of the base {@link OAuth2Flow} options.
 */
export interface OIDCFlowExtendedOptions {
  /**
   * The URL where the OpenID Provider's discovery document can be found.
   * This is a required field and should point to the well-known OpenID configuration endpoint
   * (e.g., `https://example.com/.well-known/openid-configuration`).
   */
  discoveryUrl: string;

  /**
   * The URL where the OpenID Provider's JSON Web Key Set (JWKS) can be found.
   * Used for validating tokens issued by the provider. If not provided, it will be derived
   * from the discovery document.
   * Can be an absolute URL or a relative path (e.g. `"/jwks"`) resolved against the
   * discovery URL's origin.
   */
  jwksEndpoint?: string;

  /**
   * Additional OpenID configuration parameters to include in the discovery document.
   * The provided values are merged with the defaults derived from the flow's settings,
   * and take precedence over them. Useful for adding custom fields or overriding defaults.
   */
  openIdConfiguration?: Record<string, string | string[] | undefined>;
}

/**
 * Contract for OIDC-capable flow classes.
 *
 * Extends {@link OAuth2Flow} with the ability to produce an OpenID Connect
 * discovery configuration document, as required by
 * {@link https://openid.net/specs/openid-connect-discovery-1_0.html | OpenID Connect Discovery}.
 */
export interface OIDCFlow extends OAuth2Flow {
  /**
   * Retrieves the OpenID Connect discovery configuration.
   *
   * @param req - Optional request object used to determine the full base URL for
   *   resolving relative endpoint paths. If omitted, relative endpoints are resolved
   *   against the discovery URL's origin.
   * @returns The OpenID Connect discovery document fields.
   * @see https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata
   */
  getDiscoveryConfiguration(req?: Request): Record<string, string | string[] | undefined>;

  /**
   * Returns the discovery document URL.
   * @returns The discovery URL.
   */
  getDiscoveryUrl(): string;

  /**
   * Returns the JWKS endpoint URL.
   * @returns The JWKS endpoint URL.
   */
  getJwksEndpoint(): string | undefined;
}

/**
 * Represents the claims returned by the OpenID Connect UserInfo endpoint.
 *
 * @see https://openid.net/specs/openid-connect-core-1_0.html#UserInfoResponse
 */
export interface OIDCUserInfo {
  /** The subject identifier - a locally unique identifier for the end-user. */
  sub: string;

  /** Additional standard or custom claims returned by the UserInfo endpoint. */
  [claim: string]: unknown;
}
