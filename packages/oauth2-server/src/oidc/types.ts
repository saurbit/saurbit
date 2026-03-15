import { OAuth2Flow } from "../grants/flow.ts";

export interface OIDCFlowExtendedOptions {
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
  jwksEndpoint?: string;
  /**
   * Additional OpenID configuration parameters to include in the discovery document.
   * This allows for customization of the discovery document beyond the standard fields.
   * The provided configuration will be merged with the default values derived from the flow's settings.
   * This is useful for adding custom fields or overriding defaults when necessary.
   */
  openIdConfiguration?: Record<string, string | string[] | undefined>;
}

export interface OIDCFlow extends OAuth2Flow {
  /**
   * Retrieves the OpenID Connect discovery configuration.
   * @param req - Optional request object to help determine the full URL for relative endpoints in the discovery document. If not provided, relative endpoints will be resolved against the discovery URL's origin.
   * @returns The OpenID Connect discovery configuration.
   * @link https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata
   */
  getDiscoveryConfiguration(req?: Request): Record<string, string | string[] | undefined>;
}

export interface OIDCUserInfo {
  sub: string;
  [claim: string]: unknown;
}
