/**
 * @module oidc_client_credentials
 * @description OpenID Connect extension of the Client Credentials grant flow.
 * Adds OIDC discovery document generation and `openIdConnect` security scheme
 * support to the base {@link AbstractClientCredentialsFlow}.
 * Note: the Client Credentials flow is machine-to-machine and does not involve
 * end-user authentication, so ID tokens and UserInfo endpoints are typically not used.
 */

import {
  AbstractClientCredentialsFlow,
  ClientCredentialsFlowOptions,
} from "../grants/client_credentials.ts";
import { getOriginFromRequest, getOriginFromUrl, normalizeUrl } from "../utils/url_tools.ts";
import { OIDCFlow, OIDCFlowExtendedOptions } from "./types.ts";

/**
 * Configuration options for the OIDC Client Credentials flow.
 * Combines the base client credentials options with OIDC-specific options
 * such as the discovery URL, optional JWKS endpoint, and static OpenID configuration overrides.
 */
export interface OIDCClientCredentialsFlowOptions
  extends ClientCredentialsFlowOptions, OIDCFlowExtendedOptions {
}

/**
 * OpenID Connect Client Credentials flow implementation.
 *
 * Extends {@link AbstractClientCredentialsFlow} with OIDC capabilities:
 * - Generates an OIDC discovery document via `getDiscoveryConfiguration()`.
 * - Implements `toOpenAPISecurityScheme()` with the `openIdConnect` scheme type.
 *
 * Because the Client Credentials grant is purely machine-to-machine, this flow
 * does not issue ID tokens or expose a UserInfo endpoint. The discovery document
 * is provided for completeness and interoperability with OIDC-aware clients.
 */
export class OIDCClientCredentialsFlow extends AbstractClientCredentialsFlow implements OIDCFlow {
  protected discoveryUrl: string;
  protected jwksEndpoint?: string;
  protected openIdConfiguration?: Record<string, string | string[] | undefined>;

  /**
   * Creates a new `OIDCClientCredentialsFlow` instance.
   * @param options - Configuration options including the discovery URL and optional JWKS endpoint.
   */
  constructor(options: OIDCClientCredentialsFlowOptions) {
    const { discoveryUrl, jwksEndpoint, openIdConfiguration, ...baseOptions } = options;
    super(baseOptions);
    this.discoveryUrl = discoveryUrl;
    this.jwksEndpoint = jwksEndpoint;
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
   * Returns the JWKS endpoint URL used for token validation, if configured.
   * May be an absolute URL or a relative path resolved against the discovery URL's origin.
   * @returns The JWKS endpoint URL, or `undefined` if not set.
   */
  getJwksEndpoint(): string | undefined {
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
      fullUrl = getOriginFromRequest(req);
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

    const wellKnownOpenIDConfig: Record<string, string | string[] | undefined> = {
      issuer: host,
      token_endpoint: tokenEndpoint,
      jwks_uri: jwksEndpoint,
      // irrelevant and typically not used in the client credentials flow.
      userinfo_endpoint: undefined,
      registration_endpoint: undefined,
      claims_supported: undefined,
      grant_types_supported: [this.grantType],
      // Because this is an OIDC flow, response_types_supported is required in the discovery document,
      // even if it's not used in client credentials flow.
      // "code" is a common value to include here as it is the most widely supported response type in OIDC.
      response_types_supported: ["code"],
      scopes_supported: Object.keys(scopes),
      // The client credentials flow typically does not involve user authentication,
      // so "public" is the most relevant subject type.
      subject_types_supported: ["public"],
      // The id_token_signing_alg_values_supported field is required in OIDC discovery documents.
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
}
