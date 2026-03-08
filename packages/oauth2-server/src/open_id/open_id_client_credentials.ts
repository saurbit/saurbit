import {
  AbstractClientCredentialsGrantFlow,
  ClientCredentialsGrantFlowOptions,
} from "../grants/client_credentials.ts";

/**
 * Options for configuring the client credentials grant flow.
 */
export interface OpenIDClientCredentialsGrantFlowOptions extends ClientCredentialsGrantFlowOptions {
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
  jwksUri?: string;
  /**
   * Additional OpenID configuration parameters to include in the discovery document.
   * This allows for customization of the discovery document beyond the standard fields.
   * The provided configuration will be merged with the default values derived from the flow's settings.
   * This is useful for adding custom fields or overriding defaults when necessary.
   */
  openIdConfiguration?: Record<string, string | string[] | undefined>;
}

export class OpenIDClientCredentialsGrantFlow extends AbstractClientCredentialsGrantFlow {
  protected discoveryUrl: string;
  protected jwksUri?: string;
  protected openIdConfiguration?: Record<string, string | string[] | undefined>;

  constructor(options: OpenIDClientCredentialsGrantFlowOptions) {
    const { discoveryUrl, jwksUri, openIdConfiguration, ...baseOptions } = options;
    super(baseOptions);
    this.discoveryUrl = discoveryUrl;
    this.jwksUri = jwksUri;
    this.openIdConfiguration = openIdConfiguration;
  }

  protected normalizeUrl(url: string, origin?: string): string {
    if (url && /^\/(?!\/)/.test(url)) {
      // Relative path, resolve against discovery URL's origin
      const resolvedOrigin = origin || new URL(this.discoveryUrl).origin;
      return `${resolvedOrigin}${url}`;
    }
    return url;
  }

  getDiscoveryUrl(): string {
    return this.discoveryUrl;
  }

  getJwksUri(): string | undefined {
    return this.jwksUri;
  }

  getOpenIdConfiguration(): Record<string, string | string[] | undefined> | undefined {
    return this.openIdConfiguration;
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

    const wellKnownOpenIDConfig: Record<string, string | string[] | undefined> = {
      issuer: host,
      token_endpoint: tokenEndpoint,
      userinfo_endpoint: undefined, // irrelevant and typically not used in the client credentials flow
      jwks_uri: jwksUri,
      registration_endpoint: undefined,
      claims_supported: ["aud", "exp", "iat", "iss", "sub"],
      grant_types_supported: [this.grantType],
      response_types_supported: ["token"],
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
}
