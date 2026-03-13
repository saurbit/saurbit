import {
  AbstractClientCredentialsFlow,
  ClientCredentialsFlowOptions,
} from "../grants/client_credentials.ts";
import { normalizeUrl } from "../utils/normalize_url.ts";
import { OIDCFlow, OIDCFlowExtendedOptions } from "./types.ts";

/**
 * Options for configuring the client credentials grant flow.
 */
export interface OIDCClientCredentialsFlowOptions
  extends ClientCredentialsFlowOptions, OIDCFlowExtendedOptions {
}

export class OIDCClientCredentialsFlow extends AbstractClientCredentialsFlow implements OIDCFlow {
  protected discoveryUrl: string;
  protected jwksEndpoint?: string;
  protected openIdConfiguration?: Record<string, string | string[] | undefined>;

  constructor(options: OIDCClientCredentialsFlowOptions) {
    const { discoveryUrl, jwksEndpoint, openIdConfiguration, ...baseOptions } = options;
    super(baseOptions);
    this.discoveryUrl = discoveryUrl;
    this.jwksEndpoint = jwksEndpoint;
    this.openIdConfiguration = openIdConfiguration;
  }

  protected normalizeUrl(url: string, origin?: string): string {
    return normalizeUrl(url, origin || new URL(this.discoveryUrl).origin);
  }

  getDiscoveryUrl(): string {
    return this.discoveryUrl;
  }

  getJwksUri(): string | undefined {
    return this.jwksEndpoint;
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

    const host = typeof fullUrl === "string" ? fullUrl : new URL(this.getDiscoveryUrl()).origin;

    // Format jwks_uri if it's a relative path
    let jwksEndpoint = this.getJwksUri();
    if (jwksEndpoint) {
      jwksEndpoint = this.normalizeUrl(jwksEndpoint, host);
    }
    // Format token endpoint if it's a relative path
    let tokenEndpoint = this.getTokenEndpoint();
    if (tokenEndpoint) {
      tokenEndpoint = this.normalizeUrl(tokenEndpoint, host);
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
      result.userinfo_endpoint = this.normalizeUrl(result.userinfo_endpoint, host);
    }
    if (typeof result.registration_endpoint === "string") {
      result.registration_endpoint = this.normalizeUrl(result.registration_endpoint, host);
    }

    return result;
  }
}
