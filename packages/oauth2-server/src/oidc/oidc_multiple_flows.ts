// TODO: multiple flows for OpenID Connect.
// ---
// It basically have a list of flows and
// a method "token()" that will check the grant type
// and call the appropriate flow's token method.
// The refresh token handler will be tried for all flows,
// and if one of them can handle it, it will be used.
// ---
// The token verification will also be tried for all flows,
// and if one of them can handle it, it will be used.
// ---
// This allows for a flexible implementation that can support multiple OpenID Connect flows
// (e.g., authorization code, client credentials, etc.) in a single server.
// So the order of the flows is important,
// and the first one that can handle the request will be used.
// A method for the openid configuration endpoint will also be needed,
// which will return the supported flows and their configuration.

import { OAuth2Error, OAuth2Errors } from "../errors.ts";
import { OAuth2FlowTokenResponse } from "../grants/flow.ts";
import { StrategyError, StrategyInternalError, StrategyResult } from "../strategy.ts";
import { getOriginFromUrl, normalizeUrl } from "../utils/url_tools.ts";
import { OIDCFlow } from "./types.ts";

export class OIDCMultipleFlows<TFlow extends OIDCFlow = OIDCFlow> {
  protected flows: TFlow[];
  protected discoveryUrl: string;
  protected openidConfiguration: Record<string, string | string[] | undefined>;
  protected tokenEndpoint = "/token";
  protected jwksEndpoint = "/jwks";
  protected securitySchemeName: string;
  protected description?: string;

  constructor(
    {
      flows,
      discoveryUrl,
      jwksEndpoint,
      openidConfiguration,
      tokenEndpoint,
      securitySchemeName,
      description,
    }: {
      flows: TFlow[];
      discoveryUrl: string;
      jwksEndpoint?: string;
      tokenEndpoint?: string;
      openidConfiguration?: Record<string, string | string[] | undefined>;
      securitySchemeName: string;
      description?: string;
    },
  ) {
    this.flows = [...flows];
    this.discoveryUrl = discoveryUrl;
    this.openidConfiguration = openidConfiguration || {};
    this.securitySchemeName = securitySchemeName;
    this.description = description;
    if (jwksEndpoint) this.jwksEndpoint = jwksEndpoint;
    if (tokenEndpoint) this.tokenEndpoint = tokenEndpoint;
  }

  getDiscoveryUrl(): string {
    return this.discoveryUrl;
  }

  getSecuritySchemeName(): string {
    return this.securitySchemeName;
  }

  getDescription(): string | undefined {
    return this.description;
  }

  async token(request: Request): Promise<OAuth2FlowTokenResponse> {
    const errors: OAuth2Error[] = [];
    for (const flow of this.flows) {
      const result = await flow.token(request);
      if (result.success) {
        return result;
      }
      errors.push(result.error);
    }
    return errors.length
      ? { success: false, error: new OAuth2Errors(errors) }
      : { success: false, error: new OAuth2Error("No flows available") };
  }

  async verifyToken(request: Request): Promise<StrategyResult> {
    const errors: StrategyError[] = [];
    for (const flow of this.flows) {
      const validation = await flow.verifyToken(request);
      if (validation.success) {
        return validation;
      }
      errors.push(validation.error);
    }
    return errors.length
      ? { success: false, error: new StrategyInternalError(errors) }
      : { success: false, error: new StrategyInternalError("No flows available") };
  }

  toOpenAPIPathItem(scopes?: string[]) {
    return {
      [this.getSecuritySchemeName()]: scopes || [],
    };
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
  getDiscoveryConfiguration(req?: Request): Record<string, string | string[] | undefined> {
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

    let wellKnownOpenIDConfig: {
      authorization_endpoint?: string;
      grant_types_supported: string[];
      token_endpoint_auth_methods_supported: string[];
      [key: string]: string | string[] | undefined;
    } = {
      issuer: `${host}`,
      authorization_endpoint: undefined,
      device_authorization_endpoint: undefined,
      token_endpoint: `${normalizeUrl(this.tokenEndpoint, host)}`,
      userinfo_endpoint: undefined,
      jwks_uri: this.jwksEndpoint ? `${normalizeUrl(this.jwksEndpoint, host)}` : undefined,
      registration_endpoint: undefined,
      grant_types_supported: [],
      token_endpoint_auth_methods_supported: [],
    };

    for (const flow of this.flows) {
      if (typeof flow.getDiscoveryConfiguration === "function") {
        const {
          issuer: _unused_issuer,
          token_endpoint: _unused_token_endpoint,
          jwks_uri: _unused_jwks_uri,
          ...more
        } = flow.getDiscoveryConfiguration(req);

        // merge properties
        wellKnownOpenIDConfig = {
          ...wellKnownOpenIDConfig,
          ...Object.fromEntries(
            Object.entries(more).map(([key, val]) => [
              key,
              // merge arrays and ensure unique values (Set)
              Array.isArray(wellKnownOpenIDConfig[key]) && Array.isArray(val)
                ? [...new Set([...wellKnownOpenIDConfig[key] as string[], ...val as string[]])]
                : val,
            ]),
          ),
        };
      }
    }

    const result = { ...wellKnownOpenIDConfig, ...this.openidConfiguration };

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
