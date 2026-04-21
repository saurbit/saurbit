/**
 * @module
 *
 * Provides {@link OIDCMultipleFlows}, a composite OIDC flow that aggregates multiple
 * individual flows (e.g. Authorization Code, Client Credentials, Device Authorization)
 * behind a single token endpoint, token verification method, and OpenID Connect
 * discovery document.
 *
 * Grant type dispatch: `token()` inspects the incoming request and delegates to the
 * first flow that accepts it. Refresh token and token verification are tried against
 * all registered flows in order.
 *
 * The order of flows passed to the constructor matters: the first flow able to
 * handle a request wins.
 */

import { OAuth2Error, OAuth2Errors } from "../errors.ts";
import { OAuth2FlowTokenResponse } from "../grants/flow.ts";
import { StrategyError, StrategyInternalError, StrategyResult } from "../strategy.ts";
import { getOriginFromRequest, getOriginFromUrl, normalizeUrl } from "../utils/url_tools.ts";
import { OIDCFlow } from "./types.ts";

/**
 * Aggregates multiple OIDC flows into a single handler that exposes a unified
 * token endpoint, token verification, and OpenID Connect discovery document.
 *
 * @template TFlow - The concrete OIDC flow type. Defaults to {@link OIDCFlow}.
 *
 * @example
 * ```ts
 * const flows = new OIDCMultipleFlows({
 *   securitySchemeName: "oidc",
 *   discoveryUrl: "/.well-known/openid-configuration",
 *   flows: [authorizationCodeFlow, clientCredentialsFlow],
 * });
 * ```
 */
export class OIDCMultipleFlows<TFlow extends OIDCFlow = OIDCFlow> {
  protected flows: TFlow[];
  protected discoveryUrl: string;
  protected openidConfiguration: Record<string, string | string[] | undefined>;
  protected tokenEndpoint = "/token";
  protected jwksEndpoint = "/jwks";
  protected securitySchemeName: string;
  protected description?: string;

  /**
   * Creates a new `OIDCMultipleFlows` instance.
   *
   * @param options.flows - Ordered list of OIDC flows to delegate to.
   * @param options.discoveryUrl - URL of the OpenID Connect discovery document
   *   (e.g. `"/.well-known/openid-configuration"`).
   * @param options.securitySchemeName - Name of the OpenAPI security scheme entry.
   * @param options.jwksEndpoint - URL of the JWKS endpoint. Defaults to `"/jwks"`.
   * @param options.tokenEndpoint - URL of the token endpoint. Defaults to `"/token"`.
   * @param options.openidConfiguration - Optional overrides merged into the discovery document.
   * @param options.description - Optional human-readable description for the OpenAPI security scheme.
   */
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

  /**
   * Returns the URL of the OpenID Connect discovery document.
   */
  getDiscoveryUrl(): string {
    return this.discoveryUrl;
  }

  /**
   * Returns the OpenAPI security scheme name for this set of flows.
   */
  getSecuritySchemeName(): string {
    return this.securitySchemeName;
  }

  /**
   * Returns the optional human-readable description for the OpenAPI security scheme.
   */
  getDescription(): string | undefined {
    return this.description;
  }

  /**
   * Handles an incoming token request by trying each registered flow in order.
   * The first flow that returns a successful result is used.
   * If no flow succeeds, returns a combined error from all flows.
   *
   * @param request - The incoming token endpoint HTTP request.
   * @returns The token response from the first matching flow, or a failure with all errors.
   */
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

  /**
   * Verifies an access token by trying each registered flow in order.
   * The first flow that successfully verifies the token is used.
   * If no flow succeeds, returns a combined error from all flows.
   *
   * @param request - The incoming HTTP request containing the `Authorization` header.
   * @returns The strategy result from the first flow that accepts the token, or a failure.
   */
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

  /**
   * Returns the OpenAPI path item security requirement object for this set of flows.
   *
   * @param scopes - Optional list of required scopes.
   * @returns An object keyed by the security scheme name with the required scopes.
   */
  toOpenAPIPathItem(scopes?: string[]): Record<string, string[]> {
    return {
      [this.getSecuritySchemeName()]: scopes || [],
    };
  }

  /**
   * Returns the OpenAPI security scheme definition for this set of flows.
   * Uses the `openIdConnect` scheme type pointing to the discovery URL.
   *
   * @returns An object keyed by the security scheme name with the scheme definition.
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
   * Retrieves the OpenID Connect discovery configuration by merging the configurations
   * of all registered flows. Array-valued fields (e.g. `grant_types_supported`) are
   * merged and deduplicated. Static overrides set via `openidConfiguration` take
   * precedence over flow-derived values.
   *
   * @param req - Optional request object used to determine the full base URL for
   *   resolving relative endpoint paths. If omitted, the origin is derived from
   *   `discoveryUrl`.
   * @returns The merged OpenID Connect discovery document.
   * @see https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata
   */
  getDiscoveryConfiguration(req?: Request): Record<string, string | string[] | undefined> {
    let fullUrl: string | undefined;
    if (req) {
      fullUrl = getOriginFromRequest(req);
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
