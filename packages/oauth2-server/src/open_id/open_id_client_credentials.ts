import { AbstractClientCredentialsGrantFlow, ClientCredentialsGrantFlowOptions } from "../grants/client_credentials.ts";

/**
 * Options for configuring the client credentials grant flow.
 */
export interface OpenIDClientCredentialsGrantFlowOptions extends ClientCredentialsGrantFlowOptions {
  discoveryUrl: string;
  jwksUri?: string;
  openidConfiguration?: Record<string, string | string[] | undefined>;
}

export class OpenIDClientCredentialsGrantFlow extends AbstractClientCredentialsGrantFlow {
    protected discoveryUrl: string;
    protected jwksUri?: string;
    protected openidConfiguration?: Record<string, string | string[] | undefined>;

    constructor(options: OpenIDClientCredentialsGrantFlowOptions) {
        const { discoveryUrl, jwksUri, openidConfiguration, ...baseOptions } = options;
        super(baseOptions);
        this.discoveryUrl = discoveryUrl;
        this.jwksUri = jwksUri;
        this.openidConfiguration = openidConfiguration;
    }

    getDiscoveryUrl(): string {
        return this.discoveryUrl;
    }

    getJwksUri(): string | undefined {
        return this.jwksUri;
    }

    getOpenidConfiguration(): Record<string, string | string[] | undefined> | undefined {
        return this.openidConfiguration;
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
        if (jwksUri && /^\/(?!\/)/.test(jwksUri)) {
            jwksUri = `${host}${jwksUri}`;
        }
        // Format token endpoint if it's a relative path
        let tokenEndpoint = this.getTokenUrl();
        if (tokenEndpoint && /^\/(?!\/)/.test(tokenEndpoint)) {
            tokenEndpoint = `${host}${tokenEndpoint}`;
        }

        const wellKnownOpenIDConfig: Record<string, string | string[] | undefined> = {
            issuer: host,
            token_endpoint: tokenEndpoint,
            userinfo_endpoint: undefined, // irrelevant and typically not used in the client credentials flow
            jwks_uri: jwksUri,
            registration_endpoint: undefined,
            claims_supported: ['aud', 'exp', 'iat', 'iss', 'sub'],
            grant_types_supported: [this.grantType],
            response_types_supported: ['token'],
            scopes_supported: Object.keys(scopes),
            subject_types_supported: ['public'],
            id_token_signing_alg_values_supported: ['RS256'],
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

        const result = { ...wellKnownOpenIDConfig, ...(this.getOpenidConfiguration() || {}) };

        // Format unhandled endpoints
        if (typeof result.userinfo_endpoint === 'string' && /^\/(?!\/)/.test(result.userinfo_endpoint)) {
            result.userinfo_endpoint = `${host}${result.userinfo_endpoint}`;
        }
        if (typeof result.registration_endpoint === 'string' && /^\/(?!\/)/.test(result.registration_endpoint)) {
            result.registration_endpoint = `${host}${result.registration_endpoint}`;
        }

        return result;
    }
}