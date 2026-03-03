import { ClientSecretBasic } from "../client_auth_methods/client_secret_basic.ts";
import type { OAuth2Model } from "../types.ts";
import { BearerTokenType } from "../token_types/bearer_token.ts";

/**
 * Handles the Client Credentials grant type.
 *
 * @see https://datatracker.ietf.org/doc/html/rfc6749#section-4.4
 */
export interface ClientCredentialsGrant {
  /** The grant type identifier. */
  readonly grantType: "client_credentials";
}

/**
 * @internal
 */
export class ClientCredentialsGrantImpl implements ClientCredentialsGrant {
  readonly grantType = "client_credentials" as const;
  readonly #model: OAuth2Model;

  constructor(model: OAuth2Model) {
    this.#model = model;
  }

  // TODO: implement client credentials exchange

  async token(request: Request): Promise<Response> {

    // TODO: support multiple token types, not just Bearer
    const tokenType = new BearerTokenType();

    if (request.method !== "POST") {
      return new Response("Method Not Allowed", { status: 405, headers: { "Allow": "POST" } });
    }

    if (!request.headers.get("content-type")?.includes("application/json")) {
      return new Response("Unsupported Media Type", { status: 415 });
    }

    const body: unknown = request.json ? await request.json() : null;
    const requestedParams: {
      grantType?: string;
      scopes?: string[];
    } = {};
    if (body && typeof body === 'object') {
      if ('grant_type' in body) {
        requestedParams.grantType = typeof body.grant_type === 'string' ? body.grant_type : undefined;
      }
      if ('scope' in body) {
        requestedParams.scopes = typeof body.scope === 'string' ? body.scope.split(' ') : [];
      }
    }

    // Validate that the grant type in the request body matches this grant type
    if (requestedParams.grantType !== this.grantType) {
      return new Response("Unsupported grant type", { status: 400 });
    }

    // Validate client metadata such as scopes, etc, ..., if applicable for client credentials grant
    const validatedParams = {
      grantType: requestedParams.grantType,
      scopes: requestedParams.scopes || [],
      tokenType: tokenType.prefix,
      // TODO: get it from client metadata or model configuration
      accessTokenLifetime: 3600
    };

    // Validate client authentication
    // TODO: support multiple client authentication methods, not just client_secret_basic
    const clientAuthMethod = new ClientSecretBasic();
    const { clientId, clientSecret, hasAuthMethod } = clientAuthMethod.extractClientCredentials(request);

    // If the request contains client authentication credentials, validate them
    if (hasAuthMethod) {

      // If clientId or clientSecret is missing, return 401 error
      if (!clientId || !clientSecret) {
        return new Response("Invalid client credentials", { status: 401 });
      }

      // Validate client credentials using the model's getClient() method
      const client = await this.#model.getClient(clientId, clientSecret, { ...requestedParams });

      // If client authentication fails, return 401 error
      if (!client) {
        return new Response("Invalid client credentials", { status: 401 });
      }

      // validate that client is allowed to use client credentials grant type
      if (!client.grants || !client.grants.includes(this.grantType)) {
        return new Response("Unauthorized client for this grant type", { status: 401 });
      }

      // Validate scope if provided in the request body (optional)
      if (requestedParams.scopes && client.scopes) {
        const allowedScopes = client.scopes ? client.scopes : [];
        validatedParams.scopes = requestedParams.scopes?.filter(scope => allowedScopes.includes(scope)) || [];
      }

      // generate access token and refresh token from client, valid scope, 
      // and any other relevant information, 
      // using the model's generateAccessToken() and generateRefreshToken() methods
      const accessToken = await this.#model.generateAccessToken?.(client, { ...validatedParams });
      const refreshToken = await this.#model.generateRefreshToken?.(client, { ...validatedParams });

      if (!accessToken) {
        return new Response("Failed to generate access token", { status: 500 });
      }

      const _responseBody = {
        access_token: accessToken,
        refresh_token: refreshToken ?? undefined,
        token_type: tokenType.prefix,
        expires_in: 3600,
        scope: requestedParams.scopes?.join(' ') || ''
      }
    }

    return new Response("Not implemented", { status: 501 });
  }
}
