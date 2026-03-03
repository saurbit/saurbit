import type { OAuth2Client, OAuth2TokenResponseBody } from "../types.ts";
import { OAuth2AuthFlow, OAuth2AuthFlowOptions } from "./auth_flow.ts";

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
 * Validation context for client credentials grant, 
 * which can be used by the model's generateAccessToken() method
 * to generate tokens with appropriate scopes, lifetimes, etc.
 */
export interface ClientCredentialsGrantContext {
  grantType: string;
  scopes: string[];
  tokenType: string;
  accessTokenLifetime: number;
}

/**
 * Raw token request parameters for client credentials grant.
 */
export interface ClientCredentialsTokenRequest {
  clientId: string;
  clientSecret: string;
  grantType?: string;
  scopes?: string[];
}

/**
 * Model interface that must be implemented by the consuming application
 * to provide persistence for clients and tokens related to the client credentials grant.
 */
export interface ClientCredentialsModel {
  /**
   * Retrieve a client by its id (and optionally verify its secret).
   */
  getClient(tokenRequest: ClientCredentialsTokenRequest): Promise<OAuth2Client | undefined>;
  /**
   * Generate an access token for the client credentials grant.
   */
  generateAccessToken(context: ClientCredentialsGrantContext): Promise<string | undefined>;
}

/**
 * Options for configuring the client credentials grant flow.
 */
export interface ClientCredentialsGrantFlowOptions extends OAuth2AuthFlowOptions {
  model: ClientCredentialsModel;
}

export class ClientCredentialsGrantFlow extends OAuth2AuthFlow implements ClientCredentialsGrant {
  readonly grantType = "client_credentials" as const;
  readonly #model: ClientCredentialsModel;

  constructor(options: ClientCredentialsGrantFlowOptions) {
    const { model, ...flowOptions } = { ...options };
    super(flowOptions);
    this.#model = model;
  }

  /**
   * Handle a token request for the client credentials grant type.
   * Validates the client credentials and generates an access token if valid.
   * Returns an appropriate error response if validation fails.
   * @param request 
   * @returns 
   */
  async token(request: Request): Promise<OAuth2TokenResponseBody | Response> {

    if (request.method !== "POST") {
      return new Response("Method Not Allowed", { status: 405, headers: { "Allow": "POST" } });
    }

    if (!request.headers.get("content-type")?.includes("application/json")) {
      return new Response("Unsupported Media Type", { status: 415 });
    }

    const body: unknown = request.json ? await request.json() : null;
    let grantTypeInBody: string | undefined;
    let scopesInBody: string[] | undefined;

    if (body && typeof body === 'object') {
      if ('grant_type' in body) {
        grantTypeInBody = typeof body.grant_type === 'string' ? body.grant_type : undefined;
      }
      if ('scope' in body) {
        scopesInBody = typeof body.scope === 'string' ? body.scope.split(' ') : undefined;
      }
    }

    // Validate that the grant type in the request body matches this grant type
    if (grantTypeInBody !== this.grantType) {
      return new Response("Unsupported grant type", { status: 400 });
    }

    // Validate client authentication credentials using the registered client authentication methods
    const { clientId, clientSecret, error } = await this.extractClientCredentials(
      request,
      this.clientAuthMethods,
      this.getTokenEndpointAuthMethods()
    );

    // If the request contains client authentication credentials, validate them
    if (!error) {

      // If clientId or clientSecret is missing, return 401 error
      if (!clientId || !clientSecret) {
        return new Response("Invalid client credentials", { status: 401 });
      }

      const tokenRequest: ClientCredentialsTokenRequest = {
        clientId,
        clientSecret,
        grantType: grantTypeInBody,
        scopes: scopesInBody
      };

      // Validate client credentials using the model's getClient() method
      const client = await this.#model.getClient(
        // avoid mutation
        { ...tokenRequest, scopes: tokenRequest.scopes ? [...tokenRequest.scopes] : [] }
      );

      // If client authentication fails, return 401 error
      if (!client) {
        return new Response("Invalid client credentials", { status: 401 });
      }

      // validate that client is allowed to use client credentials grant type
      if (!client.grants || !client.grants.includes(this.grantType)) {
        return new Response("Unauthorized client for this grant type", { status: 401 });
      }

      // Validate scope if provided in the request body (optional)
      let validatedScopes: string[];
      if (tokenRequest.scopes && client.scopes) {
        const allowedScopes = client.scopes ? client.scopes : [];
        validatedScopes = tokenRequest.scopes?.filter(scope => allowedScopes.includes(scope)) || [];
      } else {
        validatedScopes = [];
      }

      // Validate client metadata such as scopes, etc, ..., if applicable for client credentials grant
      const grantContext: ClientCredentialsGrantContext = {
        grantType: grantTypeInBody,
        scopes: validatedScopes,
        tokenType: this.tokenType,
        accessTokenLifetime: this.accessTokenLifetime
      };

      // generate access token from client, valid scope, 
      // and any other relevant information, 
      // using the model's generateAccessToken() and generateRefreshToken() methods
      const accessToken = await this.#model.generateAccessToken?.(
        // avoid mutation
        { ...grantContext, scopes: [...grantContext.scopes] }
      );

      // If token generation fails
      if (!accessToken) {
        return new Response("Failed to generate access token", { status: 500 });
      }

      return {
        access_token: accessToken,
        token_type: this.tokenType,
        expires_in: grantContext.accessTokenLifetime,
        scope: grantContext.scopes.join(' ')
      }
    }

    return new Response("Not implemented", { status: 501 });
  }
}
