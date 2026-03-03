import {
  InvalidClientError, 
  InvalidRequestError, 
  ServerError, 
  UnauthorizedClientError, 
  UnsupportedGrantTypeError 
} from "../errors.ts";
import { evaluateStrategy, StrategyOptions, StrategyResult } from "../strategy.ts";
import type { OAuth2Client } from "../types.ts";
import { OAuth2AuthFlow, OAuth2AuthFlowOptions, OAuth2AuthFlowTokenResponse } from "./auth_flow.ts";

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
  strategyOptions: StrategyOptions;
}

export class ClientCredentialsGrantFlow extends OAuth2AuthFlow implements ClientCredentialsGrant {
  readonly grantType = "client_credentials" as const;
  readonly #model: ClientCredentialsModel;
  readonly #strategyOptions: StrategyOptions;

  constructor(options: ClientCredentialsGrantFlowOptions) {
    const { model, strategyOptions, ...flowOptions } = { ...options };
    super(flowOptions);
    this.#model = model;
    this.#strategyOptions = strategyOptions;
  }

  /**
   * Handle a token request for the client credentials grant type.
   * Validates the client credentials and generates an access token if valid.
   * Returns an appropriate error response if validation fails.
   * @param request The incoming HTTP request. 
   */
  async token(request: Request): Promise<OAuth2AuthFlowTokenResponse> {

    if (request.method !== "POST") {
      return { success: false, error: new InvalidRequestError("Method Not Allowed") };
    }

    if (!request.headers.get("content-type")?.includes("application/json")) {
      return { success: false, error: new InvalidRequestError("Unsupported Media Type") };
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
      return { success: false, error: new UnsupportedGrantTypeError("Unsupported grant type") };
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
        return { success: false, error: new InvalidClientError("Invalid client credentials") };
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
        return { success: false, error: new InvalidClientError("Invalid client credentials") };
      }

      // validate that client is allowed to use client credentials grant type
      if (!client.grants || !client.grants.includes(this.grantType)) {
        return { success: false, error: new UnauthorizedClientError("Unauthorized client for this grant type") };
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
        return { success: false, error: new ServerError("Failed to generate access token") };
      }

      return {
        success: true,
        data: {
          access_token: accessToken,
          token_type: this.tokenType,
          expires_in: grantContext.accessTokenLifetime,
          scope: grantContext.scopes.join(' ')
        }
      };
    }

    return { success: false, error: new ServerError("Not implemented") };
  }

  /**
   * Verifies the token grants access
   * @param request
   */
  async authorize(request: Request): Promise<StrategyResult> {
    return await evaluateStrategy(request, this.#strategyOptions);
  }
}
