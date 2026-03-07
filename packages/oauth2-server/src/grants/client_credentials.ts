// grants/client_credentials.ts

import {
  InvalidClientError,
  InvalidRequestError,
  ServerError,
  UnauthorizedClientError,
  UnsupportedGrantTypeError,
} from "../errors.ts";
import { TokenTypeValidationResponse } from "../token_types/types.ts";
import type { OAuth2Client } from "../types.ts";
import {
  OAuth2AuthFlow,
  type OAuth2AuthFlowOptions,
  type OAuth2AuthFlowTokenResponse,
  type OAuth2GrantModel,
} from "./auth_flow.ts";

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
 * to generate tokens with appropriate scope, lifetimes, etc.
 */
export interface ClientCredentialsGrantContext {
  client: OAuth2Client;
  grantType: string;
  scope: string[];
  tokenType: string;
  accessTokenLifetime: number;
}

/**
 * Raw token request parameters for client credentials grant.
 */
export interface ClientCredentialsTokenRequest {
  clientId: string;
  clientSecret: string;
  grantType: string;
  scope?: string[];
}

/**
 * Model interface that must be implemented by the consuming application
 * to provide persistence for clients and tokens related to the client credentials grant.
 */
export interface ClientCredentialsModel
  extends OAuth2GrantModel<ClientCredentialsTokenRequest, ClientCredentialsGrantContext> {}

/**
 * Options for configuring the client credentials grant flow.
 */
export interface ClientCredentialsGrantFlowOptions extends OAuth2AuthFlowOptions {
  model: ClientCredentialsModel;
}

export abstract class AbstractClientCredentialsGrantFlow extends OAuth2AuthFlow implements ClientCredentialsGrant {
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
   * @param request The incoming HTTP request.
   */
  async token(request: Request): Promise<OAuth2AuthFlowTokenResponse> {
    const req = request.clone();
    if (req.method !== "POST") {
      return { success: false, error: new InvalidRequestError("Method Not Allowed") };
    }

    let body: unknown;
    let grantTypeInBody: string | undefined;
    let scopeInBody: string[] | undefined;
    const contentType = req.headers.get("content-type") || "";

    if (contentType.includes("application/x-www-form-urlencoded")) {
      const form = await req.formData();
      body = {
        grant_type: form.get("grant_type"),
        scope: form.get("scope"),
      };
    } else if (contentType.includes("application/json")) {
      body = req.json ? await req.json() : null;
    } else {
      return { success: false, error: new InvalidRequestError("Unsupported Media Type") };
    }

    if (body && typeof body === "object") {
      if ("grant_type" in body) {
        grantTypeInBody = typeof body.grant_type === "string" ? body.grant_type : undefined;
      }
      if ("scope" in body) {
        scopeInBody = typeof body.scope === "string" ? body.scope.split(" ") : undefined;
      }
    }

    // Validate that the grant type in the request body matches this grant type
    if (grantTypeInBody !== this.grantType) {
      return { success: false, error: new UnsupportedGrantTypeError("Unsupported grant type") };
    }

    // Validate client authentication credentials using the registered client authentication methods
    const { clientId, clientSecret, error } = await this.extractClientCredentials(
      request.clone(),
      this.clientAuthMethods,
      this.getTokenEndpointAuthMethods(),
    );

    // If the request contains client authentication credentials, validate them
    if (!error) {
      // If clientId or clientSecret is missing, return 401 error
      if (!clientId || !clientSecret) {
        return { success: false, error: new InvalidClientError("Invalid client credentials") };
      }

      // e.g. for DPoP token type, we need to validate the token request before validating client credentials
      const tokenTypeValidationResponse: TokenTypeValidationResponse =
        this._tokenType.isValidTokenRequest
          ? await this._tokenType.isValidTokenRequest(request.clone())
          : { isValid: true };
      if (!tokenTypeValidationResponse.isValid) {
        return {
          success: false,
          error: new InvalidRequestError(
            tokenTypeValidationResponse.message || "Invalid token request",
          ),
        };
      }

      const tokenRequest: ClientCredentialsTokenRequest = {
        clientId,
        clientSecret,
        grantType: grantTypeInBody,
        scope: scopeInBody,
      };

      // Validate client credentials using the model's getClient() method
      const client = await this.#model.getClient(
        // avoid mutation
        { ...tokenRequest, scope: tokenRequest.scope ? [...tokenRequest.scope] : [] },
      );

      // If client authentication fails, return 401 error
      if (!client) {
        return { success: false, error: new InvalidClientError("Invalid client credentials") };
      }

      // validate that client is allowed to use client credentials grant type
      if (!client.grants || !client.grants.includes(this.grantType)) {
        return {
          success: false,
          error: new UnauthorizedClientError("Unauthorized client for this grant type"),
        };
      }

      // Validate scope if provided in the request body (optional)
      let validatedScopes: string[];
      if (tokenRequest.scope && client.scopes) {
        const allowedScopes = client.scopes ? client.scopes : [];
        validatedScopes = tokenRequest.scope?.filter((scope) => allowedScopes.includes(scope)) ||
          [];
      } else {
        validatedScopes = [];
      }

      // Validate client metadata such as scope, etc, ..., if applicable for client credentials grant
      const grantContext: ClientCredentialsGrantContext = {
        client: client,
        grantType: grantTypeInBody,
        scope: validatedScopes,
        tokenType: this.tokenType,
        accessTokenLifetime: this.accessTokenLifetime,
      };

      // generate access token from client, valid scope,
      // and any other relevant information,
      // using the model's generateAccessToken() and generateRefreshToken() methods
      const accessTokenResult = await this.#model.generateAccessToken?.(
        // avoid mutation
        { ...grantContext, scope: [...grantContext.scope] },
      );

      // If token generation fails
      if (!accessTokenResult) {
        return { success: false, error: new ServerError("Failed to generate access token") };
      }

      return {
        success: true,
        tokenResponse: {
          access_token: typeof accessTokenResult === "string"
            ? accessTokenResult
            : accessTokenResult.accessToken,
          token_type: this.tokenType,
          expires_in: grantContext.accessTokenLifetime,
          scope: grantContext.scope.length > 0 ? grantContext.scope.join(" ") : undefined,
        },
      };
    }

    return { success: false, error };
  }
}

export class ClientCredentialsGrantFlow extends AbstractClientCredentialsGrantFlow {
  toOpenAPISecurityScheme() {
    return {
      [this.getSecuritySchemeName()]: {
        type: "oauth2" as const,
        description: this.getDescription(),
        flows: {
          clientCredentials: {
            scopes: { ...(this.getScopes() || {}) },
            tokenUrl: this.getTokenUrl(),
          },
        },
      },
    };
  }
}
