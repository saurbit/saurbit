import {
  InvalidClientError,
  InvalidRequestError,
  OAuth2Error,
  ServerError,
  UnauthorizedClientError,
  UnsupportedGrantTypeError,
} from "../errors.ts";
import { TokenTypeValidationResponse } from "../token_types/types.ts";
import type { OAuth2Client } from "../types.ts";
import {
  OAuth2AuthFlow,
  OAuth2AuthFlowOptions,
  OAuth2AuthFlowTokenResponse,
  OAuth2GrantModel,
} from "./auth_flow.ts";

/**
 * Handles the Authorization Code grant type.
 *
 * @see https://datatracker.ietf.org/doc/html/rfc6749#section-4.1
 */
export interface AuthorizationCodeGrant {
  /** The grant type identifier. */
  readonly grantType: "authorization_code";
}

/**
 * Validation context for authorization code grant,
 * which can be used by the model's generateAccessToken() method
 * to generate tokens with appropriate scopes, lifetimes, etc.
 */
export interface AuthorizationCodeGrantContext {
  client: OAuth2Client;
  grantType: string;
  tokenType: string;
  accessTokenLifetime: number;
  code: string;
  codeVerifier?: string;
  redirectUri?: string;
}

/**
 * Raw token request parameters for authorization code grant.
 */
export interface AuthorizationCodeTokenRequest {
  clientId: string;
  grantType: string;
  code: string;
  codeVerifier?: string;
  clientSecret?: string;
  redirectUri?: string;
}

/**
 * Validation context for authorization code authentication (authorization endpoint request),
 * which can be used by the model's generateAuthorizationCode() method
 * to generate an authorization code with appropriate scopes, etc.
 */
export interface AuthorizationCodeEndpointContext {
  client: OAuth2Client;
  responseType: "code"; // should be "code" for authorization code grant
  redirectUri: string;
  scopes: string[];
  state?: string;
  codeChallenge?: string;
  nonce?: string;
}

/**
 * Raw authentication request parameters for authorization code grant.
 */
export interface AuthorizationCodeEndpointRequest {
  clientId: string;
  responseType: "code"; // should be "code" for authorization code grant
  redirectUri: string;
  scopes?: string[];
  state?: string;
  codeChallenge?: string;
  nonce?: string;
}

export interface AuthorizationCodeEndpointResponseParams {
  client: OAuth2Client;
  redirectUri: string;
  scopes: string[];
  code: string;
  state?: string;
  error?: never;
  [key: string]: unknown;
}

export type AuthorizationCodeEndpointResponse =
  | { success: true }
  | { success: true; codeResponse: AuthorizationCodeEndpointResponseParams }
  | { success: false; error: OAuth2Error; state?: string };

/**
 * Model interface that must be implemented by the consuming application
 * to provide persistence for clients and tokens related to the authorization code grant.
 */
export interface AuthorizationCodeModel
  extends OAuth2GrantModel<AuthorizationCodeTokenRequest, AuthorizationCodeGrantContext> {
  getClientForAuthentication(
    authRequest: AuthorizationCodeEndpointRequest,
  ): Promise<OAuth2Client | undefined>;

  generateAuthorizationCode(context: AuthorizationCodeEndpointContext): Promise<string | undefined>;
}

/**
 * Options for configuring the authorization code grant flow.
 */
export interface AuthorizationCodeGrantFlowOptions extends OAuth2AuthFlowOptions {
  model: AuthorizationCodeModel;
  authorizationUrl?: string;
}

export class AuthorizationCodeGrantFlow extends OAuth2AuthFlow implements AuthorizationCodeGrant {
  readonly grantType = "authorization_code" as const;
  readonly #model: AuthorizationCodeModel;

  protected authorizationUrl: string = "/authorize";

  constructor(options: AuthorizationCodeGrantFlowOptions) {
    const { model, authorizationUrl, ...flowOptions } = { ...options };
    super(flowOptions);
    this.#model = model;
    if (authorizationUrl) {
      this.authorizationUrl = authorizationUrl;
    }
  }

  setAuthorizationUrl(url: string): this {
    this.authorizationUrl = url;
    return this;
  }

  getAuthorizationUrl(): string {
    return this.authorizationUrl;
  }

  async handleAuthorizationEndpoint(request: Request): Promise<AuthorizationCodeEndpointResponse> {
    const query = new URL(request.url).searchParams;
    const clientId = query.get("client_id") || undefined;
    const responseType = query.get("response_type") || undefined;
    const redirectUri = query.get("redirect_uri") || undefined;
    const scope = query.get("scope") || undefined;
    const state = query.get("state") || undefined;
    const codeChallenge = query.get("code_challenge") || undefined;
    const nonce = query.get("nonce") || undefined;

    if (!clientId) {
      return { success: false, error: new InvalidRequestError("Missing client_id parameter") };
    }

    if (responseType !== "code") {
      return { success: false, error: new UnsupportedGrantTypeError("Unsupported response type") };
    }

    if (!redirectUri) {
      return { success: false, error: new InvalidRequestError("Missing redirect_uri parameter") };
    }

    // In a real implementation, you would validate the client_id and redirect_uri here,
    // and then generate an authorization code and redirect the user to the redirect_uri with the code and state as query parameters.

    const client = await this.#model.getClientForAuthentication({
      clientId,
      responseType,
      redirectUri,
      scopes: scope ? scope.split(" ") : undefined,
      state,
      codeChallenge,
      nonce,
    });

    if (!client) {
      return {
        success: false,
        error: new InvalidClientError("Invalid client_id or redirect_uri or scope"),
      };
    }

    if (request.method === "GET") {
      // In a real implementation, you would render a login page
      // or consent page here for the user
      // to authenticate and authorize the client.
      return {
        success: true,
      };
    }

    if (request.method === "POST") {
      // In a real implementation, you would authenticate the user here,
      // and if authentication is successful, generate an authorization code,
      // and redirect the user to the redirect_uri with the code and state as query parameters.

      const code = await this.#model.generateAuthorizationCode({
        client,
        responseType,
        redirectUri,
        scopes: scope ? scope.split(" ") : [],
        state,
        codeChallenge,
        nonce,
      });

      if (!code) {
        return { success: false, error: new ServerError("Failed to generate authorization code") };
      }

      // Validate scope if provided in the request body (optional)
      let validatedScopes: string[];
      if (client.scopes) {
        const allowedScopes = client.scopes ? client.scopes : [];
        validatedScopes = scope?.split(" ")?.filter((scope) => allowedScopes.includes(scope)) ||
          [];
      } else {
        validatedScopes = [];
      }

      return {
        success: true,
        codeResponse: {
          client,
          redirectUri,
          scopes: validatedScopes,
          code,
          state,
        },
      };
    }

    return { success: false, error: new InvalidRequestError("Unsupported HTTP method") };
  }

  /**
   * Handle a token request for the authorization code grant type.
   * Validates the authorization code and generates an access token if valid.
   * Returns an appropriate error response if validation fails.
   * @param request The incoming HTTP request.
   */
  async token(request: Request): Promise<OAuth2AuthFlowTokenResponse> {
    if (request.method !== "POST") {
      return { success: false, error: new InvalidRequestError("Method Not Allowed") };
    }

    let body: unknown;
    let grantTypeInBody: string | undefined;
    let codeInBody: string | undefined;
    let codeVerifierInBody: string | undefined;
    let redirectUriInBody: string | undefined;
    const contentType = request.headers.get("content-type") || "";

    if (contentType.includes("application/x-www-form-urlencoded")) {
      const form = await request.formData();
      body = {
        grant_type: form.get("grant_type"),
        scope: form.get("scope"),
        code: form.get("code"),
        code_verifier: form.get("code_verifier"),
        redirect_uri: form.get("redirect_uri"),
      };
    } else if (contentType.includes("application/json")) {
      body = request.json ? await request.json() : null;
    } else {
      return { success: false, error: new InvalidRequestError("Unsupported Media Type") };
    }

    if (body && typeof body === "object") {
      if ("grant_type" in body) {
        grantTypeInBody = typeof body.grant_type === "string" ? body.grant_type : undefined;
      }
      if ("code" in body) {
        codeInBody = typeof body.code === "string" ? body.code : undefined;
      }
      if ("code_verifier" in body) {
        codeVerifierInBody = typeof body.code_verifier === "string"
          ? body.code_verifier
          : undefined;
      }
      if ("redirect_uri" in body) {
        redirectUriInBody = typeof body.redirect_uri === "string" ? body.redirect_uri : undefined;
      }
    }

    // Validate that the grant type in the request body matches this grant type
    if (grantTypeInBody !== this.grantType) {
      return { success: false, error: new UnsupportedGrantTypeError("Unsupported grant type") };
    }

    if (!codeInBody) {
      return { success: false, error: new InvalidRequestError("Missing authorization code") };
    }

    // Validate client authentication credentials using the registered client authentication methods
    const { clientId, clientSecret, error } = await this.extractClientCredentials(
      request,
      this.clientAuthMethods,
      this.getTokenEndpointAuthMethods(),
    );

    // If the request contains client authentication credentials, validate them
    if (!error) {
      // If clientId is missing, return 401 error
      if (!clientId) {
        return { success: false, error: new InvalidClientError("Invalid client credentials") };
      }

      // e.g. for DPoP token type, we need to validate the token request before validating client credentials
      const tokenTypeValidationResponse: TokenTypeValidationResponse =
        this._tokenType.isValidTokenRequest
          ? await this._tokenType.isValidTokenRequest(request)
          : { isValid: true };
      if (!tokenTypeValidationResponse.isValid) {
        return {
          success: false,
          error: new InvalidClientError(
            tokenTypeValidationResponse.message || "Invalid token request",
          ),
        };
      }

      const tokenRequest: AuthorizationCodeTokenRequest = {
        clientId,
        clientSecret,
        grantType: grantTypeInBody,
        code: codeInBody,
        codeVerifier: codeVerifierInBody,
        redirectUri: redirectUriInBody,
      };

      // Validate client credentials using the model's getClient() method
      const client = await this.#model.getClient(
        // avoid mutation
        { ...tokenRequest },
      );

      // If client authentication fails, return 401 error
      if (!client) {
        return { success: false, error: new InvalidClientError("Invalid client credentials") };
      }

      // validate that client is allowed to use authorization code grant type
      if (!client.grants || !client.grants.includes(this.grantType)) {
        return {
          success: false,
          error: new UnauthorizedClientError("Unauthorized client for this grant type"),
        };
      }

      // Validate client metadata such as scopes, etc, ..., if applicable for client credentials grant
      const grantContext: AuthorizationCodeGrantContext = {
        client: client,
        grantType: grantTypeInBody,
        tokenType: this.tokenType,
        accessTokenLifetime: this.accessTokenLifetime,
        code: codeInBody,
        codeVerifier: codeVerifierInBody,
        redirectUri: redirectUriInBody,
      };

      // generate access token from client, valid scope,
      // and any other relevant information,
      // using the model's generateAccessToken() and generateRefreshToken() methods
      const accessToken = await this.#model.generateAccessToken?.(
        // avoid mutation
        { ...grantContext },
      );

      // If token generation fails
      if (!accessToken) {
        return { success: false, error: new ServerError("Failed to generate access token") };
      }

      return {
        success: true,
        tokenResponse: {
          access_token: accessToken,
          token_type: this.tokenType,
          expires_in: grantContext.accessTokenLifetime,
          scope: '',
        },
      };
    }

    return { success: false, error };
  }

  toOpenAPISecurityScheme() {
    return {
      [this.getSecuritySchemeName()]: {
        type: "oauth2" as const,
        description: this.getDescription(),
        flows: {
          authorizationCode: {
            authorizationUrl: this.getAuthorizationUrl(),
            scopes: { ...(this.getScopes() || {}) },
            tokenUrl: this.getTokenUrl(),
          },
        },
      },
    };
  }
}
