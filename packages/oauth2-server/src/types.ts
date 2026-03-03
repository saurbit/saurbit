/**
 * A string or array of strings representing OAuth 2.0 scopes.
 */
export type OAuth2Scope = string | string[];

export interface OAuth2TokenResponseBody {
    access_token: string;
    token_type: string;
    expires_in?: number;
    refresh_token?: string;
    scope?: string;
    id_token?: string;
    error?: never;
    [key: string]: unknown;
}

/**
 * Represents a registered OAuth 2.0 client.
 */
export interface OAuth2Client {
  /** Unique client identifier. */
  id: string;

  /** Client secret (for confidential clients). */
  secret?: string;

  /** Allowed redirect URIs. */
  redirectUris: string[];

  /** Grant types the client is authorized to use. */
  grants: string[];

  /** Scopes the client is allowed to request. */
  scopes?: string[];
}

/**
 * Represents an issued OAuth 2.0 access / refresh token pair.
 */
export interface OAuth2Token {
  /** The access token string. */
  accessToken: string;

  /** When the access token expires. */
  accessTokenExpiresAt: Date;

  /** The refresh token string (if issued). */
  refreshToken?: string;

  /** When the refresh token expires. */
  refreshTokenExpiresAt?: Date;

  /** The scopes granted to this token. */
  scope?: string[];

  /** The client this token was issued to. */
  client: OAuth2Client;

  /** The resource owner (user) this token represents. */
  user: Record<string, unknown>;
}

/**
 * Represents an OAuth 2.0 authorization code.
 */
export interface OAuth2AuthorizationCode {
  /** The authorization code string. */
  code: string;

  /** When the code expires. */
  expiresAt: Date;

  /** The redirect URI used in the authorization request. */
  redirectUri: string;

  /** The scopes authorized by the resource owner. */
  scope?: string[];

  /** The client that requested the code. */
  client: OAuth2Client;

  /** The resource owner (user) who authorized the request. */
  user: Record<string, unknown>;

  /** PKCE code challenge (if provided). */
  codeChallenge?: string;

  /** PKCE code challenge method (`plain` | `S256`). */
  codeChallengeMethod?: "plain" | "S256";
}

/**
 * Model interface that must be implemented by the consuming application
 * to provide persistence for clients, tokens, and authorization codes.
 */
export interface OAuth2Model {
  // ── Client lookup ──────────────────────────────────────────────────

  /**
   * Retrieve a client by its id (and optionally verify its secret).
   */
  getClient(clientId: string, clientSecret?: string, options?: { grantType?: string, scopes?: string[]; }): Promise<OAuth2Client | undefined>;

  // ── Token persistence ──────────────────────────────────────────────
  
  generateAccessToken?(client: OAuth2Client, validatedOptions: { scopes: string[]; grantType: string; accessTokenLifetime: number; tokenType: string; }): Promise<string | undefined>;
  generateRefreshToken?(client: OAuth2Client, validatedOptions: { scopes: string[]; grantType: string; accessTokenLifetime: number; tokenType: string; }): Promise<string | undefined>;

  /**
   * Persist a newly generated token.
   */
  saveToken(token: OAuth2Token, client: OAuth2Client, user: Record<string, unknown>): Promise<OAuth2Token>;

  /**
   * Retrieve an existing access token.
   */
  getAccessToken(accessToken: string): Promise<OAuth2Token | undefined>;

  /**
   * Retrieve an existing refresh token.
   */
  getRefreshToken?(refreshToken: string): Promise<OAuth2Token | undefined>;

  /**
   * Revoke a refresh token (e.g. after rotation).
   */
  revokeToken?(token: OAuth2Token): Promise<boolean>;

  // ── Authorization code persistence ─────────────────────────────────

  /**
   * Persist a newly generated authorization code.
   */
  saveAuthorizationCode?(
    code: OAuth2AuthorizationCode,
    client: OAuth2Client,
    user: Record<string, unknown>,
  ): Promise<OAuth2AuthorizationCode>;

  /**
   * Retrieve an authorization code.
   */
  getAuthorizationCode?(code: string): Promise<OAuth2AuthorizationCode | undefined>;

  /**
   * Revoke an authorization code after it has been exchanged.
   */
  revokeAuthorizationCode?(code: OAuth2AuthorizationCode): Promise<boolean>;

  // ── Scope validation ───────────────────────────────────────────────

  /**
   * Verify that the requested scope is valid for the given client/user.
   * Return the validated scope, or throw/return undefined to deny.
   */
  validateScope?(
    client: OAuth2Client,
    user: Record<string, unknown>,
    scope?: string[],
  ): Promise<string[] | undefined>;
}
