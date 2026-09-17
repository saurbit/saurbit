/**
 * The result returned by token type validation methods.
 */
export type TokenTypeValidationResponse = {
  /** Whether the token or token request is considered valid. */
  isValid?: boolean;

  /** An optional human-readable message describing the validation failure. */
  message?: string;

  /** Additional properties returned by the validation. */
  [key: string]: unknown;
};

/**
 * Defines how a specific token type (e.g. Bearer, DPoP) is recognised and validated.
 *
 * Implement this interface to support custom token schemes beyond the built-in ones.
 */
export interface TokenType {
  /**
   * The token type prefix as it appears in the `Authorization` header (e.g. `"Bearer"`, `"DPoP"`).
   * Used both for extracting the token from the request and for the `token_type` field
   * in the token endpoint response.
   */
  readonly prefix: string;

  /**
   * Validates the token extracted from an incoming request.
   * Called on protected resource endpoints after the token has been extracted.
   *
   * @param request - The incoming HTTP request.
   * @param token - The raw token string extracted from the `Authorization` header.
   * @returns A validation response indicating whether the token is valid.
   */
  isValid: (
    request: Request,
    token: string,
  ) => TokenTypeValidationResponse | Promise<TokenTypeValidationResponse>;

  /**
   * Validates the token request itself at the token endpoint, before client credentials
   * are checked. Used for token types (e.g. DPoP) that require request-level proof
   * to be verified independently of client authentication.
   *
   * Optional - only implement when the token type requires token endpoint validation.
   *
   * @param request - The incoming token endpoint HTTP request.
   * @param ctxt - Contextual information about the token request, such as the grant type and refresh token if applicable.
   * @returns A validation response indicating whether the request is valid.
   */
  isValidTokenRequest?: (
    request: Request,
    ctxt: { grantType: "refresh_token"; refreshToken: string } | { grantType: string },
  ) => TokenTypeValidationResponse | Promise<TokenTypeValidationResponse>;
}
