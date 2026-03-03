/**
 * @module
 * A framework-agnostic OAuth 2.0 authorization server for Deno.
 *
 * @example
 * ```ts
 * import { OAuth2Server } from "@saurbit/oauth2-server";
 *
 * const server = new OAuth2Server({ model: myModel });
 * ```
 */

export { OAuth2Server } from "./src/server.ts";
export type { OAuth2ServerOptions } from "./src/server.ts";

export {
  OAuth2Error,
  AccessDeniedError,
  InsufficientScopeError,
  InvalidClientError,
  InvalidGrantError,
  InvalidRequestError,
  InvalidScopeError,
  InvalidTokenError,
  ServerError,
  UnauthorizedClientError,
  UnauthorizedRequestError,
  UnsupportedGrantTypeError,
  UnsupportedResponseTypeError,
} from "./src/errors.ts";

export type {
  OAuth2Client,
  OAuth2Token,
  OAuth2AuthorizationCode,
  OAuth2Model,
  OAuth2Scope,
} from "./src/types.ts";

export type { AuthorizationCodeGrant } from "./src/grants/authorization_code.ts";
export type { ClientCredentialsGrant } from "./src/grants/client_credentials.ts";
export type { RefreshTokenGrant } from "./src/grants/refresh_token.ts";

export { BearerTokenType, type BearerTokenValidation } from "./src/token_types/bearer_token.ts";
export type { TokenType, TokenTypeValidationResponse } from "./src/token_types/types.ts";
export type {
  JwtAuthority,
  JwtPayload,
  JwtVerifier,
  JwksKeyStore,
  JwksRotationTimestampStore,
  JwksRotatorOptions,
  JwtSigner, 
  KeyGenerator,
  RSA,
  RawKey
 } from './src/utils/jwt_authority.ts';
export { JwksRotator } from "./src/utils/jwt_authority.ts";
export type { 
  AppCredentials,
  AuthCredentials,
  StrategyResult,
  UserCredentials,
  StrategyOptions,
  StrategyVerifyTokenFunction
} from "./src/strategy.ts";
export { 
  evaluateStrategy,
  StrategyInvalidTokenError,
  StrategyJwtVerificationError,
  StrategyInvalidTokenTypeError,
  StrategyInternalError,
  StrategyError 
 } from "./src/strategy.ts";
