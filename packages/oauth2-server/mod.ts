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

export {
    ClientSecretBasic
} from './src/client_auth_methods/client_secret_basic.ts';
export {
    ClientSecretPost
} from './src/client_auth_methods/client_secret_post.ts';
export {
    NoneAuthMethod
} from './src/client_auth_methods/none.ts';
export {
    ClientSecretJwt,
    ClientSecretJwtAlgorithms
} from './src/client_auth_methods/client_secret_jwt.ts';
export {
    PrivateKeyJwt,
    PrivateKeyJwtAlgorithms
} from './src/client_auth_methods/private_key_jwt.ts';
export type { ClientAuthMethod, ClientAuthMethodResponse, TokenEndpointAuthMethod } from './src/client_auth_methods/types.ts';

export type { AuthorizationCodeGrant } from "./src/grants/authorization_code.ts";
export type { 
  ClientCredentialsGrant, 
  ClientCredentialsGrantContext, 
  ClientCredentialsTokenRequest, 
  ClientCredentialsModel, 
  ClientCredentialsGrantFlowOptions
} from "./src/grants/client_credentials.ts";
export { ClientCredentialsGrantFlow } from "./src/grants/client_credentials.ts";
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
