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

export { OAuth2Server } from "./server.ts";
export type { OAuth2ServerOptions } from "./server.ts";

export {
  AccessDeniedError,
  InsufficientScopeError,
  InvalidClientError,
  InvalidGrantError,
  InvalidRequestError,
  InvalidScopeError,
  InvalidTokenError,
  OAuth2Error,
  ServerError,
  UnauthorizedClientError,
  UnauthorizedRequestError,
  UnsupportedGrantTypeError,
  UnsupportedResponseTypeError,
} from "./errors.ts";

export type {
  OAuth2AuthorizationCode,
  OAuth2Client,
  OAuth2Model,
  OAuth2Scope,
  OAuth2Token,
} from "./types.ts";

export { ClientSecretBasic } from "./client_auth_methods/client_secret_basic.ts";
export { ClientSecretPost } from "./client_auth_methods/client_secret_post.ts";
export { NoneAuthMethod } from "./client_auth_methods/none.ts";
export {
  ClientSecretJwt,
  ClientSecretJwtAlgorithms,
} from "./client_auth_methods/client_secret_jwt.ts";
export { PrivateKeyJwt, PrivateKeyJwtAlgorithms } from "./client_auth_methods/private_key_jwt.ts";
export type {
  ClientAuthMethod,
  ClientAuthMethodResponse,
  TokenEndpointAuthMethod,
} from "./client_auth_methods/types.ts";

export type {
  OAuth2AccessTokenResult,
  OAuth2AuthFlowOptions,
  OAuth2AuthFlowTokenResponse,
  OAuth2GrantModel,
  OAuth2RefreshTokenGrantContext,
  OAuth2RefreshTokenRequest,
} from "./grants/auth_flow.ts";
export { OAuth2AuthFlow } from "./grants/auth_flow.ts";
export type {
  AuthorizationCodeAccessTokenResult,
  AuthorizationCodeEndpointCodeResponse,
  AuthorizationCodeEndpointContext,
  AuthorizationCodeEndpointContinueResponse,
  AuthorizationCodeEndpointRequest,
  AuthorizationCodeEndpointResponse,
  AuthorizationCodeGeneratorResult,
  AuthorizationCodeGrant,
  AuthorizationCodeGrantContext,
  AuthorizationCodeGrantFlowOptions,
  AuthorizationCodeInitiationResponse,
  AuthorizationCodeModel,
  AuthorizationCodeProcessResponse,
  AuthorizationCodeReqBody,
  AuthorizationCodeTokenRequest,
  AuthorizationCodeUser,
} from "./grants/authorization_code.ts";
export { AuthorizationCodeGrantFlow } from "./grants/authorization_code.ts";
export type {
  ClientCredentialsGrant,
  ClientCredentialsGrantContext,
  ClientCredentialsGrantFlowOptions,
  ClientCredentialsModel,
  ClientCredentialsTokenRequest,
} from "./grants/client_credentials.ts";
export { ClientCredentialsGrantFlow } from "./grants/client_credentials.ts";
export type { RefreshTokenGrant } from "./grants/refresh_token.ts";

export type {
  OpenIDAuthorizationCodeAccessTokenResult,
  OpenIDAuthorizationCodeFlowOptions,
  OpenIDAuthorizationCodeModel,
} from "./open_id/open_id_authorization_code.ts";
export { OpenIDAuthorizationCodeFlow } from "./open_id/open_id_authorization_code.ts";
export type { OpenIDClientCredentialsFlowOptions } from "./open_id/open_id_client_credentials.ts";
export { OpenIDClientCredentialsFlow } from "./open_id/open_id_client_credentials.ts";
export type { OpenIDUserInfo } from "./open_id/types.ts";

export { BearerTokenType, type BearerTokenValidation } from "./token_types/bearer_token.ts";
export type { TokenType, TokenTypeValidationResponse } from "./token_types/types.ts";
export type {
  JwksKeyStore,
  JwksRotationTimestampStore,
  JwksRotatorOptions,
  JwtAuthority,
  JwtPayload,
  JwtSigner,
  JwtVerifier,
  KeyGenerator,
  RawKey,
  RSA,
} from "./utils/jwt_authority.ts";
export { JwksRotator } from "./utils/jwt_authority.ts";
export type {
  AppCredentials,
  AuthCredentials,
  StrategyOptions,
  StrategyResult,
  StrategyVerifyTokenFunction,
  UserCredentials,
} from "./strategy.ts";
export {
  evaluateStrategy,
  StrategyError,
  StrategyInsufficientScopeError,
  StrategyInternalError,
  StrategyInvalidTokenError,
  StrategyInvalidTokenTypeError,
  StrategyJwtVerificationError,
} from "./strategy.ts";
