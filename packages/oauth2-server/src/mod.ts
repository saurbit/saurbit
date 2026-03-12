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
  OAuth2Errors,
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
  OAuth2FlowOptions,
  OAuth2FlowTokenResponse,
  OAuth2GenerateAccessTokenFromRefreshTokenFunction,
  OAuth2GenerateAccessTokenFunction,
  OAuth2GetClientFunction,
  OAuth2GrantModel,
  OAuth2RefreshTokenGrantContext,
  OAuth2RefreshTokenRequest,
} from "./grants/flow.ts";
export { OAuth2Flow } from "./grants/flow.ts";
export type {
  AbstractAuthorizationCodeFlow,
  AuthorizationCodeAccessTokenResult,
  AuthorizationCodeEndpointCodeResponse,
  AuthorizationCodeEndpointContext,
  AuthorizationCodeEndpointContinueResponse,
  AuthorizationCodeEndpointRequest,
  AuthorizationCodeEndpointResponse,
  AuthorizationCodeFlowOptions,
  AuthorizationCodeGrant,
  AuthorizationCodeGrantContext,
  AuthorizationCodeInitiationResponse,
  AuthorizationCodeModel,
  AuthorizationCodeProcessResponse,
  AuthorizationCodeReqBody,
  AuthorizationCodeTokenRequest,
  AuthorizationCodeUser,
  GenerateAuthorizationCodeFunction,
  GenerateAuthorizationCodeResult,
  GetUserForAuthenticationFunction,
  GetUserForAuthenticationResult,
} from "./grants/authorization_code.ts";
export { AuthorizationCodeFlow } from "./grants/authorization_code.ts";
export type {
  AbstractClientCredentialsFlow,
  ClientCredentialsFlowOptions,
  ClientCredentialsGrant,
  ClientCredentialsGrantContext,
  ClientCredentialsModel,
  ClientCredentialsTokenRequest,
} from "./grants/client_credentials.ts";
export { ClientCredentialsFlow } from "./grants/client_credentials.ts";

export type {
  OIDCAuthenticationRequestParams,
  OIDCAuthorizationCodeAccessTokenResult,
  OIDCAuthorizationCodeEndpointContext,
  OIDCAuthorizationCodeEndpointRequest,
  OIDCAuthorizationCodeEndpointResponse,
  OIDCAuthorizationCodeFlowOptions,
  OIDCAuthorizationCodeInitiationResponse,
  OIDCAuthorizationCodeModel,
  OIDCAuthorizationCodeProcessResponse,
} from "./oidc/oidc_authorization_code.ts";
export { OIDCAuthorizationCodeFlow } from "./oidc/oidc_authorization_code.ts";
export type { OIDCClientCredentialsFlowOptions } from "./oidc/oidc_client_credentials.ts";
export { OIDCClientCredentialsFlow } from "./oidc/oidc_client_credentials.ts";
export { OIDCMultipleFlows } from "./oidc/oidc_multiple_flows.ts";
export type { OIDCFlow, OIDCFlowExtendedOptions, OIDCUserInfo } from "./oidc/types.ts";

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
  StrategyErrors,
  StrategyInsufficientScopeError,
  StrategyInternalError,
  StrategyInvalidTokenError,
  StrategyInvalidTokenTypeError,
  StrategyJwtVerificationError,
} from "./strategy.ts";
