/**
 * @module
 * @description `@saurbit/oauth2` - A modular, framework-agnostic OAuth 2.0 and OpenID Connect
 * server library.
 *
 * Supports the following grant types out of the box:
 * - **Authorization Code** (with PKCE) - {@link AuthorizationCodeFlow} / {@link OIDCAuthorizationCodeFlow}
 * - **Client Credentials** - {@link ClientCredentialsFlow} / {@link OIDCClientCredentialsFlow}
 * - **Device Authorization** (RFC 8628) - {@link DeviceAuthorizationFlow} / {@link OIDCDeviceAuthorizationFlow}
 *
 * Each grant type has a corresponding fluent builder for easy configuration:
 * {@link AuthorizationCodeFlowBuilder}, {@link ClientCredentialsFlowBuilder},
 * {@link DeviceAuthorizationFlowBuilder}, and their OIDC counterparts.
 *
 * ## Quick start
 *
 * ```ts
 * import { ClientCredentialsFlowBuilder } from "@saurbit/oauth2";
 *
 * const flow = new ClientCredentialsFlowBuilder({ tokenEndpoint: "/token" })
 *   .setScopes({ "read:data": "Read access to data" })
 *   .clientSecretBasicAuthenticationMethod()
 *   .getClient(async ({ clientId, clientSecret }) => db.findClient(clientId, clientSecret))
 *   .generateAccessToken(async (ctx) => ({ accessToken: issueToken(ctx) }))
 *   .verifyToken(async (token) => verifyToken(token))
 *   .build();
 * ```
 *
 * ## Client authentication methods
 *
 * The following token endpoint authentication methods are available:
 * {@link ClientSecretBasic}, {@link ClientSecretPost}, {@link NoneAuthMethod},
 * {@link ClientSecretJwt}, {@link PrivateKeyJwt}.
 *
 * ## Token types
 *
 * Access tokens can be validated as Bearer ({@link BearerTokenType}) or
 * DPoP ({@link DPoPTokenType}).
 *
 * ## OpenID Connect
 *
 * OIDC flows extend the base grant flows with ID token enforcement, UserInfo endpoint
 * support, and discovery document generation. Use {@link OIDCMultipleFlows} to aggregate
 * multiple OIDC flows behind a single discovery and token endpoint.
 *
 * ## Strategy middleware
 *
 * Use {@link evaluateStrategy} to protect routes by validating access tokens
 * against a configured flow.
 *
 * @see https://datatracker.ietf.org/doc/html/rfc6749 OAuth 2.0 Authorization Framework
 * @see https://openid.net/specs/openid-connect-core-1_0.html OpenID Connect Core 1.0
 * @see https://datatracker.ietf.org/doc/html/rfc8628 OAuth 2.0 Device Authorization Grant
 */

//#region Builders

export { AuthorizationCodeFlowBuilder } from "./builders/authorization_code_builder.ts";
export { ClientCredentialsFlowBuilder } from "./builders/client_credentials_builder.ts";
export { DeviceAuthorizationFlowBuilder } from "./builders/device_authorization_builder.ts";
export { OAuth2FlowBuilder } from "./builders/flow_builder.ts";
export { OIDCAuthorizationCodeFlowBuilder } from "./builders/oidc_authorization_code_builder.ts";
export { OIDCClientCredentialsFlowBuilder } from "./builders/oidc_client_credentials_builder.ts";
export { OIDCDeviceAuthorizationFlowBuilder } from "./builders/oidc_device_authorization_builder.ts";

//#endregion

//#region  Client Authentication Methods

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

//#endregion

//#region Flows and Grants

export type {
  OAuth2AccessTokenResult,
  OAuth2FlowOptions,
  OAuth2FlowStrategyOptions,
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
  AuthorizationCodeReqData,
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
export type {
  OIDCDeviceAuthorizationAccessTokenResult,
  OIDCDeviceAuthorizationFlowOptions,
  OIDCDeviceAuthorizationModel,
} from "./oidc/oidc_device_authorization.ts";
export { OIDCDeviceAuthorizationFlow } from "./oidc/oidc_device_authorization.ts";
export { OIDCMultipleFlows } from "./oidc/oidc_multiple_flows.ts";
export type { OIDCFlow, OIDCFlowExtendedOptions, OIDCUserInfo } from "./oidc/types.ts";

export type {
  AbstractDeviceAuthorizationFlow,
  DeviceAuthorizationAccessTokenError,
  DeviceAuthorizationAccessTokenResult,
  DeviceAuthorizationEndpointCodeResponse,
  DeviceAuthorizationEndpointContext,
  DeviceAuthorizationEndpointRequest,
  DeviceAuthorizationEndpointResponse,
  DeviceAuthorizationFlowOptions,
  DeviceAuthorizationGrant,
  DeviceAuthorizationGrantContext,
  DeviceAuthorizationInitiationResponse,
  DeviceAuthorizationModel,
  DeviceAuthorizationProcessResponse,
  DeviceAuthorizationTokenRequest,
  GenerateDeviceCodeFunction,
} from "./grants/device_authorization.ts";

export { DeviceAuthorizationFlow } from "./grants/device_authorization.ts";

//#endregion

//#region Token Types

export { BearerTokenType, type BearerTokenValidation } from "./token_types/bearer_token.ts";
export {
  DPoPTokenType,
  type DPoPTokenTypeRequestValidation,
  type DPoPTokenTypeValidation,
  type DPoPTokenTypeValidationResponse,
} from "./token_types/dpop_token.ts";
export type { TokenType, TokenTypeValidationResponse } from "./token_types/types.ts";

//#endregion

//#region Utilities

export type {
  JwkThumbprintCalculator,
  JwkVerify,
  JwtDecode,
  JwtPayload,
  JwtVerify,
} from "./utils/jwt_types.ts";
export {
  createInMemoryReplayStore,
  InMemoryReplayStore,
  type ReplayDetector,
  type ReplayStore,
} from "./utils/replay_store.ts";
export { generateAccessTokenHash } from "./utils/methods.ts";
export { getOriginFromRequest } from "./utils/url_tools.ts";

//#endregion

//#region Errors

export {
  AccessDeniedError,
  AuthorizationPendingError,
  ExpiredTokenError,
  InsufficientScopeError,
  InvalidClientError,
  InvalidGrantError,
  InvalidRequestError,
  InvalidScopeError,
  InvalidTokenError,
  OAuth2Error,
  OAuth2Errors,
  ServerError,
  SlowDownError,
  UnauthorizedClientError,
  UnauthorizedRequestError,
  UnsupportedGrantTypeError,
  UnsupportedResponseTypeError,
} from "./errors.ts";

//#endregion

//#region Strategy

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
} from "./strategy.ts";

//#endregion

//#region Types

export type { OAuth2Client } from "./types.ts";

//#endregion
