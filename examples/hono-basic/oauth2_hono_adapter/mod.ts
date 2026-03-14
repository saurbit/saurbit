// Re-export for convenience
export type {
  AuthCredentials,
  StrategyOptions,
  StrategyVerifyTokenFunction,
  TokenType,
  TokenTypeValidationResponse,
} from "@saurbit/oauth2-server";
export { BearerTokenType } from "@saurbit/oauth2-server";

export type {
  FailedAuthorizationAction,
  HonoOAuth2StrategyOptions,
  HonoStrategyOptions,
  OAuth2ServerEnv,
} from "./types.ts";

export { createAuthMiddleware } from "./utils.ts";

export {
  HonoAuthorizationCodeFlow,
  type HonoAuthorizationCodeFlowOptions,
  HonoOIDCAuthorizationCodeFlow,
  type HonoOIDCAuthorizationCodeFlowOptions,
} from "./authorization_code.ts";
export {
  HonoClientCredentialsFlow,
  HonoClientCredentialsFlowBuilder,
  type HonoClientCredentialsFlowOptions,
  HonoOIDCClientCredentialsFlow,
  type HonoOIDCClientCredentialsFlowOptions,
} from "./client_credentials.ts";
export { type HonoOIDCFlow, HonoOIDCMultipleFlows } from "./oidc_multiple_flow.ts";
