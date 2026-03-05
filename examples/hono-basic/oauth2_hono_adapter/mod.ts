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
  HonoStrategyOptions,
  HonoStrategyOptionsWithFailedAuth,
  OAuth2ServerEnv,
} from "./types.ts";

export { createAuthMiddleware } from "./utils.ts";

export {
  type HonoAuthorizationCodeFlowOptions,
  HonoAuthorizationCodeGrantFlow,
} from "./authorization_code.ts"
export {
  type HonoClientCredentialsFlowOptions,
  HonoClientCredentialsGrantFlow,
} from "./client_credentials.ts";
