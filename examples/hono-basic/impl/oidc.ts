import { HonoOIDCMultipleFlows } from "../oauth2_hono_adapter/oidc_multiple_flow.ts";
import { oidcAuthorizationCodeFlow } from "./oidc_authorization_code.ts";

export const oidcMultipleFlows = new HonoOIDCMultipleFlows({
  flows: [oidcAuthorizationCodeFlow],
  discoveryUrl: "http://localhost/.well-known/openid-configuration",
  securitySchemeName: "honoOIDCMultipleFlows",
  description: "Multiple OIDC Flows for Hono API",
  jwksEndpoint: "/jwks",
  tokenEndpoint: "/token",
});
