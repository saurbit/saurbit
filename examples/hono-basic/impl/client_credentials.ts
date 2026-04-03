import { BearerTokenType, StrategyInternalError } from "@saurbit/oauth2";

import { HonoClientCredentialsFlowBuilder } from "@saurbit/hono-oauth2";
import { HTTPException } from "hono/http-exception";
import { verifyTokenFunction } from "./common.ts";

export const clientCredentialsFlow = HonoClientCredentialsFlowBuilder
  .create()
  .setSecuritySchemeName("honoClientCredentialsBuilder")
  .setDescription("Client Credentials Grant Flow for Hono API (built with builder)")
  .setScopes({
    "content:read": "Read content",
    "content:write": "Write content",
    "admin": "Admin access",
  })
  .setTokenEndpoint("/token")
  .setAccessTokenLifetime(3600)
  .clientSecretBasicAuthenticationMethod()
  .clientSecretPostAuthenticationMethod()
  // Set the token type to Bearer
  .setTokenType(new BearerTokenType())
  .getClient(async ({ clientId, clientSecret: _cs, grantType, scope }) => {
    console.log("getClient called with:", { clientId, grantType, scope });
    if (clientId === "my-client") {
      return await Promise.resolve({
        id: "my-client",
        redirectUris: [],
        grants: ["client_credentials"],
        scopes: ["content:read", "content:write"],
      });
    }
  })
  .generateAccessToken(
    async ({ accessTokenLifetime: _a, client: _c, grantType: _g, scope, tokenType: _t }) => {
      console.log("generateAccessToken called with:", {
        client: _c,
        grantType: _g,
        scope,
        tokenType: _t,
      });
      // In a real implementation, you would generate a secure token here
      return await Promise.resolve("admin-" + scope.join(","));
    },
  )
  .tokenVerifier(verifyTokenFunction)
  .failedAuthorizationAction((_, error) => {
    // You can perform additional actions here, such as logging or modifying the response
    console.log("Authorization failed:", { error: error.name, message: error.message });
    let message: string;
    if (Deno.env.get("DENO_ENV") === "production") {
      message = error instanceof StrategyInternalError ? "Internal Server Error" : "Unauthorized";
    } else {
      message = "Unauthorized";
    }
    throw new HTTPException(401, {
      message,
    });
  }).build();
