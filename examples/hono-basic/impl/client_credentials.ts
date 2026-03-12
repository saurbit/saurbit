import { StrategyInternalError } from "@saurbit/oauth2-server";

import { BearerTokenType, HonoClientCredentialsFlow } from "../oauth2_hono_adapter/mod.ts";
import { HTTPException } from "hono/http-exception";
import { verifyTokenFunction } from "./common.ts";
import { HonoClientCredentialsFlowBuilder } from "../oauth2_hono_adapter/client_credentials.ts";

export const clientCredentialsFlow = HonoClientCredentialsFlowBuilder
  .create()
  .setSecuritySchemeName("honoClientCredentialsBuilder")
  .setDescription("Client Credentials Grant Flow for Hono API (built with builder)")
  .setScopes({
    "content:read": "Read content",
    "content:write": "Write content",
    "admin": "Admin access",
  })
  .setTokenUrl("/token")
  .setAccessTokenLifetime(3600)
  .clientSecretBasicAuthenticationMethod()
  .clientSecretPostAuthenticationMethod()
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
  .verifyTokenHandler(verifyTokenFunction)
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

export const clientCredentialsFlowInstance = new HonoClientCredentialsFlow({
  model: {
    getClient: async ({
      clientId,
      clientSecret: _c,
      grantType: _g,
      scope: _s,
    }) => {
      console.log("getClient called with:", { clientId, grantType: _g, scope: _s });
      if (clientId === "my-client") {
        return await Promise.resolve({
          id: "my-client",
          redirectUris: [],
          grants: ["client_credentials"],
          scopes: ["content:read", "content:write"],
        });
      }
    },
    generateAccessToken: async ({
      accessTokenLifetime: _a,
      client: _c,
      grantType: _g,
      scope,
      tokenType: _t,
    }) => {
      console.log("generateAccessToken called with:", {
        client: _c,
        grantType: _g,
        scope,
        tokenType: _t,
      });
      // In a real implementation, you would generate a secure token here
      return await Promise.resolve("admin-" + scope.join(","));
    },
  },
  strategyOptions: {
    failedAuthorizationAction: (_, error) => {
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
    },
    verifyToken: verifyTokenFunction,
  },
  accessTokenLifetime: 3600,
  securitySchemeName: "honoClientCredentials",
});

// Configure the client credentials flow with both
// - client secret basic authentication method and
// - client secret post authentication methods
clientCredentialsFlow
  .clientSecretBasicAuthenticationMethod()
  .clientSecretPostAuthenticationMethod();

// Set the token type to Bearer
clientCredentialsFlow.setTokenType(
  new BearerTokenType(),
);

// Set the description and scopes for the OpenAPI documentation
clientCredentialsFlow
  .setDescription("Client Credentials Grant Flow for Hono API")
  .setScopes({
    "content:read": "Read content",
    "content:write": "Write content",
    "admin": "Admin access",
  })
  .setTokenUrl("/token"); // Set the token URL for the OpenAPI documentation
