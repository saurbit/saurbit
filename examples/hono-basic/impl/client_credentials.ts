import {
  StrategyInternalError,
} from "@saurbit/oauth2-server";

import { BearerTokenType, HonoClientCredentialsGrantFlow } from "../oauth2_hono_adapter/mod.ts";
import { HTTPException } from "hono/http-exception";

export const clientCredentialsFlow = new HonoClientCredentialsGrantFlow({
  model: {
    getClient: async ({
      clientId,
      clientSecret: _c,
      grantType: _g,
      scopes: _s,
    }) => {
      console.log("getClient called with:", { clientId, grantType: _g, scopes: _s });
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
      scopes,
      tokenType: _t,
    }) => {
      console.log("generateAccessToken called with:", {
        client: _c,
        grantType: _g,
        scopes,
        tokenType: _t,
      });
      // In a real implementation, you would generate a secure token here
      return await Promise.resolve("admin-" + scopes.join(","));
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
    verifyToken: (_context, { token }) => {
      console.log("verifyToken called with token:", token);
      if (token.startsWith("admin")) {
        return {
          isValid: true,
          credentials: {
            user: {
              username: "admin",
              level: 50,
            },
            scope: token.substring(6).split(","),
          },
        };
      }

      return { isValid: false };
    },
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