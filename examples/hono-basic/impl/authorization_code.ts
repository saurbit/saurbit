import {
  StrategyInternalError,
} from "@saurbit/oauth2-server";

import { BearerTokenType, HonoAuthorizationCodeGrantFlow } from "../oauth2_hono_adapter/mod.ts";
import { HTTPException } from "hono/http-exception";

export const authorizationCodeFlow = new HonoAuthorizationCodeGrantFlow({
  model: {
    getClient: async ({
      clientId,
      clientSecret: _c,
      grantType: _g
    }) => {
      console.log("getClient called with:", { clientId, grantType: _g });
      if (clientId === "my-client") {
        return await Promise.resolve({
          id: "my-client",
          redirectUris: ["http://localhost/callback"],
          grants: ["authorization_code"],
          scopes: ["content:read", "content:write"],
        });
      }
    },
    generateAccessToken: async ({
      accessTokenLifetime: _a,
      client: _c,
      grantType: _g,
      tokenType: _t,
    }) => {
      console.log("generateAccessToken called with:", {
        client: _c,
        grantType: _g,
        tokenType: _t,
      });
      // In a real implementation, you would generate a secure token here
      return await Promise.resolve("admin-");
    },
    getClientForAuthentication: async ({
      clientId,
      redirectUri,
      responseType: _rt,
      codeChallenge: _cc,
      nonce: _n,
      state: _s,
      scopes: _scopes,
    }) => {
      console.log("getClientForAuthentication called with:", { clientId, redirectUri, responseType: _rt, codeChallenge: _cc, nonce: _n, state: _s, scopes: _scopes });
      if (clientId === "my-client") {
        return await Promise.resolve({
          id: "my-client",
          redirectUris: ["http://localhost/callback"],
          grants: ["authorization_code"],
          scopes: ["content:read", "content:write"],
        });
      }
    },
    generateAuthorizationCode: async ({
      client: _c,
      redirectUri: _r,
      responseType: _rt,
      codeChallenge: _cc,
      nonce: _n,
      scopes,
      state: _s,
    }) => {
      console.log("generateAuthorizationCode called with:", { client: _c, redirectUri: _r, scopes });
      // In a real implementation, you would generate a secure code here and associate it with the client, redirect URI, scope, and user
      return await Promise.resolve("authcode-" + scopes.join(","));
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

// Configure the authorization code flow with both
// - client secret basic authentication method and
// - client secret post authentication methods
authorizationCodeFlow
  .clientSecretBasicAuthenticationMethod()
  .clientSecretPostAuthenticationMethod();

// Set the token type to Bearer
authorizationCodeFlow.setTokenType(
  new BearerTokenType(),
);

// Set the description and scopes for the OpenAPI documentation
authorizationCodeFlow
  .setDescription("Authorization Code Grant Flow for Hono API")
  .setScopes({
    "content:read": "Read content",
    "content:write": "Write content",
    "admin": "Admin access",
  })
  .setTokenUrl("/token"); // Set the token URL for the OpenAPI documentation