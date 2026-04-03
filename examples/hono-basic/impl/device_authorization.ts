// impl/device_authorization.ts

import { BearerTokenType, StrategyInternalError } from "@saurbit/oauth2";

import { HonoDeviceAuthorizationFlowBuilder } from "@saurbit/hono-oauth2";
import { HTTPException } from "hono/http-exception";
import { verifyTokenFunction } from "./common.ts";

export const deviceAuthorizationFlow = HonoDeviceAuthorizationFlowBuilder.create()
  // -- common configuration for OpenAPI documentation

  .setSecuritySchemeName("honoDeviceAuthorization")
  .setDescription("Device Authorization Grant Flow for Hono API (built with builder)")
  .setScopes({
    "content:read": "Read content",
    "content:write": "Write content",
    "admin": "Admin access",
  })
  .setTokenEndpoint("/oauth2/token")
  .setAuthorizationEndpoint("/oauth2/device_authorization")
  .setVerificationEndpoint("/oauth2/verify_user_code")
  // -- configuration for the device authorization flow

  .setAccessTokenLifetime(3600)
  // Configure the device authorization flow with both
  // - client secret basic authentication method and
  // - public client authentication method (none)
  // to allow for both confidential and public clients to use the
  // device authorization flow. In a real implementation, you would
  // typically choose the authentication methods that are appropriate
  // for your use case and security requirements.
  .addClientAuthenticationMethod("client_secret_basic")
  .addClientAuthenticationMethod("none")
  // Set the token type to Bearer
  .setTokenType(new BearerTokenType())
  // -- handlers at authorization endpoint

  .getClientForAuthentication(
    async ({
      clientId,
      scope,
      clientSecret: _c,
    }) => {
      console.log("getClientForAuthentication called with:", {
        clientId,
        scope,
      });
      if (clientId === "my-client") {
        return await Promise.resolve({
          id: "my-client",
          redirectUris: ["http://localhost/callback"],
          grants: ["urn:ietf:params:oauth:grant-type:device_code"],
          scopes: ["content:read", "content:write"],
        });
      }
    },
  )
  .generateDeviceCode(
    async ({
      client,
      scope,
    }) => {
      console.log("generateDeviceCode called with:", {
        client,
        scope,
      });

      // generate deviceCode and userCode and associate them with the client and scope in your data store

      return await Promise.resolve({
        deviceCode: "device-code-" + scope.join(","),
        userCode: "user-code-" + scope.join(","),
      });
    },
  )
  .verifyUserCode(
    (userCode) => {
      console.log("verifyUserCode called with:", { userCode });

      // verify the userCode and if valid, mark the associated deviceCode as authorized in your data store

      if (userCode.startsWith("user-code-")) {
        return {
          client: {
            id: "my-client",
            redirectUris: ["http://localhost/callback"],
            grants: ["urn:ietf:params:oauth:grant-type:device_code"],
            scopes: ["content:read", "content:write"],
          },
          deviceCode: "device-code-" + userCode.slice("user-code-".length),
        };
      }
    },
  )
  // -- handlers at token endpoint

  .getClient(async ({ clientId, clientSecret: _c, ...props }) => {
    console.log("getClient called with:", { clientId, grantType: props.grantType });
    if (props.grantType === "refresh_token") {
      // For refresh token request, you would typically validate the refresh token and return the associated client information. For this example, we'll just return a dummy client object if the clientId matches.
      if (clientId === "my-client" && props.refreshToken.startsWith("valid-refresh-token-")) {
        // If asking for new scope, it cannot have scopes that are not
        // in the original scope associated with the refresh token

        const scope = props.refreshToken.slice("valid-refresh-token-".length).split(",");
        const invalidScopes = props.scope?.filter((scope) => !scope.includes(scope));
        if (invalidScopes && invalidScopes.length > 0) {
          console.log("Invalid scopes in refresh token request:", {
            requestedScopes: props.scope,
            validScopes: scope,
          });
          return; // Return if there are invalid scopes in the request
        }

        return await Promise.resolve({
          id: "my-client",
          redirectUris: ["http://localhost/callback"],
          grants: ["urn:ietf:params:oauth:grant-type:device_code"],
          scopes: ["content:read", "content:write"],
          metadata: {
            // You can include any additional metadata here that you want
            // to be available in the grant context for generating the access token
            newScope: props.scope || scope,
            exampleMetadata: "exampleValue",
          },
        });
      }
      return; // Return if the client is not found or the refresh token is invalid
    }
    if (clientId === "my-client" && props.deviceCode.startsWith("device-code-")) {
      const scope = props.deviceCode.slice("device-code-".length).split(",");
      return await Promise.resolve({
        id: "my-client",
        redirectUris: ["http://localhost/callback"],
        grants: ["urn:ietf:params:oauth:grant-type:device_code"],
        scopes: ["content:read", "content:write"],
        metadata: {
          // You can include any additional metadata here that you want
          // to be available in the grant context for generating the access token
          newScope: scope,
          exampleMetadata: "exampleValue",
        },
      });
    }
  })
  .generateAccessToken(
    ({
      accessTokenLifetime: _a,
      client,
      grantType: _g,
      tokenType: _t,
      deviceCode,
    }) => {
      console.log("generateAccessToken called with:", {
        client,
        grantType: _g,
        tokenType: _t,
      });
      // In a real implementation, you would generate a secure token here
      if (deviceCode.startsWith("device-code-") && Array.isArray(client.metadata?.newScope)) {
        return {
          accessToken: "admin-" + client.metadata?.newScope.join(","),
          scope: client.metadata?.newScope,
          refreshToken: "valid-refresh-token-" + client.metadata?.newScope.join(","),
        };
      }
    },
  )
  .generateAccessTokenFromRefreshToken(
    (context) => {
      console.log("generateAccessTokenFromRefreshToken called with:", {
        client: context.client,
        grantType: context.grantType,
        tokenType: context.tokenType,
      });
      // In a real implementation, you would generate a secure token here
      if (
        context.refreshToken.startsWith("valid-refresh-token-") &&
        Array.isArray(context.client.metadata?.newScope)
      ) {
        return {
          accessToken: "admin-" + context.refreshToken.slice("valid-refresh-token-".length),
          scope: context.client.metadata?.newScope,
        };
      }
    },
  )
  // -- handlers for token verification and failed authorization

  .tokenVerifier(verifyTokenFunction)
  .failedAuthorizationAction((_, error) => {
    // You can perform additional actions here, such as logging or modifying the response
    console.log("Authorization failed:", { error: error.name, message: error.message });
    let message: string;
    if (Deno.env.get("DENO_ENV") === "production") {
      message = error instanceof StrategyInternalError ? "Internal Server Error" : "Unauthorized";
    } else {
      message = error.message;
    }
    throw new HTTPException(401, {
      message,
    });
  })
  .build();
