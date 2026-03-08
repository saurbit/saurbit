// impl/authorization_code.ts

import { StrategyInternalError } from "@saurbit/oauth2-server";

import { BearerTokenType, HonoOIDCAuthorizationCodeFlow } from "../oauth2_hono_adapter/mod.ts";
import { HTTPException } from "hono/http-exception";
import { html } from "hono/html";
import { verifyTokenFunction } from "./common.ts";

export class HTTPRateLimitException extends HTTPException {
  constructor(message: string) {
    super(429, { message });
  }
}

export const oidcAuthorizationCodeFlow = new HonoOIDCAuthorizationCodeFlow({
  discoveryUrl: "http://localhost/.well-known/openid-configuration",
  jwksUri: "/jwks",
  parseAuthorizationEndpointBody: async (context) => {
    const formData = await context.req.formData();
    const username = formData.get("username");
    const password = formData.get("password");
    console.log("Parsing authorization endpoint body:", { username, password });
    if (username === "gg") {
      throw new HTTPRateLimitException("Rate limit exceeded");
    }
    return {
      username: typeof username === "string" ? username : "",
      password: typeof password === "string" ? password : "",
    };
  },
  model: {
    // -- at authorization endpoint

    getClientForAuthentication: async ({
      clientId,
      redirectUri,
      responseType: _rt,
      codeChallenge: _cc,
      state: _s,
      scope: _scope,
      nonce: _n,
      prompt: _p,
    }) => {
      console.log("getClientForAuthentication called with:", {
        clientId,
        redirectUri,
        responseType: _rt,
        codeChallenge: _cc,
        state: _s,
        scopes: _scope,
      });
      if (clientId === "my-client") {
        return await Promise.resolve({
          id: "my-client",
          redirectUris: ["http://localhost/callback"],
          grants: ["authorization_code"],
          scopes: ["content:read", "content:write"],
        });
      }
    },

    getUserForAuthentication: async (
      {
        client: _c,
        redirectUri: _r,
        responseType: _rt,
        codeChallenge: _cc,
        state: _s,
        scope: _scope,
        nonce: _n,
        prompt: _p,
      },
      { username, password },
    ) => {
      console.log("getUserForAuthentication called with:", {
        client: _c,
        redirectUri: _r,
        responseType: _rt,
        codeChallenge: _cc,
        state: _s,
        scopes: _scope,
        username,
        password,
      });
      // In a real implementation, you would authenticate the user here based on the request data (e.g. form data, headers, etc.)
      // For this example, we'll just return a dummy user object
      if (username === "user" && password === "crossterm") {
        return await Promise.resolve({
          type: "authenticated",
          user: {
            username: "user",
            level: 1,
          },
        });
      }

      if (username === "noconsent" && password === "crossterm") {
        return await Promise.resolve({
          type: "authenticated",
          user: {
            username: "noconsent",
            level: 2,
          },
        });
      }
    },

    generateAuthorizationCode: async ({
      client: _c,
      redirectUri: _r,
      responseType: _rt,
      codeChallenge: _cc,
      scope,
      state: _s,
      nonce: _n,
      prompt: _p,
    }, user) => {
      console.log("generateAuthorizationCode called with:", {
        client: _c,
        redirectUri: _r,
        scope,
        user,
      });

      if (user?.username === "noconsent") {
        return {
          type: "deny",
          message: "User did not consent to the authorization request",
        };
      }

      // In a real implementation, you would generate a secure code here and associate it with the client, redirect URI, scope, and user
      return await Promise.resolve({
        type: "code",
        code: "authcode-" + scope.join(","),
      });
    },

    // -- at token endpoint

    getClient: async ({ clientId, clientSecret: _c, ...props }) => {
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
            grants: ["authorization_code"],
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
      if (clientId === "my-client" && props.code.startsWith("authcode-")) {
        const scope = props.code.slice("authcode-".length).split(",");
        return await Promise.resolve({
          id: "my-client",
          redirectUris: ["http://localhost/callback"],
          grants: ["authorization_code"],
          scopes: ["content:read", "content:write"],
          metadata: {
            // You can include any additional metadata here that you want
            // to be available in the grant context for generating the access token
            newScope: scope,
            exampleMetadata: "exampleValue",
          },
        });
      }
    },
    generateAccessToken: ({
      accessTokenLifetime: _a,
      client,
      grantType: _g,
      tokenType: _t,
      code,
      redirectUri: _r,
      codeVerifier: _cv,
    }) => {
      console.log("generateAccessToken called with:", {
        client,
        grantType: _g,
        tokenType: _t,
      });
      // In a real implementation, you would generate a secure token here
      if (code.startsWith("authcode-") && Array.isArray(client.metadata?.newScope)) {
        return {
          accessToken: "admin-" + client.metadata?.newScope.join(","),
          scope: client.metadata?.newScope,
          refreshToken: "valid-refresh-token-" + client.metadata?.newScope.join(","),
          idToken: '{"sub":"1234567890","name":"John Doe","admin":true}', // Example ID token payload
        };
      }
    },
    generateAccessTokenFromRefreshToken: (context) => {
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
  },
  strategyOptions: {
    failedAuthorizationAction: (_, error) => {
      // You can perform additional actions here, such as logging or modifying the response
      console.log("Authorization failed:", {
        error: error.name,
        message: error.message,
      });
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
  securitySchemeName: "honoAuthorizationCode",
});

// Configure the authorization code flow with both
// - client secret basic authentication method and
// - client secret post authentication methods
oidcAuthorizationCodeFlow
  .clientSecretBasicAuthenticationMethod()
  .clientSecretPostAuthenticationMethod();

// Set the token type to Bearer
oidcAuthorizationCodeFlow.setTokenType(new BearerTokenType());

// Set the description and scopes for the OpenAPI documentation
oidcAuthorizationCodeFlow
  .setDescription("Authorization Code Grant Flow for Hono API")
  .setScopes({
    "content:read": "Read content",
    "content:write": "Write content",
    admin: "Admin access",
  })
  .setTokenUrl("/token") // Set the token URL for the OpenAPI documentation
  .setAuthorizationUrl("/authorize"); // Set the authorization URL for the OpenAPI documentation

export const HtmlFormContent = (props: {
  errorMessage?: string;
  username?: string;
  usernameField: string;
  passwordField: string;
}) =>
  html`
    <!DOCTYPE html>
    <html lang="en">
      <head>
        <meta charset="UTF-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1.0" />
        <title>OIDC Sign in</title>
        <style>
        :root {
          --bg: #0f172a;
          --card: #111827;
          --accent: #6366f1;
          --text: #e5e7eb;
          --muted: #9ca3af;
          --ring: rgba(99, 102, 241, 0.35);
        }
        * {
          box-sizing: border-box;
        }
        body {
          margin: 0;
          min-height: 100vh;
          display: grid;
          place-items: center;
          background: radial-gradient(
            1200px 600px at 20% 0%,
            #1f2937,
            var(--bg)
          );
          font-family:
            system-ui,
            -apple-system,
            Segoe UI,
            Roboto,
            "Helvetica Neue",
            Arial,
            sans-serif;
          color: var(--text);
        }
        .card {
          width: 92%;
          max-width: 380px;
          padding: 26px 24px;
          border-radius: 16px;
          background: linear-gradient(
            180deg,
            rgba(255, 255, 255, 0.04),
            rgba(255, 255, 255, 0.02)
          );
          border: 1px solid rgba(255, 255, 255, 0.08);
          box-shadow: 0 20px 50px rgba(0, 0, 0, 0.35);
          backdrop-filter: blur(8px);
        }
        .error {
          background: rgba(239, 68, 68, 0.15);
          color: #f87171;
          border: 1px solid rgba(239, 68, 68, 0.4);
          padding: 10px 14px;
          border-radius: 10px;
          font-size: 0.9rem;
          margin-bottom: 14px;
        }
        .title {
          font-size: 1.25rem;
          font-weight: 600;
          letter-spacing: 0.2px;
          margin: 0 0 8px;
        }
        .subtitle {
          color: var(--muted);
          font-size: 0.95rem;
          margin: 0 0 18px;
        }
        label {
          display: block;
          font-size: 0.85rem;
          color: var(--muted);
          margin: 12px 0 8px;
        }
        .field {
          display: flex;
          align-items: center;
          gap: 8px;
          background: #0b1220;
          border: 1px solid rgba(255, 255, 255, 0.08);
          padding: 12px 14px;
          border-radius: 12px;
          transition:
            border-color 0.2s,
            box-shadow 0.2s,
            transform 0.05s;
          }
          .field:focus-within {
            border-color: var(--accent);
            box-shadow: 0 0 0 4px var(--ring);
          }
          .field input {
            all: unset;
            flex: 1;
            color: var(--text);
            caret-color: var(--accent);
          }
          .icon {
            width: 18px;
            height: 18px;
            opacity: 0.7;
            filter: drop-shadow(0 1px 0 rgba(0, 0, 0, 0.35));
          }
          .actions {
            margin-top: 18px;
            display: flex;
            align-items: center;
            justify-content: space-between;
          }
          .btn {
            appearance: none;
            border: none;
            cursor: pointer;
            background: linear-gradient(135deg, #7c3aed, var(--accent));
            color: white;
            padding: 12px 16px;
            border-radius: 12px;
            font-weight: 600;
            box-shadow: 0 10px 20px rgba(99, 102, 241, 0.35);
            transition:
              transform 0.05s,
              filter 0.2s;
            }
            .btn:hover {
              filter: brightness(1.05);
            }
            .btn:active {
              transform: translateY(1px);
            }
          </style>
        </head>
        <body>
          <form class="card" method="POST">
            <p class="subtitle">OIDC: Sign in to continue</p>
            ${props.errorMessage
              ? html`
                <p class="error" id="error-message">${props.errorMessage}</p>
              `
              : ""}

            <label for="${props.usernameField}">${props.usernameField}</label>
            <div class="field">
              <svg
                class="icon"
                viewBox="0 0 24 24"
                fill="currentColor"
                aria-hidden="true"
              >
                <path
                  d="M12 12a5 5 0 1 0-5-5 5 5 0 0 0 5 5Zm0 2c-4.42 0-8 2.18-8 4.87V21h16v-2.13C20 16.18 16.42 14 12 14Z"
                />
              </svg>
              <input
                id="${props.usernameField}"
                name="${props.usernameField}"
                type="text"
                placeholder="${props.usernameField}"
                autocomplete="${props.usernameField}"
                value="${props.username || ""}"
              />
            </div>

            <label for="${props.passwordField}">${props.passwordField}</label>
            <div class="field">
              <svg
                class="icon"
                viewBox="0 0 24 24"
                fill="currentColor"
                aria-hidden="true"
              >
                <path
                  d="M17 8V7a5 5 0 0 0-10 0v1H5v12h14V8Zm-8 0V7a3 3 0 0 1 6 0v1Z"
                />
              </svg>
              <input
                id="${props.passwordField}"
                name="${props.passwordField}"
                type="password"
                placeholder="••••••••"
                autocomplete="current-password"
              />
            </div>

            <div class="actions">
              <button class="btn" type="submit">Sign in</button>
            </div>
          </form>
        </body>
      </html>
    `;
