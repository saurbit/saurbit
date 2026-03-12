import { Hono } from "hono";
import { type } from "arktype";

import {
  describeRoute,
  openAPIRouteHandler,
  resolver,
  validator as arktypeValidator,
} from "hono-openapi";
import { swaggerUI } from "@hono/swagger-ui";

import { UnauthorizedClientError, UnsupportedGrantTypeError } from "@saurbit/oauth2-server";

import { clientCredentialsFlow } from "./impl/client_credentials.ts";
import { authorizationCodeFlow, HtmlFormContent } from "./impl/authorization_code.ts";
import { oauth2Redirect } from "./swagger_ui/oauth2_redirect.ts";
import { AccessDeniedError } from "@saurbit/oauth2-server";
import { HTTPRateLimitException } from "./impl/common.ts";

const app = new Hono();

app.get(
  "/",
  describeRoute({
    responses: {
      200: {
        description: "Successful response",
        content: {
          "application/json": {
            schema: {
              type: "object",
              properties: {
                message: { type: "string" },
              },
            },
          },
        },
      },
    },
  }),
  (c) => {
    return c.json({ message: "Hello from Hono!" });
  },
);

app.get("/authorize", async (c) => {
  const result = await authorizationCodeFlow.hono().handleAuthorizationEndpoint(c);
  if (result.type === "initiated") {
    return c.html(HtmlFormContent({ usernameField: "username", passwordField: "password" }));
  } else if (result.type === "error") {
    const error = result.error;
    console.log("Authorization endpoint error:", { error: error.name, message: error.message });
    return c.json({ error: "invalid_request" }, 400);
  }
});

app.post("/authorize", async (c) => {
  try {
    // Here you would typically validate the user's credentials and then proceed with the authorization process
    const result = await authorizationCodeFlow.hono().processAuthorization(c);

    if (result.type === "error") {
      // for security reasons, it is recommended to return a generic error message in production instead of the specific error message
      const error = result.error;
      console.log("Authorization endpoint error:", { error: error.name, message: error.message });

      if (result.redirectable) {
        // If the error is redirectable, redirect the user to the client's redirect_uri with the error and state as query parameters
        const qs = [
          `error=${
            encodeURIComponent(
              error instanceof AccessDeniedError ? error.errorCode : "invalid_request",
            )
          }`,
          `error_description=${
            encodeURIComponent(
              error instanceof AccessDeniedError ? error.message : "Invalid request",
            )
          }`,
          result.state ? `state=${encodeURIComponent(result.state)}` : null,
        ].filter(Boolean).join("&");

        return c.redirect(`${result.redirectUri}?${qs}`);
      }

      // If the error is not redirectable, render an error message
      return c.html(
        HtmlFormContent({
          usernameField: "username",
          passwordField: "password",
          errorMessage: error.message,
        }),
        400,
      );
    }

    if (result.type === "code") {
      // redirect the user to the client's redirect_uri with the authorization code and state as query parameters
      const { user, code, context: { state, redirectUri } } = result.authorizationCodeResponse;
      console.log("Authorization successful:", {
        user: user?.username,
        code,
        state,
      });

      const searchParams = new URLSearchParams();
      searchParams.set("code", code);
      if (state) {
        searchParams.set("state", state);
      }

      return c.redirect(`${redirectUri}?${searchParams.toString()}`);
    } else if (result.type === "continue") {
      // In a real implementation, you would render a consent page here for the user to authorize the client to access their resources.
      return c.json({ message: "Consent page was not implemented" }, 500);
    } else if (result.type === "unauthenticated") {
      // render the login page with an optional error message
      return c.html(
        HtmlFormContent({
          usernameField: "username",
          passwordField: "password",
          errorMessage: result.message || "Authentication failed. Please try again.",
        }),
        400,
      );
    }
  } catch (error) {
    // unexpected errors should be logged and a generic error message should be returned to the user
    if (error instanceof HTTPRateLimitException) {
      return c.html(
        HtmlFormContent({
          usernameField: "username",
          passwordField: "password",
          errorMessage: error.message,
        }),
        429,
      );
    }
    console.log("Unexpected error at authorization endpoint:", {
      error: error instanceof Error ? { name: error.name, message: error.message } : error,
    });
    return c.html(
      HtmlFormContent({
        usernameField: "username",
        passwordField: "password",
        errorMessage: "An unexpected error occurred. Please try again later.",
      }),
      500,
    );
  }
});

const schema = type({
  name: "string",
  age: "number",
});

const responseSchema = type({
  success: "boolean",
  message: "string",
});

app.post(
  "/author",
  // Apply the authentication middleware to this route
  clientCredentialsFlow.hono().authorizeMiddleware(["content:read", "content:write"]),
  // Add OpenAPI documentation for this route, including the security requirements and response schema
  describeRoute({
    security: [
      authorizationCodeFlow.toOpenAPIPathItem(["content:read", "content:write"]),
      clientCredentialsFlow.toOpenAPIPathItem(["content:read", "content:write"]),
    ],
    responses: {
      200: {
        description: "Successful response",
        content: {
          "application/json": {
            schema: resolver(responseSchema),
          },
        },
      },
    },
  }),
  arktypeValidator("json", schema),
  (c) => {
    const username = c.var.credentials?.user?.username;
    const data = c.req.valid("json");
    return c.json({
      success: true,
      message: `${data.name} is ${data.age}`,
      username,
      me: c.get("credentials"), // this will contain the credentials set by the authentication middleware
    });
  },
);

app.post(
  "/token",
  async (c) => {
    console.log("Token endpoint called with body");
    //const result = await clientCredentialsFlow.hono().token(c);
    const result = await authorizationCodeFlow.hono().token(c);
    if (result.success) {
      return c.json(result.tokenResponse);
    } else {
      // for security reasons, it is recommended to return a generic error message in production instead of the specific error message
      const error = result.error;
      if (error instanceof UnsupportedGrantTypeError || error instanceof UnauthorizedClientError) {
        return c.json(
          { error: result.error.errorCode, errorDescription: result.error.message },
          400,
        );
      } else {
        console.log("Token endpoint error:", { error: error.name, message: error.message });
        return c.json({ error: "invalid_request" }, 400);
      }
    }
  },
);

app.get(
  "/openapi.json",
  openAPIRouteHandler(app, {
    documentation: {
      info: {
        title: "Astre Hono t",
        version: "1.0.0",
        description: "API for greeting users",
      },
      components: {
        securitySchemes: {
          ...authorizationCodeFlow.toOpenAPISecurityScheme(),
          ...clientCredentialsFlow.toOpenAPISecurityScheme(),
        },
      },
    },
  }),
);

app.get("/docs/ui", swaggerUI({ url: "/openapi.json" }));
// Serve the oauth2 redirect handler
app.get("/docs/oauth2-redirect.html", oauth2Redirect);

app.get("/health", (c) => c.text("OK"));

Deno.serve({ port: 3000 }, app.fetch);
