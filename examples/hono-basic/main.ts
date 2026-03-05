import { Hono } from "hono";
import { type } from "arktype";
import {
  describeRoute,
  openAPIRouteHandler,
  resolver,
  validator as arktypeValidator,
} from "hono-openapi";
import { swaggerUI } from "@hono/swagger-ui";

import {
  UnauthorizedClientError,
  UnsupportedGrantTypeError,
} from "@saurbit/oauth2-server";

import { clientCredentialsFlow } from "./impl/client_credentials.ts";

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
  clientCredentialsFlow.authorizeMiddleware(["content:read", "content:write"]),
  // Add OpenAPI documentation for this route, including the security requirements and response schema
  describeRoute({
    security: [
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
    const result = await clientCredentialsFlow.tokenFromHono(c);
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
        title: "Hono",
        version: "1.0.0",
        description: "API for greeting users",
      },
      components: {
        securitySchemes: {
          ...clientCredentialsFlow.toOpenAPISecurityScheme(),
        },
      },
    },
  }),
);

app.get("/ui", swaggerUI({ url: "/openapi.json" }));

app.get("/health", (c) => c.text("OK"));

Deno.serve({ port: 3000 }, app.fetch);
