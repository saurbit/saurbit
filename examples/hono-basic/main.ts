import { Hono } from 'hono'
import { type } from 'arktype'
import {
  validator as arktypeValidator,
  resolver,
  describeRoute,
  openAPIRouteHandler
} from "hono-openapi";
import { swaggerUI } from '@hono/swagger-ui'

import { createAuthMiddleware, BearerTokenType } from "./oauth2_hono_adapter.ts";

const app = new Hono();

app.get("/",  describeRoute({}), (c) => {
  return c.json({ message: "Hello from Hono!" });
});

const schema = type({
  name: 'string',
  age: 'number',
})

const responseSchema = type({
  success: 'boolean',
  message: 'string',
})

const auth = createAuthMiddleware({
  tokenType: new BearerTokenType(),
  verifyToken: (_c, { token }) => {
    if (token === 'admin') {
      return {
        isValid: true,
        credentials: {
          user: {
            username: 'admin',
            level: 50
          }
        }
      }
    }

    return { isValid: false }
  }
})

app.post(
  '/author',

  // Apply the authentication middleware to this route
  auth,

  //
  describeRoute({
    security: [
      {
        bearerAuth: [],
      },
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
  arktypeValidator('json', schema),
  (c) => {
    const data = c.req.valid('json')
    return c.json({
      success: true,
      message: `${data.name} is ${data.age}`,
    })
  })

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
          bearerAuth: {
            type: "http",
            scheme: "bearer",
            bearerFormat: "JWT",
          },
        },
      }
    },
  }),
);

app.get('/ui', swaggerUI({ url: '/openapi.json' }))

app.get('/health', (c) => c.text('OK'))

Deno.serve({ port: 3000 }, app.fetch);
