import { Hono } from 'hono'
import { type } from 'arktype'
import { OpenAPIV3 } from "openapi-types";
import {
  validator as arktypeValidator,
  resolver,
  describeRoute,
  openAPIRouteHandler
} from "hono-openapi";
import { swaggerUI } from '@hono/swagger-ui'

import {
  UnauthorizedClientError,
  UnsupportedGrantTypeError
} from "@saurbit/oauth2-server";

import {
  //createAuthMiddleware, 
  BearerTokenType,
  HonoClientCredentialsGrantFlow
} from "./oauth2_hono_adapter.ts";


const clientCredentialsFlow = new HonoClientCredentialsGrantFlow({
  model: {
    getClient: async ({
      clientId,
      clientSecret: _c,
      grantType: _g,
      scopes: _s
    }) => {
      console.log("getClient called with:", { clientId, grantType: _g, scopes: _s });
      if (clientId === 'my-client') {
        return await Promise.resolve({
          id: 'my-client',
          redirectUris: [],
          grants: ['client_credentials'],
          scopes: ['content:read', 'content:write']
        })
      }
    },
    generateAccessToken: async ({
      accessTokenLifetime: _a,
      client: _c,
      grantType: _g,
      scopes: _s,
      tokenType: _t
    }) => {
      console.log("generateAccessToken called with:", { client: _c, grantType: _g, scopes: _s, tokenType: _t });
      // In a real implementation, you would generate a secure token here
      return await Promise.resolve('admin');
    }
  },
  strategyOptions: {
    verifyToken: (_context, { token }) => {
      console.log("verifyToken called with token:", token);
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
  },
  accessTokenLifetime: 3600,
  securitySchemeName: 'honoClientCredentials'
});

// Configure the client credentials flow with both 
// - client secret basic authentication method and 
// - client secret post authentication methods
clientCredentialsFlow
  .clientSecretBasicAuthenticationMethod()
  .clientSecretPostAuthenticationMethod();

// Set the token type to Bearer
clientCredentialsFlow.setTokenType(
  new BearerTokenType()
);

// Set the description and scopes for the OpenAPI documentation
clientCredentialsFlow
  .setDescription("Client Credentials Grant Flow for Hono API")
  .setScopes({
    "content:read": "Read content",
    "content:write": "Write content",
    "admin": "Admin access"
  });

const securityScheme: OpenAPIV3.SecuritySchemeObject = {
  type: 'oauth2',
  description: clientCredentialsFlow.getDescription(),
  flows: {
    clientCredentials: {
      scopes: clientCredentialsFlow.getScopes() || {},
      tokenUrl: '/token'
    }
  }
}

const app = new Hono();

app.get("/", describeRoute({}), (c) => {
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

/*
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
*/

app.post(
  '/author',

  // Apply the authentication middleware to this route
  //auth,
  clientCredentialsFlow.authorizeMiddleware(),

  //
  describeRoute({
    security: [
      /*
      {
        bearerAuth: [],
      },
      */
      {
        [clientCredentialsFlow.getSecuritySchemeName()]: [],
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
      me: c.get("credentials") // this will contain the credentials set by the authentication middleware
    })
  })

app.post(
  '/token',
  async (c) => {
    const result = await clientCredentialsFlow.token(c.req.raw);
    if (result.success) {
      return c.json(result.tokenResponse);
    } else {
      // for security reasons, it is recommended to return a generic error message in production instead of the specific error message
      const error = result.error;
      if (error instanceof UnsupportedGrantTypeError || error instanceof UnauthorizedClientError) {
        return c.json({ error: result.error.errorCode, errorDescription: result.error.message }, 400);
      } else {
        return c.json({ error: 'invalid_request' }, 400);
      }
    }
  }
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
          bearerAuth: {
            type: "http",
            scheme: "bearer",
            bearerFormat: "JWT",
          },
          [clientCredentialsFlow.getSecuritySchemeName()]: securityScheme
        },
      }
    },
  }),
);

app.get('/ui', swaggerUI({ url: '/openapi.json' }))

app.get('/health', (c) => c.text('OK'))

Deno.serve({ port: 3000 }, app.fetch);
