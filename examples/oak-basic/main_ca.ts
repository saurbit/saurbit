// main_ca.ts for Oak framework with Client Credentials Flow and Private Key JWT authentication

import { Application, Router } from "@oak/oak";
import {
  ClientCredentialsFlowBuilder,
  PrivateKeyJwt,
  PrivateKeyJwtAlgorithms,
} from "@saurbit/oauth2";
import { createJwtVerify, decodeJwt } from "@saurbit/oauth2-jwt";
import { exportJWK, importSPKI } from "jose";

const CLIENT_PUBLIC_KEY = `-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA8iGQANAR1Nm9IU2Y0pCo
sf6Wrw7JsURKNIPLouB+yTDtQRzTcioKh5iufTyQTThmhXBh8OPpAlrtmOghIdcp
aZpL91d8MmbDu5ADBV3AxBEYIt+pbttICFyAnjJs4MoAfZlEPDZSRG0ZM1qn6VZT
hutDgJgyFU6Tx6nhxqKF9IVejGAAXu2/kv2c6USL6lL9uQl4Tny1S8gQSYpiMMi4
v0hihxWOYb2KCS1t+Stbq8nEXQ+/yU3AclxdPAIeghsVFR5IKSjWmhg4HoTxVHur
RR8oW4jzpSFGn+Ddunkv/jfu5qFwPY1j4z5kiWVjFWTN5ntqDhUnzOfcSmLPTs6v
wMcPJBD3ULFk2dgBeGhHqmhMatExhO87yEK6YxnUrBVxsKS4INazbiJeOL5e8F5A
wZ+fayDpoxOeredv9UQxhXx1w9Q2rInBbZI0jVgoWhtM+Pp4H2lfjW6F8JnTRAH7
5+yb+SM8yQLkyw9TZ45oHdDh9phC+kYspI7lswTz6UJ3EmPKmrPseJ+pCxqKTVHf
R8a+7So32EpQR7l1XQCr1cZCoRXF1KtDtVTs4v+l/xJJ1yd3ABH1aAl3ZCukxWUG
yD9A0GRYf0JuRDk6zK08z/Q2fvBR1MZTn6WAx7vAxKXomdBipGYklXwMf+5ICXAK
2LQJpf3DaRNpPSCgQpRR8Z8CAwEAAQ==
-----END PUBLIC KEY-----
`;

const flow = new ClientCredentialsFlowBuilder({
  securitySchemeName: "clientCredentials",
})
  .setScopes({
    "read": "Read access to protected resources",
    "write": "Write access to protected resources",
  })
  .setTokenEndpoint("/token")
  .addClientAuthenticationMethod(
    new PrivateKeyJwt(
      decodeJwt,
      createJwtVerify({
        audience: "http://localhost:8000/token",
      }),
    )
      .addAlgorithm(PrivateKeyJwtAlgorithms.RS256)
      .getPublicKeyForClient(async (clientId) => {
        // Implement logic to retrieve the public key for the given client ID.
        if (clientId === "example-client") {
          // Import using jose to get the CryptoKey
          const publicKey = await importSPKI(CLIENT_PUBLIC_KEY, "RS256");
          // Export the public key to JWK format for verification
          const jwk = await exportJWK(publicKey);
          return jwk;
        }
        return Promise.resolve(null);
      }),
  )
  .getClient((tokenRequest) => {
    // Implement logic to retrieve and validate the client.
    // the client_assertion is verified by the PrivateKeyJwt method, so we only need to check the clientId here
    if (
      tokenRequest.clientId === "example-client"
    ) {
      return { id: "example-client", grants: [tokenRequest.grantType], redirectUris: [] };
    }
    return undefined;
  })
  .generateAccessToken((_grantContext) => {
    // Implement logic to generate an access token.
    return "valid-token";
  })
  .verifyToken((_req, { token }) => {
    // Implement logic to verify the access token.
    if (token === "valid-token") {
      return {
        isValid: true,
        credentials: { app: { clientId: "example-client", name: "Example Client" } },
      };
    }
    return { isValid: false };
  })
  .build();

const router = new Router();

router.get("/", (ctx) => {
  ctx.response.body = { message: "Hello, World!" };
});

router.post("/token", async (ctx) => {
  try {
    const result = await flow.token(ctx.request.source as Request);
    if (!result.success) {
      ctx.response.status = result.error.statusCode || 400;
      ctx.response.body = {
        error: result.error.errorCode,
        error_description: result.error.message,
      };
    } else {
      ctx.response.status = 200;
      ctx.response.body = result.tokenResponse;
    }
  } catch (_err) {
    ctx.response.status = 500;
    ctx.response.body = { error: "Internal Server Error" };
  }
});

router.get("/protected", async (ctx, next) => {
  const result = await flow.verifyToken(ctx.request.source as Request);
  if (!result.success) {
    ctx.response.status = 401;
    ctx.response.body = { error: "Unauthorized" };
  } else {
    ctx.state.client = result.credentials.app;
    await next();
  }
}, (ctx) => {
  ctx.response.body = { message: "This is a protected resource.", client: ctx.state.client };
});

router.get("/openapi.json", (ctx) => {
  ctx.response.body = flow.toOpenAPISecurityScheme();
});

const app = new Application();
app.use(router.routes());
app.use(router.allowedMethods());
console.log("Server starting on http://localhost:8000");
await app.listen({ port: 8000 });
