// main_cas.ts for Oak framework with Client Credentials Flow and Client Secret JWT authentication

import { Application, Router } from "@oak/oak";
import {
  ClientCredentialsFlowBuilder,
  ClientSecretJwt,
  ClientSecretJwtAlgorithms,
} from "@saurbit/oauth2";
import { createJwtVerify, decodeJwt } from "@saurbit/oauth2-jwt";

const CLIENT_SECRET = `abcd1234efgh5678ijkl9012mnop3456qrst7890uvwx1234yzab5678cdef9012`;

const flow = new ClientCredentialsFlowBuilder({
  securitySchemeName: "clientCredentials",
})
  .setScopes({
    "read": "Read access to protected resources",
    "write": "Write access to protected resources",
  })
  .setTokenEndpoint("/token")
  .clientSecretBasicAuthenticationMethod()
  .addClientAuthenticationMethod(
    new ClientSecretJwt(
      decodeJwt,
      createJwtVerify({
        audience: "http://localhost:8000/token",
      }),
    )
      .addAlgorithm(ClientSecretJwtAlgorithms.HS256)
      .getClientSecret((clientId) => {
        // Implement logic to retrieve the public key for the given client ID.
        if (clientId === "example-client") {
          return Promise.resolve(CLIENT_SECRET);
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
