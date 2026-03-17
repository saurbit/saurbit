import { Application, Router } from "@oak/oak";
import { ClientCredentialsFlowBuilder } from "@saurbit/oauth2-server";

const flow = new ClientCredentialsFlowBuilder({
  securitySchemeName: "clientCredentials",
})
  .setTokenEndpoint("/token")
  .clientSecretBasicAuthenticationMethod()
  .getClient((tokenRequest) => {
    // Implement logic to retrieve and validate the client.
    if (
      tokenRequest.clientId === "example-client" && tokenRequest.clientSecret === "example-secret"
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
