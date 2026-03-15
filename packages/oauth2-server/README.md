# @saurbit/oauth2-server

A framework-agnostic [OAuth 2.0](https://datatracker.ietf.org/doc/html/rfc6749) authorization server
implementation for [Deno](https://deno.land/).

## Features

- **Authorization Code** flow (with PKCE support)
- **Client Credentials** flow
- **Device Authorization** flow
- Framework-agnostic - bring your own HTTP layer
- Pluggable model interface for storage

## Quick Start

### 1. Create a flow

Use `ClientCredentialsFlowBuilder` (or its counterparts for other grant types) to configure a flow
with your client lookup and token generation logic:

```ts
import { ClientCredentialsFlowBuilder } from "@saurbit/oauth2-server";

const flow = new ClientCredentialsFlowBuilder({
  securitySchemeName: "clientCredentials",
})
  .getClient((tokenRequest) => {
    // Look up the client by ID/secret and return it, or undefined if not found.
    return undefined;
  })
  .generateAccessToken((grantContext) => {
    // Generate and return an access token string for the authenticated client.
    return undefined;
  })
  .clientSecretBasicAuthenticationMethod()
  .build();
```

### 2. Wire it into your HTTP framework

The flow's `token()` method accepts a web-standard
[`Request`](https://developer.mozilla.org/en-US/docs/Web/API/Request) and returns a typed result
object, no framework-specific dependencies. Below is an example using [Oak](https://jsr.io/@oak/oak):

> **Note:** Oak's `ctx.request` is its own wrapper class, not a web-standard `Request`. Use
> `ctx.request.source` to get the underlying native request.

```ts
import { Application, Router } from "@oak/oak";

const router = new Router();

router.post("/token", async (ctx) => {
  try {
    const result = await flow.token(ctx.request.source as Request);

    if (!result.success) {
      ctx.response.status = result.error.statusCode ?? 400;
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

const app = new Application();
app.use(router.routes());
app.use(router.allowedMethods());
app.listen({ port: 8000 });
```

### 3. Generate an OpenAPI security scheme (optional)

```ts
const securityScheme = flow.toOpenAPISecurityScheme();
```

## License

[MIT](../../LICENSE)
