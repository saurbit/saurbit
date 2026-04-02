# @saurbit/hono-oauth2

[Hono](https://hono.dev/) adapter for `@saurbit/oauth2`. Provides flow builders, token endpoints,
and authorization middleware for your Hono application.

## Supported Flows

This package adapts all OAuth 2.0 flows supported by `@saurbit/oauth2`:

| Hono Builder                                   | Grant Type                             |
| ---------------------------------------------- | -------------------------------------- |
| `HonoAuthorizationCodeFlowBuilder`             | Authorization Code (with PKCE support) |
| `HonoClientCredentialsFlowBuilder`             | Client Credentials                     |
| `HonoDeviceAuthorizationFlowBuilder`           | Device Authorization                   |
| `HonoOIDCAuthorizationCodeFlowBuilder`         | OIDC Authorization Code                |
| `HonoOIDCClientCredentialsFlowBuilder`         | OIDC Client Credentials                |
| `HonoOIDCDeviceAuthorizationFlowBuilder`       | OIDC Device Authorization              |

### Multiple flows

`HonoOIDCMultipleFlows` lets you combine several OIDC flows behind a single interface. It tries
each registered flow in order and returns the first successful result, making it straightforward to
support multiple grant types on the same server.

### The `hono()` method

Every flow class exposes a `hono()` method that returns a frozen set of Hono-adapted helpers:

| Method                           | Description                                                                                     |
| -------------------------------- | ----------------------------------------------------------------------------------------------- |
| `token(c)`                       | Handles a token endpoint request using the Hono context.                                        |
| `verifyToken(c)`                 | Extracts and verifies the bearer token, returning a typed result.                               |
| `authorizeMiddleware(scopes?)`   | Returns a middleware that enforces token validity and optional scope requirements on a route. On success it sets `c.get("credentials")` for downstream handlers. |

```ts
// token endpoint
app.post("/token", async (c) => {
  const result = await flow.hono().token(c);
  // ...
});

// verify token manually
const result = await flow.hono().verifyToken(c);

// protect a route
app.get("/resource", flow.hono().authorizeMiddleware(["read"]), handler);
```

## Installation

```bash
npm install @saurbit/hono-oauth2 @saurbit/oauth2
```

## Quick Start

### 1. Configure a flow

```ts
import { HonoClientCredentialsFlowBuilder } from "@saurbit/hono-oauth2";
import { HTTPException } from "hono/http-exception";

export const flow = HonoClientCredentialsFlowBuilder
  .create()
  .setSecuritySchemeName("clientCredentials")
  .setScopes({
    "content:read": "Read content",
    "content:write": "Write content",
  })
  .setTokenEndpoint("/token")
  .setAccessTokenLifetime(3600)
  .clientSecretBasicAuthenticationMethod()
  .getClient(async (tokenRequest) => {
    // Look up and return the client, or undefined if not found
    return undefined;
  })
  .generateAccessToken(async (grantContext) => {
    // Return an access token string
    return undefined;
  })
  .tokenVerifier((ctxt, { token }) => {
    if (token === "valid-token") {
      return { isValid: true, credentials: { app: { clientId: "example-client" } } };
    }
    return { isValid: false };
  })
  .failedAuthorizationAction((_, error) => {
    throw new HTTPException(401, {
      message: error instanceof StrategyInternalError ? "Internal Server Error" : "Unauthorized",
    });
  })
  .build();
```

### 2. Add the token endpoint

```ts
import { Hono } from "@hono/hono";
import { UnauthorizedClientError, UnsupportedGrantTypeError } from "@saurbit/oauth2";

const app = new Hono();

app.post(flow.getTokenEndpoint(), async (c) => {
  const result = await flow.hono().token(c);

  if (result.type === "success") {
    return c.json(result.tokenResponse);
  }

  const error = result.error;
  if (error instanceof UnauthorizedClientError || error instanceof UnsupportedGrantTypeError) {
    return c.json({ error: error.errorCode, errorDescription: error.message }, 400);
  }
  return c.json({ error: "invalid_request" }, 400);
});
```

### 3. Protect routes

Use `authorizeMiddleware()` to verify tokens and enforce scopes:

```ts
app.get(
  "/protected",
  flow.hono().authorizeMiddleware(["content:read"]),
  async (c) => c.text(`Hello, ${c.get("credentials")?.app?.clientId}!`),
);
```

## License

[MIT](./LICENSE)
