# @saurbit/hono-oauth2

This package provides an adapter to integrate the OAuth 2.0 flows from `@saurbit/oauth2` into the
Hono web framework. It allows you to easily implement OAuth 2.0 authorization and token endpoints in
your Hono application using the flows defined in `@saurbit/oauth2`.

## Installation

You can install the package using npm or yarn:

```bash
npm install @saurbit/hono-oauth2 @saurbit/oauth2
```

or

```bash
yarn add @saurbit/hono-oauth2 @saurbit/oauth2
```

## Usage

To use the adapter, import the desired flow builders from `@saurbit/hono-oauth2` and configure them
according to your application's needs. Then, wire the flow's `token()` method into your Hono routes
to handle OAuth 2.0 token requests. Finally, use the flow's `verifyToken()` method on protected
endpoints to validate access tokens.

### 1. Configure the flow

Import the flow builder for the OAuth 2.0 flow you want to implement (e.g., Authorization Code,
Client Credentials, Device Authorization) and configure it with the necessary options and handlers.
For example, to set up an Client Credentials flow:

```ts
import { HonoClientCredentialsFlowBuilder } from "@saurbit/hono-oauth2";
import { HTTPException } from "hono/http-exception";

export const clientCredentialsFlow = HonoClientCredentialsFlowBuilder
  .create()
  .setSecuritySchemeName("clientCredentials")
  .setDescription("Client Credentials Flow for machine-to-machine authentication")
  .setScopes({
    "content:read": "Read content",
    "content:write": "Write content",
    "admin": "Admin access",
  })
  .setTokenEndpoint("/token")
  .setAccessTokenLifetime(3600)
  .clientSecretBasicAuthenticationMethod()
  .getClient(async (tokenRequest) => {
    // Look up the client by ID/secret and return it, or undefined if not found.
    return undefined;
  })
  .generateAccessToken(
    async (grantContext) => {
      // Generate and return an access token string for the authenticated client.
      return undefined;
    },
  )
  .verifyTokenHandler((request, { token }) => {
    // Implement logic to verify the access token.
    if (token === "valid-token") {
      return { isValid: true, credentials: { app: { clientId: "example-client" } } };
    }
    return { isValid: false };
  })
  .failedAuthorizationAction((_, error) => {
    // You can perform additional actions here, such as logging or modifying the response
    throw new HTTPException(401, {
      message: error instanceof StrategyInternalError ? "Internal Server Error" : "Unauthorized",
    });
  }).build();
```

This example sets up a Client Credentials flow with basic client authentication, custom token
generation and verification logic, and a custom error handler for failed authorization attempts.

### 2. Wire it into Hono routes

Use the flow's `hono().token()` method in your Hono routes to handle token requests.

```ts
import { Hono } from "@hono/hono";
import { UnauthorizedClientError, UnsupportedGrantTypeError } from "@saurbit/oauth2";

const app = new Hono();

app.post(flow.getTokenEndpoint(), async (c) => {
  const result = await flow.hono().token(c);
  if (result.type === "success") {
    return c.json(result.tokenResponse);
  } else {
    const error = result.error;
    if (error instanceof UnauthorizedClientError || error instanceof UnsupportedGrantTypeError) {
      return c.json(
        { error: error.errorCode, errorDescription: error.message },
        400,
      );
    } else {
      return c.json({ error: "invalid_request" }, 400);
    }
  }
});
```

Then, use the flow's `hono().authorizeMiddleware()` on protected routes to verify access tokens and
enforce scopes:

```ts
app.get(
  "/protected",
  flow.hono().authorizeMiddleware(["content:read"]),
  async (c) => c.text(`Hello, ${c.get("credentials")?.app?.clientId}!`),
);
```
