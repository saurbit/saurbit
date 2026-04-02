import { assertEquals, assertInstanceOf } from "@std/assert";
import { type Context, Hono } from "hono";
import { HTTPException } from "hono/http-exception";
import {
  HonoClientCredentialsFlow,
  HonoClientCredentialsFlowBuilder,
} from "../src/client_credentials.ts";
import type { HonoClientCredentialsFlowOptions } from "../src/client_credentials.ts";
import { StrategyError, StrategyInvalidTokenError } from "@saurbit/oauth2";

function createStubOptions(): HonoClientCredentialsFlowOptions {
  return {
    model: {
      getClient: () => Promise.resolve(undefined),
      generateAccessToken: () => Promise.resolve(undefined),
    },
    strategyOptions: {},
  };
}

//#region HonoClientCredentialsFlow

Deno.test("HonoClientCredentialsFlow - can be instantiated with default options", () => {
  const flow = new HonoClientCredentialsFlow(createStubOptions());
  assertEquals(flow.getAccessTokenLifetime(), 3600);
  assertEquals(flow.grantType, "client_credentials");
});

Deno.test("HonoClientCredentialsFlow - hono() returns frozen methods object", () => {
  const flow = new HonoClientCredentialsFlow(createStubOptions());
  const hono = flow.hono();
  assertEquals(typeof hono.token, "function");
  assertEquals(typeof hono.verifyToken, "function");
  assertEquals(typeof hono.authorizeMiddleware, "function");
  assertEquals(Object.isFrozen(hono), true);
});

Deno.test("HonoClientCredentialsFlow - token() returns error for missing credentials", async () => {
  const flow = new HonoClientCredentialsFlow({
    ...createStubOptions(),
    clientAuthenticationMethods: ["client_secret_basic"],
  });

  const app = new Hono();
  app.post("/token", async (c) => {
    const result = await flow.hono().token(c);
    return c.json(result);
  });

  const res = await app.request("/token", { method: "POST" });
  const body = await res.json();
  assertEquals(body.success, false);
});

Deno.test("HonoClientCredentialsFlow - token() returns success for valid client", async () => {
  const flow = HonoClientCredentialsFlowBuilder.create()
    .clientSecretBasicAuthenticationMethod()
    .getClient(({ clientId, clientSecret }) => {
      if (clientId === "test-client" && clientSecret === "test-secret") {
        return Promise.resolve({
          id: "test-client",
          redirectUris: [],
          grants: ["client_credentials"],
          scopes: ["read"],
        });
      }
      return Promise.resolve(undefined);
    })
    .generateAccessToken(() => Promise.resolve({ accessToken: "tok_abc123" }))
    .build();

  const app = new Hono();
  app.post("/token", async (c) => {
    const result = await flow.hono().token(c);
    if (result.success) {
      return c.json(result.tokenResponse);
    }
    return c.json({ error: result.error.errorCode }, (result.error.statusCode ?? 400) as 400);
  });

  const credentials = btoa("test-client:test-secret");
  const res = await app.request("/token", {
    method: "POST",
    headers: {
      "Authorization": `Basic ${credentials}`,
      "Content-Type": "application/x-www-form-urlencoded",
    },
    body: "grant_type=client_credentials",
  });

  assertEquals(res.status, 200);
  const body = await res.json();
  assertEquals(body.access_token, "tok_abc123");
  assertEquals(body.token_type, "Bearer");
});

Deno.test("HonoClientCredentialsFlow - authorizeMiddleware sets credentials on valid token", async () => {
  const flow = HonoClientCredentialsFlowBuilder.create()
    .clientSecretBasicAuthenticationMethod()
    .getClient(() => Promise.resolve(undefined))
    .generateAccessToken(() => Promise.resolve(undefined))
    .verifyTokenHandler((_context, { token }) => {
      if (token === "valid-token") {
        return Promise.resolve({
          isValid: true,
          credentials: { app: { clientId: "test" }, scope: ["read"] },
        });
      }
      return Promise.resolve({ isValid: false });
    })
    .build();

  const app = new Hono();
  app.get("/protected", flow.hono().authorizeMiddleware(), (c) => {
    const credentials = c.get("credentials");
    return c.json({ clientId: (credentials?.app as Record<string, unknown>)?.clientId });
  });

  const res = await app.request("/protected", {
    headers: { "Authorization": "Bearer valid-token" },
  });

  assertEquals(res.status, 200);
  const body = await res.json();
  assertEquals(body.clientId, "test");
});

Deno.test("HonoClientCredentialsFlow - authorizeMiddleware returns 401 for invalid token", async () => {
  const flow = HonoClientCredentialsFlowBuilder.create()
    .clientSecretBasicAuthenticationMethod()
    .getClient(() => Promise.resolve(undefined))
    .generateAccessToken(() => Promise.resolve(undefined))
    .verifyTokenHandler(() => Promise.resolve({ isValid: false }))
    .build();

  const app = new Hono();
  app.get("/protected", flow.hono().authorizeMiddleware(), (c) => {
    return c.json({ ok: true });
  });

  const res = await app.request("/protected", {
    headers: { "Authorization": "Bearer bad-token" },
  });

  assertEquals(res.status, 401);
});

Deno.test("HonoClientCredentialsFlow - authorizeMiddleware with scopes rejects insufficient scope", async () => {
  const flow = HonoClientCredentialsFlowBuilder.create()
    .clientSecretBasicAuthenticationMethod()
    .getClient(() => Promise.resolve(undefined))
    .generateAccessToken(() => Promise.resolve(undefined))
    .verifyTokenHandler((_context, { token }) => {
      if (token === "limited-token") {
        return Promise.resolve({
          isValid: true,
          credentials: { app: { clientId: "test" }, scope: ["read"] },
        });
      }
      return Promise.resolve({ isValid: false });
    })
    .failedAuthorizationAction((_c, _error) => {
      throw new HTTPException(403, { message: "Forbidden" });
    })
    .build();

  const app = new Hono();
  app.get("/admin", flow.hono().authorizeMiddleware(["admin"]), (c) => {
    return c.json({ ok: true });
  });
  app.onError((err, c) => {
    if (err instanceof HTTPException) {
      return c.json({ error: err.message }, err.status);
    }
    throw err;
  });

  const res = await app.request("/admin", {
    headers: { "Authorization": "Bearer limited-token" },
  });

  assertEquals(res.status, 403);
});

//#endregion

//#region HonoClientCredentialsFlowBuilder

Deno.test("HonoClientCredentialsFlowBuilder - build() returns HonoClientCredentialsFlow", () => {
  const flow = new HonoClientCredentialsFlowBuilder({})
    .getClient(() => Promise.resolve(undefined))
    .generateAccessToken(() => Promise.resolve(undefined))
    .build();

  assertInstanceOf(flow, HonoClientCredentialsFlow);
});

Deno.test("HonoClientCredentialsFlowBuilder - static create() returns builder", () => {
  const builder = HonoClientCredentialsFlowBuilder.create();
  assertInstanceOf(builder, HonoClientCredentialsFlowBuilder);
});

Deno.test("HonoClientCredentialsFlowBuilder - verifyToken() returns invalid token error", async () => {
  const builder = HonoClientCredentialsFlowBuilder.create();
  const flow = builder.build();
  const req = new Request("http://localhost/protected", {
    headers: { "Authorization": "Bearer token" },
  });
  const result = await flow.hono().verifyToken({ req: { raw: req } } as Context);
  assertEquals(result.success, false);
  let error: StrategyError | undefined;
  if (!result.success) {
    error = result.error;
  }
  assertInstanceOf(error, StrategyInvalidTokenError);
  assertEquals(error.status === 401, true);
});

Deno.test("HonoClientCredentialsFlowBuilder - allows overriding access token lifetime", () => {
  const flow = HonoClientCredentialsFlowBuilder.create()
    .setAccessTokenLifetime(7200)
    .getClient(() => Promise.resolve(undefined))
    .generateAccessToken(() => Promise.resolve(undefined))
    .build();

  assertEquals(flow.getAccessTokenLifetime(), 7200);
});

//#endregion
