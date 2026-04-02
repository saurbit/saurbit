import { assertEquals, assertInstanceOf } from "@std/assert";
import { type Context, Hono } from "hono";
import {
  HonoDeviceAuthorizationFlow,
  HonoDeviceAuthorizationFlowBuilder,
} from "../src/device_authorization.ts";
import type { HonoDeviceAuthorizationFlowOptions } from "../src/device_authorization.ts";
import { StrategyError, StrategyInvalidTokenError } from "../../oauth2/src/strategy.ts";

function createStubOptions(): HonoDeviceAuthorizationFlowOptions {
  return {
    model: {
      getClient: () => Promise.resolve(undefined),
      getClientForAuthentication: () => Promise.resolve(undefined),
      generateAccessToken: () => Promise.resolve(undefined),
      generateDeviceCode: () => Promise.resolve(undefined),
      verifyUserCode: () => Promise.resolve(undefined),
    },
    strategyOptions: {},
  };
}

//#region HonoDeviceAuthorizationFlow

Deno.test("HonoDeviceAuthorizationFlow - can be instantiated with default options", () => {
  const flow = new HonoDeviceAuthorizationFlow(createStubOptions());
  assertEquals(flow.getAccessTokenLifetime(), 3600);
  assertEquals(flow.grantType, "urn:ietf:params:oauth:grant-type:device_code");
});

Deno.test("HonoDeviceAuthorizationFlow - hono() returns frozen methods object", () => {
  const flow = new HonoDeviceAuthorizationFlow(createStubOptions());
  const hono = flow.hono();
  assertEquals(typeof hono.token, "function");
  assertEquals(typeof hono.verifyToken, "function");
  assertEquals(typeof hono.authorizeMiddleware, "function");
  assertEquals(typeof hono.processAuthorization, "function");
  assertEquals(typeof hono.handleAuthorizationEndpoint, "function");
  assertEquals(Object.isFrozen(hono), true);
});

Deno.test("HonoDeviceAuthorizationFlow - handleAuthorizationEndpoint returns error on non-POST", async () => {
  const flow = new HonoDeviceAuthorizationFlow(createStubOptions());

  const app = new Hono();
  app.all("/device/authorize", async (c) => {
    const result = await flow.hono().handleAuthorizationEndpoint(c);
    if (result.type === "error") {
      return c.json({ error: result.error.message }, 400);
    }
    return c.json(result);
  });

  const res = await app.request("/device/authorize", { method: "GET" });
  assertEquals(res.status, 400);
  const body = await res.json();
  assertEquals(body.error, "Unsupported HTTP method");
});

Deno.test("HonoDeviceAuthorizationFlow - token() returns error for missing credentials", async () => {
  const flow = new HonoDeviceAuthorizationFlow({
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

Deno.test("HonoDeviceAuthorizationFlow - authorizeMiddleware returns 401 without token", async () => {
  const flow = new HonoDeviceAuthorizationFlow({
    ...createStubOptions(),
    strategyOptions: {
      verifyToken: () => {
        return { isValid: false };
      },
    },
  });

  const app = new Hono();
  app.get("/protected", flow.hono().authorizeMiddleware(), (c) => {
    return c.json({ ok: true });
  });

  const res = await app.request("/protected");
  assertEquals(res.status, 401);
});

Deno.test("HonoDeviceAuthorizationFlow - authorizeMiddleware sets credentials on valid token", async () => {
  const flow = new HonoDeviceAuthorizationFlow({
    ...createStubOptions(),
    strategyOptions: {
      verifyToken: (_context, { token }) => {
        if (token === "device-token") {
          return {
            isValid: true,
            credentials: { app: { clientId: "device-client" }, scope: ["read"] },
          };
        }
        return { isValid: false };
      },
    },
  });

  const app = new Hono();
  app.get("/protected", flow.hono().authorizeMiddleware(), (c) => {
    const credentials = c.get("credentials");
    return c.json({ clientId: (credentials?.app as Record<string, unknown>)?.clientId });
  });

  const res = await app.request("/protected", {
    headers: { "Authorization": "Bearer device-token" },
  });

  assertEquals(res.status, 200);
  const body = await res.json();
  assertEquals(body.clientId, "device-client");
});

//#endregion

//#region HonoDeviceAuthorizationFlowBuilder

Deno.test("HonoDeviceAuthorizationFlowBuilder - build() returns HonoDeviceAuthorizationFlow", () => {
  const flow = HonoDeviceAuthorizationFlowBuilder.create()
    .getClient(() => Promise.resolve(undefined))
    .generateAccessToken(() => Promise.resolve(undefined))
    .generateDeviceCode(() => Promise.resolve(undefined))
    .verifyUserCode(() => Promise.resolve(undefined))
    .build();

  assertInstanceOf(flow, HonoDeviceAuthorizationFlow);
});

Deno.test("HonoDeviceAuthorizationFlowBuilder - static create() returns builder", () => {
  const builder = HonoDeviceAuthorizationFlowBuilder.create();
  assertInstanceOf(builder, HonoDeviceAuthorizationFlowBuilder);
});

Deno.test("HonoDeviceAuthorizationFlowBuilder - verifyToken() returns invalid token error", async () => {
  const builder = HonoDeviceAuthorizationFlowBuilder.create();
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

Deno.test("HonoDeviceAuthorizationFlowBuilder - allows overriding access token lifetime", () => {
  const flow = HonoDeviceAuthorizationFlowBuilder.create()
    .setAccessTokenLifetime(900)
    .getClient(() => Promise.resolve(undefined))
    .generateAccessToken(() => Promise.resolve(undefined))
    .generateDeviceCode(() => Promise.resolve(undefined))
    .verifyUserCode(() => Promise.resolve(undefined))
    .build();

  assertEquals(flow.getAccessTokenLifetime(), 900);
});

//#endregion
