import { assertEquals, assertInstanceOf } from "@std/assert";
import { type Context, Hono } from "hono";
import { HTTPException } from "hono/http-exception";
import {
  HonoAuthorizationCodeFlow,
  HonoAuthorizationCodeFlowBuilder,
} from "../src/authorization_code.ts";
import type { HonoAuthorizationCodeFlowOptions } from "../src/authorization_code.ts";
import { StrategyError, StrategyInvalidTokenError } from "@saurbit/oauth2";

function createStubOptions(): HonoAuthorizationCodeFlowOptions {
  return {
    model: {
      getClient: () => Promise.resolve(undefined),
      generateAccessToken: () => Promise.resolve(undefined),
      generateAuthorizationCode: () => Promise.resolve(undefined),
      getUserForAuthentication: () => Promise.resolve(undefined),
      getClientForAuthentication: () => Promise.resolve(undefined),
    },
    strategyOptions: {},
    parseAuthorizationEndpointData: (_context) => {
      return Promise.resolve({ username: "", password: "" });
    },
  };
}

//#region HonoAuthorizationCodeFlow

Deno.test("HonoAuthorizationCodeFlow - can be instantiated with default options", () => {
  const flow = new HonoAuthorizationCodeFlow(createStubOptions());
  assertEquals(flow.getAccessTokenLifetime(), 3600);
  assertEquals(flow.grantType, "authorization_code");
});

Deno.test("HonoAuthorizationCodeFlow - hono() returns frozen methods object", () => {
  const flow = new HonoAuthorizationCodeFlow(createStubOptions());
  const hono = flow.hono();
  assertEquals(typeof hono.token, "function");
  assertEquals(typeof hono.verifyToken, "function");
  assertEquals(typeof hono.authorizeMiddleware, "function");
  assertEquals(typeof hono.initiateAuthorization, "function");
  assertEquals(typeof hono.processAuthorization, "function");
  assertEquals(typeof hono.handleAuthorizationEndpoint, "function");
  assertEquals(Object.isFrozen(hono), true);
});

Deno.test("HonoAuthorizationCodeFlow - token() returns error for missing credentials", async () => {
  const flow = new HonoAuthorizationCodeFlow({
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

Deno.test("HonoAuthorizationCodeFlow - handleAuthorizationEndpoint returns error on unsupported method", async () => {
  const flow = new HonoAuthorizationCodeFlow(createStubOptions());

  const app = new Hono();
  app.all("/authorize", async (c) => {
    const result = await flow.hono().handleAuthorizationEndpoint(c);
    if (result.type === "error") {
      return c.json({ error: result.error.message }, 400);
    }
    return c.json(result);
  });

  const res = await app.request("/authorize", { method: "PUT" });
  assertEquals(res.status, 400);
  const body = await res.json();
  assertEquals(body.error, "Unsupported HTTP method");
});

Deno.test("HonoAuthorizationCodeFlow - authorizeMiddleware returns 401 without token", async () => {
  const flow = new HonoAuthorizationCodeFlow({
    ...createStubOptions(),
    strategyOptions: {
      verifyToken: () => {
        return Promise.resolve({ isValid: false });
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

Deno.test("HonoAuthorizationCodeFlow - authorizeMiddleware sets credentials on valid token", async () => {
  const flow = new HonoAuthorizationCodeFlow({
    ...createStubOptions(),
    strategyOptions: {
      verifyToken: (_context, { token }) => {
        if (token === "valid-token") {
          return Promise.resolve({
            isValid: true,
            credentials: { app: { clientId: "test-client" }, scope: ["read", "write"] },
          });
        }
        return Promise.resolve({ isValid: false });
      },
    },
  });

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
  assertEquals(body.clientId, "test-client");
});

Deno.test("HonoAuthorizationCodeFlow - authorizeMiddleware with scopes rejects insufficient scope", async () => {
  const flow = new HonoAuthorizationCodeFlowBuilder({
    parseAuthorizationEndpointData: () => Promise.resolve({ username: "", password: "" }),
  })
    .clientSecretBasicAuthenticationMethod()
    .getClient(() => Promise.resolve(undefined))
    .generateAccessToken(() => Promise.resolve(undefined))
    .generateAuthorizationCode(() => Promise.resolve(undefined))
    .getUserForAuthentication(() => Promise.resolve(undefined))
    .getClientForAuthentication(() => Promise.resolve(undefined))
    .tokenVerifier((_context, { token }) => {
      if (token === "limited") {
        return { isValid: true, credentials: { app: { clientId: "c" }, scope: ["read"] } };
      }
      return { isValid: false };
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
    headers: { "Authorization": "Bearer limited" },
  });

  assertEquals(res.status, 403);
});

//#endregion

//#region HonoAuthorizationCodeFlowBuilder

Deno.test("HonoAuthorizationCodeFlowBuilder - build() returns HonoAuthorizationCodeFlow", () => {
  const flow = HonoAuthorizationCodeFlowBuilder.create({
    parseAuthorizationEndpointData: () => Promise.resolve({ username: "", password: "" }),
  })
    .getClient(() => Promise.resolve(undefined))
    .generateAccessToken(() => Promise.resolve(undefined))
    .generateAuthorizationCode(() => Promise.resolve(undefined))
    .getUserForAuthentication(() => Promise.resolve(undefined))
    .getClientForAuthentication(() => Promise.resolve(undefined))
    .build();

  assertInstanceOf(flow, HonoAuthorizationCodeFlow);
});

Deno.test("HonoAuthorizationCodeFlowBuilder - static create() returns builder", () => {
  const builder = HonoAuthorizationCodeFlowBuilder.create({
    parseAuthorizationEndpointData: () => Promise.resolve({ username: "", password: "" }),
  });
  assertInstanceOf(builder, HonoAuthorizationCodeFlowBuilder);
});

Deno.test("HonoAuthorizationCodeFlowBuilder - verifyToken() returns invalid token error", async () => {
  const builder = HonoAuthorizationCodeFlowBuilder.create({
    parseAuthorizationEndpointData: () => Promise.resolve({ username: "", password: "" }),
  });
  builder.tokenVerifier(() => Promise.resolve({ isValid: false }));
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

Deno.test("HonoAuthorizationCodeFlowBuilder - allows overriding access token lifetime", () => {
  const flow = HonoAuthorizationCodeFlowBuilder.create({
    parseAuthorizationEndpointData: () => Promise.resolve({ username: "", password: "" }),
  })
    .setAccessTokenLifetime(1800)
    .getClient(() => Promise.resolve(undefined))
    .generateAccessToken(() => Promise.resolve(undefined))
    .generateAuthorizationCode(() => Promise.resolve(undefined))
    .getUserForAuthentication(() => Promise.resolve(undefined))
    .getClientForAuthentication(() => Promise.resolve(undefined))
    .build();

  assertEquals(flow.getAccessTokenLifetime(), 1800);
});

//#endregion
