import { assertEquals } from "@std/assert";
import { Hono } from "hono";
import type { Env } from "hono";
import { HTTPException } from "hono/http-exception";
import { HonoOIDCMultipleFlows } from "../src/oidc_multiple_flow.ts";
import type { HonoOIDCFlow } from "../src/oidc_multiple_flow.ts";
import { HonoOIDCClientCredentialsFlow } from "../src/client_credentials.ts";
import type { HonoOIDCClientCredentialsFlowOptions } from "../src/client_credentials.ts";
import type { OAuth2ServerEnv } from "../src/types.ts";

const STUB_OIDC_CONFIG = {
  discoveryUrl: "https://example.com/.well-known/openid-configuration",
  securitySchemeName: "oidc",
};

function createStubOIDCFlow(
  overrides: Partial<{
    verifySuccess: boolean;
    credentials: Record<string, unknown>;
  }> = {},
): HonoOIDCFlow {
  const opts: HonoOIDCClientCredentialsFlowOptions = {
    model: {
      getClient: () => Promise.resolve(undefined),
      generateAccessToken: () => Promise.resolve(undefined),
    },
    strategyOptions: {
      verifyToken: () => {
        if (overrides.verifySuccess) {
          return {
            isValid: true,
            credentials: overrides.credentials ?? { app: { clientId: "c1" }, scope: ["read"] },
          };
        }
        return { isValid: false };
      },
    },
    discoveryUrl: "https://example.com/.well-known/openid-configuration",
  };

  return new HonoOIDCClientCredentialsFlow(opts);
}

//#region HonoOIDCMultipleFlows

Deno.test("HonoOIDCMultipleFlows - can be instantiated with an empty flows array", () => {
  const multi = new HonoOIDCMultipleFlows({ ...STUB_OIDC_CONFIG, flows: [] });
  assertEquals(typeof multi.hono, "function");
});

Deno.test("HonoOIDCMultipleFlows - hono() returns frozen methods object", () => {
  const multi = new HonoOIDCMultipleFlows({
    ...STUB_OIDC_CONFIG,
    flows: [createStubOIDCFlow()],
  });
  const hono = multi.hono();
  assertEquals(typeof hono.authorizeMiddleware, "function");
  assertEquals(typeof hono.token, "function");
  assertEquals(typeof hono.verifyToken, "function");
  assertEquals(Object.isFrozen(hono), true);
});

Deno.test("HonoOIDCMultipleFlows - token() collects errors when no flow succeeds", async () => {
  const multi = new HonoOIDCMultipleFlows({
    ...STUB_OIDC_CONFIG,
    flows: [createStubOIDCFlow(), createStubOIDCFlow()],
  });

  const app = new Hono();
  app.post("/token", async (c) => {
    const result = await multi.hono().token(c);
    return c.json({ success: result.success });
  });

  const res = await app.request("/token", { method: "POST" });
  const body = await res.json();
  assertEquals(body.success, false);
});

Deno.test("HonoOIDCMultipleFlows - token() returns 'No flows available' error when empty", async () => {
  const multi = new HonoOIDCMultipleFlows({ ...STUB_OIDC_CONFIG, flows: [] });

  const app = new Hono();
  app.post("/token", async (c) => {
    const result = await multi.hono().token(c);
    return c.json({ success: result.success, error: result.success ? null : result.error.message });
  });

  const res = await app.request("/token", { method: "POST" });
  const body = await res.json();
  assertEquals(body.success, false);
  assertEquals(body.error, "No flows available");
});

Deno.test("HonoOIDCMultipleFlows - verifyToken() returns error when no flow validates", async () => {
  const multi = new HonoOIDCMultipleFlows({
    ...STUB_OIDC_CONFIG,
    flows: [
      createStubOIDCFlow({ verifySuccess: false }),
      createStubOIDCFlow({ verifySuccess: false }),
    ],
  });

  const app = new Hono<Env & OAuth2ServerEnv>();
  app.get("/verify", async (c) => {
    const result = await multi.hono().verifyToken(c);
    return c.json({ success: result.success });
  });

  const res = await app.request("/verify", {
    headers: { "Authorization": "Bearer some-token" },
  });
  const body = await res.json();
  assertEquals(body.success, false);
});

Deno.test("HonoOIDCMultipleFlows - verifyToken() returns 'No flows available' when empty", async () => {
  const multi = new HonoOIDCMultipleFlows({ ...STUB_OIDC_CONFIG, flows: [] });

  const app = new Hono<Env & OAuth2ServerEnv>();
  app.get("/verify", async (c) => {
    const result = await multi.hono().verifyToken(c);
    return c.json({
      success: result.success,
      error: result.success ? null : result.error.message,
    });
  });

  const res = await app.request("/verify", {
    headers: { "Authorization": "Bearer some-token" },
  });
  const body = await res.json();
  assertEquals(body.success, false);
  assertEquals(body.error, "No flows available");
});

Deno.test("HonoOIDCMultipleFlows - authorizeMiddleware returns 401 when all flows reject", async () => {
  const multi = new HonoOIDCMultipleFlows({
    ...STUB_OIDC_CONFIG,
    flows: [
      createStubOIDCFlow({ verifySuccess: false }),
      createStubOIDCFlow({ verifySuccess: false }),
    ],
  });

  const app = new Hono();
  app.get("/protected", multi.hono().authorizeMiddleware(), (c) => {
    return c.json({ ok: true });
  });
  app.onError((err, c) => {
    if (err instanceof HTTPException) {
      return c.json({ error: "unauthorized" }, err.status);
    }
    throw err;
  });

  const res = await app.request("/protected");
  assertEquals(res.status, 401);
});

Deno.test("HonoOIDCMultipleFlows - authorizeMiddleware succeeds when second flow validates", async () => {
  const multi = new HonoOIDCMultipleFlows({
    ...STUB_OIDC_CONFIG,
    flows: [
      createStubOIDCFlow({ verifySuccess: false }),
      createStubOIDCFlow({
        verifySuccess: true,
        credentials: { app: { clientId: "second" }, scope: ["read"] },
      }),
    ],
  });

  const app = new Hono();
  app.get("/protected", multi.hono().authorizeMiddleware(), (c) => {
    const creds = c.get("credentials");
    return c.json({ clientId: (creds?.app as Record<string, unknown>)?.clientId });
  });

  const res = await app.request("/protected", {
    headers: { "Authorization": "Bearer valid-token" },
  });

  assertEquals(res.status, 200);
  const body = await res.json();
  assertEquals(body.clientId, "second");
});

//#endregion
