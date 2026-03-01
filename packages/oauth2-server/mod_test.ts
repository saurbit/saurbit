import { assertEquals, assertInstanceOf } from "@std/assert";
import { OAuth2Server, OAuth2Error, InvalidRequestError } from "./mod.ts";
import type { OAuth2Model } from "./mod.ts";

/** Minimal stub model for testing. */
function createStubModel(): OAuth2Model {
  return {
    getClient: () => Promise.resolve(undefined),
    saveToken: () => Promise.resolve(undefined!),
    getAccessToken: () => Promise.resolve(undefined),
  };
}

Deno.test("OAuth2Server - can be instantiated with default options", () => {
  const server = new OAuth2Server({ model: createStubModel() });
  assertEquals(server.options.accessTokenLifetime, 3600);
  assertEquals(server.options.refreshTokenLifetime, 1_209_600);
  assertEquals(server.options.authorizationCodeLifetime, 300);
});

Deno.test("OAuth2Server - allows overriding default options", () => {
  const server = new OAuth2Server({
    model: createStubModel(),
    accessTokenLifetime: 7200,
  });
  assertEquals(server.options.accessTokenLifetime, 7200);
});

Deno.test("OAuth2Error - contains correct status and error code", () => {
  const error = new InvalidRequestError("missing parameter");
  assertInstanceOf(error, OAuth2Error);
  assertEquals(error.statusCode, 400);
  assertEquals(error.errorCode, "invalid_request");
  assertEquals(error.message, "missing parameter");
});
