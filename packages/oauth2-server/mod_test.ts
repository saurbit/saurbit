import { assertEquals, assertInstanceOf } from "@std/assert";
import { ClientCredentialsFlow, InvalidRequestError, OAuth2Error } from "./src/mod.ts";
import type { ClientCredentialsFlowOptions, ClientCredentialsModel } from "./src/mod.ts";

/** Minimal stub model for testing. */
function createStubModel(): ClientCredentialsModel {
  return {
    getClient: () => Promise.resolve(undefined),
    generateAccessToken: () => Promise.resolve(undefined),
  };
}

// minimal stub strategy options for testing
function createStubStrategy(): ClientCredentialsFlowOptions["strategyOptions"] {
  return {};
}

Deno.test("OAuth2Server - ClientCredentialsFlow can be instantiated with some default options", () => {
  const flow = new ClientCredentialsFlow({
    model: createStubModel(),
    strategyOptions: createStubStrategy(),
  });
  assertEquals(flow.getAccessTokenLifetime(), 3600);
  assertEquals(flow.getSecuritySchemeName(), "oauth2-flow");
  assertEquals(flow.grantType, "client_credentials");
});

Deno.test("OAuth2Server - ClientCredentialsFlow allows overriding default options", () => {
  const flow = new ClientCredentialsFlow({
    model: createStubModel(),
    strategyOptions: createStubStrategy(),
    accessTokenLifetime: 7200,
    securitySchemeName: "custom-security-scheme",
  });
  assertEquals(flow.getAccessTokenLifetime(), 7200);
  assertEquals(flow.getSecuritySchemeName(), "custom-security-scheme");
});

Deno.test("OAuth2Error - contains correct status and error code", () => {
  const error = new InvalidRequestError("missing parameter");
  assertInstanceOf(error, OAuth2Error);
  assertEquals(error.statusCode, 400);
  assertEquals(error.errorCode, "invalid_request");
  assertEquals(error.message, "missing parameter");
});
