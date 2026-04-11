# @saurbit/oauth2-jwt

JWT utilities and JWKS authority for [`@saurbit/oauth2`](https://jsr.io/@saurbit/oauth2). Wraps
[jose](https://github.com/panva/jose) to provide ready-made implementations of the JWT-related
interfaces required by `@saurbit/oauth2`.

📖 [Documentation](https://saurbit.github.io/website/packages/oauth2-jwt/)

## Installation

**Node.js / Bun**

```sh
npm install @saurbit/oauth2-jwt
# or
yarn add @saurbit/oauth2-jwt
# or
pnpm add @saurbit/oauth2-jwt
# or
bun add @saurbit/oauth2-jwt
```

**Deno / JSR**

```sh
deno add jsr:@saurbit/oauth2-jwt
```

## JWT Utilities

`@saurbit/oauth2-jwt` provides three ready-made functions that satisfy the `JwtVerify`, `JwtDecode`,
and `JwkVerify` interfaces expected by `@saurbit/oauth2`.

### `verifyJwt` and `decodeJwt`

Used by the `ClientSecretJwt` and `PrivateKeyJwt` client authentication methods.

**`ClientSecretJwt`**

```ts
import { ClientSecretJwt } from "@saurbit/oauth2";
import { decodeJwt, verifyJwt } from "@saurbit/oauth2-jwt";

const clientSecretJwt = new ClientSecretJwt(decodeJwt, verifyJwt);
```

**`PrivateKeyJwt`**

```ts
import { PrivateKeyJwt } from "@saurbit/oauth2";
import { decodeJwt, verifyJwt } from "@saurbit/oauth2-jwt";

const privateKeyJwt = new PrivateKeyJwt(decodeJwt, verifyJwt);
```

### `verifyJwk`

Used by `DPoPTokenType` for Demonstration of Proof-of-Possession token validation.

```ts
import { createInMemoryReplayStore, DPoPTokenType } from "@saurbit/oauth2";
import { verifyJwk } from "@saurbit/oauth2-jwt";

const dpop = new DPoPTokenType(verifyJwk, createInMemoryReplayStore());
```

## JWKS Authority

`JoseJwksAuthority` manages RS256 signing key pairs, signs and verifies JWTs, and returns the JWKS
endpoint payload. Keys are stored in a `JwksKeyStore` and generated automatically on first use.

### Setup

```ts
import { createInMemoryKeyStore, JoseJwksAuthority } from "@saurbit/oauth2-jwt";

const store = createInMemoryKeyStore();
const authority = new JoseJwksAuthority(store, 8.64e+6); // public keys valid for 100 days
```

### Sign a JWT

```ts
const { token } = await authority.sign({
  sub: "user-123",
  iss: "https://auth.example.com",
  aud: "my-client",
  iat: Math.floor(Date.now() / 1000),
  exp: Math.floor(Date.now() / 1000) + 3600,
  jti: crypto.randomUUID(),
});
```

### Verify a JWT

```ts
const payload = await authority.verify(token);
console.log(payload.sub); // "user-123"
```

### JWKS endpoint

`getJwksEndpointResponse()` returns the set of current public keys in JWKS format, ready to be
served at a well-known endpoint (e.g. `/.well-known/jwks.json`).

```ts
// Example with Hono
app.get("/jwks", async (c) => {
  return c.json(await authority.getJwksEndpointResponse());
});
```

The response has the shape `{ keys: RawKey[] }` and is safe to return directly as JSON.

## Key Rotation

`JwksRotator` manages scheduled key rotation. It compares the current time against the last rotation
timestamp and generates a new key pair only when the configured interval has elapsed.

Call `checkAndRotateKeys()` at service startup and/or on a recurring schedule (e.g. every hour). If
a rotation is due a new key pair is generated; otherwise the call is a no-op. During rotation the
previous public key remains available in the JWKS until its TTL expires, so in-flight tokens
continue to verify correctly.

### Setup

```ts
import { createInMemoryKeyStore, JoseJwksAuthority, JwksRotator } from "@saurbit/oauth2-jwt";

const store = createInMemoryKeyStore();
const authority = new JoseJwksAuthority(store, 8.64e+6); // 100 days key TTL

const rotator = new JwksRotator({
  keyGenerator: authority,
  rotationTimestampStore: store,
  rotationIntervalMs: 7.884e9, // 91 days
});
```

### Usage

```ts
// At startup
await rotator.checkAndRotateKeys();

// Or on a recurring schedule
setInterval(async () => {
  await rotator.checkAndRotateKeys();
}, 60 * 60 * 1000); // every hour
```

## License

[MIT](./LICENSE)
