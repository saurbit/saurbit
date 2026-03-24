import { createInMemoryKeyStore, JoseJwksAuthority, JwksRotator } from "@saurbit/oauth2-jwt";

// For demonstration purposes, we use an in-memory key store and
// a simple authority that generates keys on the fly.
const jwksStore = createInMemoryKeyStore();

// The authority is responsible for signing JWTs and exposing the JWKS endpoint.
export const jwksAuthority = new JoseJwksAuthority(jwksStore, 86400); // 24h

// The rotator will help manage key rotation, ensuring that
// new keys are generated and old keys are retired according to the specified interval
// when checkAndRotateKeys is called (e.g., at startup or on a schedule).
export const jwksRotator = new JwksRotator({
  keyGenerator: jwksAuthority,
  rotatorKeyStore: jwksStore,
  rotationIntervalMs: 7.884e9, // 91 days
});
