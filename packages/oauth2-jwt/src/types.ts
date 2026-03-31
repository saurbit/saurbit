import type { JWTPayload } from "jose";

/**
 * Represents an RSA public or private key in JSON Web Key (JWK) format.
 *
 * When used as a public key only `kty`, `e`, and `n` are present.
 * The private key fields (`d`, `p`, `q`, `dp`, `dq`, `qi`) are included on private keys.
 *
 * @see {@link https://www.rfc-editor.org/rfc/rfc7517} JSON Web Key (JWK)
 */
export interface RSA {
  /** Key type. Always `"RSA"` for RSA keys. */
  kty: "RSA";
  /** RSA public exponent, Base64URL-encoded. */
  e: string;
  /** RSA modulus, Base64URL-encoded. */
  n: string;
  /** RSA private exponent, Base64URL-encoded. Present only on private keys. */
  d?: string | undefined;
  /** First prime factor, Base64URL-encoded. Present only on private keys. */
  p?: string | undefined;
  /** Second prime factor, Base64URL-encoded. Present only on private keys. */
  q?: string | undefined;
  /** First factor CRT exponent, Base64URL-encoded. Present only on private keys. */
  dp?: string | undefined;
  /** Second factor CRT exponent, Base64URL-encoded. Present only on private keys. */
  dq?: string | undefined;
  /** First CRT coefficient, Base64URL-encoded. Present only on private keys. */
  qi?: string | undefined;
}

/**
 * Represents a public key as exposed in a JSON Web Key Set (JWKS).
 * This is the format returned by the JWKS endpoint and used by JWT verifiers
 * to validate token signatures.
 *
 * @see {@link https://www.rfc-editor.org/rfc/rfc7517} JSON Web Key (JWK)
 */
export interface RawKey {
  /** The algorithm intended for use with this key (e.g. `"RS256"`). */
  alg: string;
  /** Key type (e.g. `"RSA"`). */
  kty: string;
  /** Intended use of the key: signature (`"sig"`), encryption (`"enc"`), or description (`"desc"`). */
  use: "sig" | "enc" | "desc";
  /** Key ID - a unique identifier used to match a JWT `kid` header to the correct public key. */
  kid: string;

  /** RSA public exponent, Base64URL-encoded. Together with `n`, forms the RSA public key. */
  e: string;
  /** RSA modulus, Base64URL-encoded. Together with `e`, forms the RSA public key. */
  n: string;
}

/**
 * Persists the timestamp of the last JWKS key rotation.
 * Used by {@link JwksRotator} to determine when the next rotation is due.
 *
 * Implement this interface backed by a persistent or distributed store
 * (e.g. Redis, database) when running multiple service instances.
 */
export interface JwksRotationTimestampStore {
  /**
   * Retrieves the Unix timestamp (in milliseconds) of the last key rotation.
   * @returns The timestamp of the last rotation, or `0` if no rotation has occurred.
   */
  getLastRotationTimestamp(): Promise<number>;
  /**
   * Persists the Unix timestamp (in milliseconds) of the most recent key rotation.
   * @param rotationTimestamp - The timestamp to store.
   */
  setLastRotationTimestamp(rotationTimestamp: number): Promise<void>;
}

/**
 * Persists the active signing key pair and the set of valid public keys
 * that are exposed via the JWKS endpoint.
 *
 * Implement this interface backed by a persistent or distributed store
 * (e.g. Redis, database) when running multiple service instances.
 * The built-in {@link InMemoryKeyStore} is suitable for single-process deployments.
 */
export interface JwksKeyStore {
  /**
   * Stores the current active private key and its corresponding public key.
   * The public key will be kept for the duration of the TTL for JWKS purposes.
   */
  storeKeyPair(
    kid: string,
    privateKey: object,
    publicKey: object,
    ttl: number,
  ): void | Promise<void>;
  /**
   * Retrieves the current private key used for signing.
   */
  getPrivateKey(): Promise<object | undefined>;
  /**
   * Retrieves all valid public keys that have not expired.
   * These are used for exposing in JWKS.
   */
  getPublicKeys(): Promise<object[]>;
}

/**
 * Generates a new signing key pair and stores it in the associated {@link JwksKeyStore}.
 * Used by {@link JwksRotator} to perform key rotation.
 */
export interface KeyGenerator {
  /**
   * Generates a new key pair and persists it to the key store.
   */
  generateKeyPair(): Promise<void>;
}

/**
 * An object capable of signing a JWT payload and returning the compact serialized token.
 *
 * Implement this interface to plug in a custom JWT signing strategy.
 */
export interface JwtSigner {
  /**
   * Signs the given payload as a JWT.
   * @param payload - The JWT payload to sign.
   * @returns An object containing the signed compact JWT string and the `kid` of the key used for signing.
   */
  sign(payload: JWTPayload): Promise<{ token: string; kid: string }>;
}

/**
 * An object capable of verifying a JWT and returning its typed payload.
 *
 * Implement this interface to plug in a custom JWT verification strategy
 * (e.g. backed by a JWKS endpoint, a local key store, or a third-party library).
 */
export interface JwtVerifier {
  /**
   * Verifies the given JWT and returns its decoded payload.
   *
   * @template P - The expected shape of the JWT payload. Defaults to {@link JWTPayload}.
   * @param token - The compact serialized JWT string to verify.
   * @returns The verified and decoded payload.
   * @throws If the token is invalid, expired, or cannot be verified.
   */
  verify<P extends JWTPayload = JWTPayload>(token: string): Promise<P>;
}

/**
 * A full JWT authority combining signing, verification, and JWKS key management.
 *
 * A `JwtAuthority` is responsible for:
 * - Signing JWT payloads with the current private key ({@link JwtSigner.sign})
 * - Verifying JWTs against the matching public key ({@link JwtVerifier.verify})
 * - Exposing the JWKS (set of public keys) for external consumers
 * - Generating new key pairs on demand or via a scheduled {@link JwksRotator}
 *
 * Use {@link JoseJwksAuthority} as the ready-made implementation backed by [jose](https://github.com/panva/jose).
 */
export interface JwtAuthority extends JwtVerifier, JwtSigner {
  /**
   * Retrieves all currently valid public keys from the key store.
   * @returns An object whose `keys` array contains the public keys in JWK format.
   */
  getPublicKeys(): Promise<{ keys: RawKey[] }>;

  /**
   * Get current kid for observability/debugging
   */
  getCurrentKid(): Promise<string | undefined>;

  /**
   * Helper for JWKS endpoint
   */
  getJwksEndpointResponse(): Promise<{ keys: RawKey[] }>;

  /**
   * Retrieves the public key corresponding to the given `kid` from the key store.
   * @param kid - The key ID to look up.
   * @returns The RSA public key if found, or `undefined` if not found or not an RSA key.
   */
  getPublicKey(kid: string): Promise<RSA | undefined>;

  /**
   * Generates a new RSA key pair and stores it in the key store.
   * The new key becomes the active signing key; the previous public key
   * remains available in the JWKS until its TTL expires.
   */
  generateKeyPair(): Promise<void>;
}
