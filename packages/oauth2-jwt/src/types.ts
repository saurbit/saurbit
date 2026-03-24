import type { JWTPayload } from "jose";
import type { JwtVerifier } from "@saurbit/oauth2";

export interface RSA {
  kty: "RSA";
  e: string;
  n: string;
  d?: string | undefined;
  p?: string | undefined;
  q?: string | undefined;
  dp?: string | undefined;
  dq?: string | undefined;
  qi?: string | undefined;
}

export interface RawKey {
  alg: string;
  kty: string;
  use: "sig" | "enc" | "desc";
  kid: string;

  // e and n make up the public key
  e: string;
  n: string;
}

export interface JwksRotationTimestampStore {
  getLastRotationTimestamp(): Promise<number>;
  setLastRotationTimestamp(rotationTimestamp: number): Promise<void>;
}

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

export interface KeyGenerator {
  generateKeyPair(): Promise<void>;
}

export interface JwtSigner {
  sign(payload: JWTPayload): Promise<{ token: string; kid: string }>;
}

export interface JwtAuthority extends JwtVerifier, JwtSigner {
  getPublicKeys(): Promise<{ keys: RawKey[] }>;

  /**
   * Get current kid for observability/debugging
   */
  getCurrentKid(): Promise<string | undefined>;

  /**
   * Helper for JWKS endpoint
   */
  getJwksEndpointResponse(): Promise<{ keys: RawKey[] }>;

  getPublicKey(kid: string): Promise<RSA | undefined>;

  generateKeyPair(): Promise<void>;
}
