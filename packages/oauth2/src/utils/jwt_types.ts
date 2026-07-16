/**
 * Represents the decoded payload of a JSON Web Token (JWT).
 *
 * @see https://datatracker.ietf.org/doc/html/rfc7519#section-4
 */
export interface JwtPayload {
  /** Issuer - identifies the principal that issued the JWT. */
  iss?: string;

  /** Subject - identifies the principal that is the subject of the JWT. */
  sub?: string;

  /** Audience - identifies the recipients the JWT is intended for. */
  aud?: string | string[];

  /** JWT ID - a unique identifier for the JWT, used to prevent replay attacks. */
  jti?: string;

  /** Not Before - the time before which the JWT must not be accepted (Unix timestamp). */
  nbf?: number;

  /** Expiration Time - the time after which the JWT must not be accepted (Unix timestamp). */
  exp?: number;

  /** Issued At - the time at which the JWT was issued (Unix timestamp). */
  iat?: number;

  /** Additional claims. */
  [propName: string]: unknown;
}

/**
 * A function that decodes a JWT string without verifying its signature.
 *
 * @param jwt - The compact serialized JWT string to decode.
 * @returns The decoded payload, synchronously or as a Promise.
 */
export type JwtDecode = (jwt: string) => JwtPayload | Promise<JwtPayload>;

/**
 * A function that verifies a JWT using a symmetric key (e.g. HMAC).
 *
 * @param jwt - The compact serialized JWT string to verify.
 * @param key - The raw symmetric key bytes used for verification.
 * @param options - Optional verification options, such as accepted algorithms.
 * @returns The verified and decoded JWT payload.
 */
export type JwtVerify = (
  jwt: string,
  key: Uint8Array,
  options?: { algorithms?: string[] },
) => Promise<JwtPayload>;

/**
 * A function that verifies a JWT against a JWK Set (JWKS).
 *
 * @param jwt - The compact serialized JWT string to verify.
 * @returns An object containing the verified JWT payload and the protected header.
 */
export type JwkVerify = (jwt: string) => Promise<{
  payload: JwtPayload;
  protectedHeader: {
    alg?: string;
    b64?: true;
    crit?: string[];
    [propName: string]: unknown;
  };
}>;

export type JwkThumbprintCalculator = (
  // deno-lint-ignore no-explicit-any
  jwk: any,
) => Promise<string>;
