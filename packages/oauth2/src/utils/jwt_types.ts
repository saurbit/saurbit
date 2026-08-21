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
 * A function that verifies a JWT using a symmetric or asymmetric key (e.g. HMAC).
 *
 * @param jwt - The compact serialized JWT string to verify.
 * @param key - The raw symmetric key bytes used for verification.
 * @param options - Optional verification options, such as accepted algorithms.
 * @returns The verified and decoded JWT payload.
 */
export type JwtVerify = (
  jwt: string,
  key: Uint8Array | object,
  options?: { algorithms?: string[] },
) => Promise<JwtPayload>;

/**
 * Client assertion context used for verifying JWTs in client authentication methods.
 */
export type ClientAssertionJwtContext = {
  /** The client ID extracted from the `aud` claim of the JWT. */
  clientId: string;
  /** The raw client assertion JWT string. */
  clientAssertion: string;
  /** The type of the client assertion, which must be `"urn:ietf:params:oauth:client-assertion-type:jwt-bearer"`. */
  clientAssertionType: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
};

/**
 * A function that verifies a client assertion JWT in the context of OAuth 2.0 client authentication.
 *
 * @param context - The client assertion context containing the client ID, assertion, and type.
 * @param request - The HTTP request object containing the client assertion.
 * @param key - The raw symmetric key bytes or public key object used for verification.
 * @param options - Optional verification options, such as accepted algorithms.
 * @returns The verified and decoded JWT payload.
 */
export type ClientAssertionJwtVerify = (
  context: ClientAssertionJwtContext,
  request: Request,
  key: Uint8Array | object,
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
    b64?: boolean;
    crit?: string[];
    [propName: string]: unknown;
  };
}>;

export type JwkThumbprintCalculator = (
  // deno-lint-ignore no-explicit-any
  jwk: any,
) => Promise<string>;
