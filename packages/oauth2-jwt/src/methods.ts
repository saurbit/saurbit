import type { JwkThumbprintCalculator, JwkVerify, JwtDecode, JwtVerify } from "@saurbit/oauth2";
import {
  calculateJwkThumbprint as joseCalculateJwkThumbprint,
  decodeJwt as joseDecodeJwt,
  importJWK,
  jwtVerify,
} from "jose";

/**
 * Verifies a JWT using the provided secret or key and returns the decoded payload.
 * Wraps [jose](https://github.com/panva/jose)'s `jwtVerify`.
 *
 * Pass this as the `JwtVerify` argument to `ClientSecretJwt` or `PrivateKeyJwt`
 * from `@saurbit/oauth2`.
 *
 * @param jwt - The compact serialized JWT to verify.
 * @param secretOrKey - The secret (`string` / `Uint8Array`) or `CryptoKey` for verification.
 * @param options - Optional jose verification options (algorithms, audience, issuer, etc.).
 * @returns The verified JWT payload.
 * @throws If the token is invalid, expired, or the signature does not match.
 */
export const verifyJwt: JwtVerify = async (jwt, secretOrKey, options) => {
  const { payload } = await jwtVerify(jwt, secretOrKey, options);
  return payload;
};

/**
 * Decodes a JWT payload **without** verifying its signature.
 * Wraps [jose](https://github.com/panva/jose)'s `decodeJwt`.
 *
 * Pass this as the `JwtDecode` argument to `ClientSecretJwt` or `PrivateKeyJwt`
 * from `@saurbit/oauth2`.
 *
 * @param jwt - The compact serialized JWT to decode.
 * @returns The decoded JWT payload (unverified).
 */
export const decodeJwt: JwtDecode = (jwt) => {
  return joseDecodeJwt(jwt);
};

/**
 * Verifies a JWT whose header embeds the public JWK (`"jwk"` header parameter).
 * The public key is extracted from the JWT header itself and used to verify the signature.
 * Only `ES256` algorithm tokens are accepted.
 *
 * Pass this as the `JwkVerify` argument to `DPoPTokenType` from `@saurbit/oauth2`.
 *
 * @param token - The compact serialized JWT (DPoP proof) to verify.
 * @returns The verified JWT payload and the protected header.
 * @throws If the token is invalid, the `jwk` header is missing, or signature verification fails.
 */
export const verifyJwk: JwkVerify = async (token) => {
  const { payload, protectedHeader } = await jwtVerify(
    token,
    (header) => {
      if (!header.jwk) throw new Error("Missing JWK");
      return importJWK(header.jwk, header.alg);
    },
    {
      algorithms: ["ES256"],
    },
  );
  return { payload, protectedHeader };
};

/**
 * Calculates the JWK thumbprint for a given JSON Web Key (JWK) using SHA-256.
 * The thumbprint is a base64url-encoded string that uniquely identifies the JWK.
 *
 * @param jwk - The JSON Web Key (JWK) for which to calculate the thumbprint.
 * @returns The JWK thumbprint as a base64url-encoded string.
 * @throws If the JWK is invalid or cannot be processed.
 *
 * Pass this as the `JwkThumbprintCalculator` argument to `DPoPTokenType` from `@saurbit/oauth2`.
 */
export const calculateJwkThumbprint: JwkThumbprintCalculator = (jwk) => {
  return joseCalculateJwkThumbprint(jwk, "sha256");
};
