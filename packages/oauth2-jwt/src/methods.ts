import type { JwkVerify, JwtDecode, JwtVerify } from "@saurbit/oauth2";
import { decodeJwt as joseDecodeJwt, importJWK, jwtVerify } from "jose";

export const verifyJwt: JwtVerify = async (jwt, secretOrKey, options) => {
  const { payload } = await jwtVerify(jwt, secretOrKey, options);
  return payload;
};

export const decodeJwt: JwtDecode = (jwt) => {
  return joseDecodeJwt(jwt);
};

export const verifyJwk: JwkVerify = async (token) => {
  const { payload } = await jwtVerify(
    token,
    (header) => {
      if (!header.jwk) throw new Error("Missing JWK");
      return importJWK(header.jwk, header.alg);
    },
    {
      algorithms: ["ES256"],
    },
  );
  return payload;
};
