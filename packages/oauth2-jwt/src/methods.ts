import type { JwkVerify, JwtDecode, JwtVerify } from "@saurbit/oauth2";
import jose from "jose";

export const verifyJwt: JwtVerify = async (jwt, secretOrKey, options) => {
  const { payload } = await jose.jwtVerify(jwt, secretOrKey, options);
  return payload;
};

export const decodeJwt: JwtDecode = (jwt) => {
  return jose.decodeJwt(jwt);
};

export const verifyJwk: JwkVerify = async (token) => {
  const { payload } = await jose.jwtVerify(
    token,
    (header) => {
      if (!header.jwk) throw new Error("Missing JWK");
      return jose.importJWK(header.jwk, header.alg);
    },
    {
      algorithms: ["ES256"],
    },
  );
  return payload;
};
