export interface JwtPayload {
  iss?: string;
  sub?: string;
  aud?: string | string[];
  jti?: string;
  nbf?: number;
  exp?: number;
  iat?: number;
  [propName: string]: unknown;
}

export type JwtDecode = (jwt: string) => JwtPayload | Promise<JwtPayload>;

export type JwtVerify = (
  jwt: string,
  key: Uint8Array,
  options?: { algorithms?: string[] },
) => Promise<JwtPayload>;

export type JwkVerify = (jwt: string) => Promise<JwtPayload>;

export interface JwtVerifier {
  verify<P extends JwtPayload = JwtPayload>(token: string): Promise<P>;
}
