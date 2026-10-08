import { TokenEndpointAuthMethod } from "./types.ts";

// Fast path for Node/Bun
declare const Buffer: {
  from(input: string, encoding: string): { toString(encoding: string): string };
};

/**
 * Decodes a base64-encoded string to a UTF-8 string.
 *
 * @param b64 - The base64-encoded string.
 * @returns The decoded UTF-8 string.
 */
export function decodeBase64(b64: string): string {
  // Fast path for Node/Bun
  if (typeof Buffer !== "undefined") {
    return Buffer.from(b64, "base64").toString("utf8");
  }

  // Universal Web API path
  const binary = atob(b64);
  const bytes = Uint8Array.from(binary, (c) => c.charCodeAt(0));
  return new TextDecoder().decode(bytes);
}

/**
 * Decodes a base64url string (no padding, `-`/`_` instead of `+`/`/`) to a UTF-8 string.
 * Works across Node/Bun and standard Web API environments.
 */
function decodeBase64Url(input: string): string {
  // Fast path for Node/Bun
  if (typeof Buffer !== "undefined") {
    return Buffer.from(input, "base64url").toString("utf8");
  }

  // Universal Web API path: convert base64url -> base64 and restore padding
  const base64 = input.replace(/-/g, "+").replace(/_/g, "/").padEnd(
    input.length + ((4 - (input.length % 4)) % 4),
    "=",
  );
  return decodeBase64(base64);
}

/**
 * Reads the `alg` field from a compact JWT's header **without** verifying its
 * signature or claims. This is only safe to use for *routing* a `client_assertion`
 * to the matching JWT-bearer client authentication method (e.g. disambiguating
 * `private_key_jwt` from `client_secret_jwt`) before any signature verification
 * happens. The assertion must still be fully verified afterwards.
 *
 * @param jwt - The compact serialized JWT string (e.g. a `client_assertion`).
 * @returns The `alg` header value, or `undefined` if the JWT is malformed or has no `alg`.
 */
export function getUnverifiedJwtAlg(jwt: string): string | undefined {
  const header = jwt.split(".")[0];
  if (!header) {
    return undefined;
  }

  try {
    const decoded: unknown = JSON.parse(decodeBase64Url(header));
    return decoded && typeof decoded === "object" && typeof (decoded as { alg?: unknown }).alg ===
        "string"
      ? (decoded as { alg: string }).alg
      : undefined;
  } catch {
    return undefined;
  }
}

const sortedTokenEndpointAuthMethods: TokenEndpointAuthMethod[] = [
  "tls_client_auth",
  "self_signed_tls_client_auth",
  "private_key_jwt",
  "client_secret_jwt",
  "client_secret_basic",
  "client_secret_post",
  "none",
];

const orderMapTokenEndpointAuthMethods = new Map(
  sortedTokenEndpointAuthMethods.map((item, index) => [item, index]),
);

export function sortTokenEndpointAuthMethods(array: TokenEndpointAuthMethod[]) {
  return array.sort((a, b) => {
    return (
      (orderMapTokenEndpointAuthMethods.get(a) ?? Infinity) -
      (orderMapTokenEndpointAuthMethods.get(b) ?? Infinity)
    );
  });
}
