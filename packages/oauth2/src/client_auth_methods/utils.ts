import { TokenEndpointAuthMethod } from "./types.ts";

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
