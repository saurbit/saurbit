/**
 * @module
 *
 * Implements the `client_secret_basic` client authentication method, where the
 * client authenticates by sending its `client_id` and `client_secret` as a
 * Base64-encoded `Authorization: Basic` header.
 *
 * @see https://datatracker.ietf.org/doc/html/rfc6749#section-2.3.1
 */

import { ClientAuthMethod, ClientAuthMethodResponse } from "./types.ts";
import { decodeBase64 } from "./utils.ts";

/**
 * {@link ClientAuthMethod} implementation for the `client_secret_basic` authentication method.
 *
 * Extracts client credentials from the `Authorization: Basic <base64(client_id:client_secret)>`
 * request header, as defined in RFC 6749 §2.3.1.
 *
 * @see https://datatracker.ietf.org/doc/html/rfc6749#section-2.3.1
 */
export class ClientSecretBasic implements ClientAuthMethod {
  /**
   * The identifier for this authentication method.
   * Always `"client_secret_basic"`.
   */
  get method(): "client_secret_basic" {
    return "client_secret_basic";
  }

  /**
   * Whether the client secret is optional for this method.
   * Always `false` - a client secret is required for `client_secret_basic`.
   */
  get secretIsOptional(): boolean {
    return false;
  }

  /**
   * Extracts the `client_id` and `client_secret` from the `Authorization: Basic` header.
   *
   * Sets `hasAuthMethod` to `true` only when a `Basic` scheme is detected, allowing
   * the caller to distinguish between "this method was attempted" and "no credentials provided".
   *
   * @param request - The incoming HTTP request.
   * @returns The extracted client credentials, or `{ hasAuthMethod: false }` if the
   *   `Authorization` header is absent or does not use the `Basic` scheme.
   */
  extractClientCredentials(request: Request): ClientAuthMethodResponse {
    const res: ClientAuthMethodResponse = {
      hasAuthMethod: false,
    };

    const authorization = request.headers.get("authorization");

    const [authType = "", base64Credentials = ""] = authorization
      ? authorization.split(/\s+/)
      : ["", ""];

    if (authType.toLowerCase() == "basic") {
      res.hasAuthMethod = true;

      const [clientId, clientSecret] = decodeBase64(base64Credentials).split(":");

      if (clientId) {
        res.clientId = clientId;
      }
      if (clientSecret) {
        res.clientSecret = clientSecret;
      }
    }

    return res;
  }
}
