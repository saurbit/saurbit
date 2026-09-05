/**
 * @module
 *
 * Core types for the client authentication method abstraction.
 *
 * Each authentication method (e.g. `client_secret_basic`, `private_key_jwt`) implements
 * {@link ClientAuthMethod} to extract client credentials from an incoming request in a
 * method-specific way.
 *
 * @see https://datatracker.ietf.org/doc/html/rfc6749#section-2.3
 * @see https://openid.net/specs/openid-connect-core-1_0.html#ClientAuthentication
 */

import type { OAuth2Error } from "../errors.ts";
import type { OAuth2Client } from "../types.ts";

/**
 * The registered client authentication method identifiers defined by OAuth 2.0 and OIDC.
 *
 * @see https://openid.net/specs/openid-connect-core-1_0.html#ClientAuthentication
 */
export type TokenEndpointAuthMethod =
  | "client_secret_basic"
  | "client_secret_post"
  | "client_secret_jwt"
  | "private_key_jwt"
  | "none";

/**
 * The result returned by {@link ClientAuthMethod.extractClientCredentials}.
 */
export type ClientAuthMethodResponse = {
  /**
   * `true` if this authentication method's scheme was detected in the request,
   * regardless of whether the credentials themselves are valid.
   */
  hasAuthMethod: boolean;

  /** The extracted client identifier, if present. */
  clientId?: string;

  /**
   * The extracted client secret (or equivalent proof), if present.
   * For `private_key_jwt` this holds the raw JWT assertion string.
   */
  clientSecret?: string;

  client?: Partial<OAuth2Client> | undefined;

  /** The error encountered during extraction, if any. */
  error?: OAuth2Error | undefined;
};

/**
 * Contract for a client authentication method implementation.
 *
 * Each method is responsible for recognising whether its scheme is present in a request
 * and, if so, extracting the `client_id` and `client_secret` (or their equivalents).
 */
export interface ClientAuthMethod {
  /**
   * The registered name of this authentication method.
   * Used as the key when registering methods on a flow.
   */
  readonly method: TokenEndpointAuthMethod;

  /**
   * Whether the client secret may be absent for this method.
   * `true` for public-client methods (e.g. `none`), `false` for all others.
   */
  readonly secretIsOptional: boolean;

  /**
   * The signing algorithms accepted by this method, if applicable.
   * Only relevant for JWT-based methods (`client_secret_jwt`, `private_key_jwt`).
   */
  readonly algorithms?: string[];

  /**
   * Extracts the `client_id` and `client_secret` (or their equivalents) from the request.
   *
   * Implementations must set `hasAuthMethod` to `true` only when the request actually
   * contains credentials for this method, allowing the caller to fall through to the
   * next registered method when this one is not present.
   *
   * @param request - The incoming HTTP request.
   * @returns The extracted credentials, or `{ hasAuthMethod: false }` if this method's
   *   scheme is not present in the request.
   */
  extractClientCredentials(
    request: Request,
  ): Promise<ClientAuthMethodResponse> | ClientAuthMethodResponse;
}
