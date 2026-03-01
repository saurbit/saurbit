import type { OAuth2Model } from "./types.ts";

/**
 * Configuration options for {@linkcode OAuth2Server}.
 */
export interface OAuth2ServerOptions {
  /** The model implementation providing persistence. */
  model: OAuth2Model;

  /** Default lifetime (in seconds) for access tokens. @default {3600} */
  accessTokenLifetime?: number;

  /** Default lifetime (in seconds) for refresh tokens. @default {1_209_600} (14 days) */
  refreshTokenLifetime?: number;

  /** Default lifetime (in seconds) for authorization codes. @default {300} */
  authorizationCodeLifetime?: number;

  /** Allowed grant types. @default {["authorization_code", "client_credentials", "refresh_token"]} */
  allowedGrantTypes?: string[];
}

const DEFAULT_OPTIONS = {
  accessTokenLifetime: 3600,
  refreshTokenLifetime: 1_209_600,
  authorizationCodeLifetime: 300,
  allowedGrantTypes: ["authorization_code", "client_credentials", "refresh_token"],
} as const satisfies Partial<OAuth2ServerOptions>;

/**
 * Core OAuth 2.0 authorization server.
 *
 * @example
 * ```ts
 * import { OAuth2Server } from "@saurbit/oauth2-server";
 *
 * const server = new OAuth2Server({ model: myModel });
 * ```
 */
export class OAuth2Server {
  readonly options: Required<OAuth2ServerOptions>;

  constructor(options: OAuth2ServerOptions) {
    this.options = {
      ...DEFAULT_OPTIONS,
      ...options,
    };
  }

  // TODO: token()  - handle token requests
  // TODO: authorize() - handle authorization requests
  // TODO: authenticate() - validate bearer tokens
}
