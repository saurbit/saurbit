import type { OAuth2Model } from "../types.ts";

/**
 * Handles the Refresh Token grant type.
 *
 * @see https://datatracker.ietf.org/doc/html/rfc6749#section-6
 */
export interface RefreshTokenGrant {
  /** The grant type identifier. */
  readonly grantType: "refresh_token";
}

/**
 * @internal
 */
export class RefreshTokenGrantImpl implements RefreshTokenGrant {
  readonly grantType = "refresh_token" as const;
  readonly #model: OAuth2Model;

  constructor(model: OAuth2Model) {
    this.#model = model;
  }

  // TODO: implement refresh token exchange
}
