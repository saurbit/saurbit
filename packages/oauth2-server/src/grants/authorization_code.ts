import type { OAuth2Model } from "../types.ts";

/**
 * Handles the Authorization Code grant type.
 *
 * @see https://datatracker.ietf.org/doc/html/rfc6749#section-4.1
 */
export interface AuthorizationCodeGrant {
  /** The grant type identifier. */
  readonly grantType: "authorization_code";
}

/**
 * @internal
 */
export class AuthorizationCodeGrantImpl implements AuthorizationCodeGrant {
  readonly grantType = "authorization_code" as const;
  readonly #model: OAuth2Model;

  constructor(model: OAuth2Model) {
    this.#model = model;
  }

  // TODO: implement authorization code exchange
}
