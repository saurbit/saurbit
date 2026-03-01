import type { OAuth2Model } from "../types.ts";

/**
 * Handles the Client Credentials grant type.
 *
 * @see https://datatracker.ietf.org/doc/html/rfc6749#section-4.4
 */
export interface ClientCredentialsGrant {
  /** The grant type identifier. */
  readonly grantType: "client_credentials";
}

/**
 * @internal
 */
export class ClientCredentialsGrantImpl implements ClientCredentialsGrant {
  readonly grantType = "client_credentials" as const;
  readonly #model: OAuth2Model;

  constructor(model: OAuth2Model) {
    this.#model = model;
  }

  // TODO: implement client credentials exchange
}
