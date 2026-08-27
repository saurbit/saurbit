/**
 * @module
 *
 * Implements the `client_secret_jwt` client authentication method, where the
 * client authenticates using a JWT signed with a shared secret (HMAC).
 * The JWT is sent as a `client_assertion` in the request body.
 *
 * JWT decoding and verification logic is injected via the constructor to avoid
 * a hard dependency on any particular JWT library.
 *
 * @see https://datatracker.ietf.org/doc/html/rfc7523
 * @see https://openid.net/specs/openid-connect-core-1_0.html#ClientAuthentication
 */

import { InvalidClientError } from "../errors.ts";
import { ClientAssertionJwtVerify, JwtDecode, JwtPayload } from "../utils/jwt_types.ts";
import { ClientAuthMethod, ClientAuthMethodResponse } from "./types.ts";

/**
 * HMAC signing algorithms supported by the `client_secret_jwt` authentication method.
 *
 * @see https://datatracker.ietf.org/doc/html/rfc7518#section-3.2
 */
export enum ClientSecretJwtAlgorithms {
  /** HMAC using SHA-256. */
  HS256 = "HS256",
  /** HMAC using SHA-384. */
  HS384 = "HS384",
  /** HMAC using SHA-512. */
  HS512 = "HS512",
}

/**
 * {@link ClientAuthMethod} implementation for the `client_secret_jwt` authentication method.
 *
 * The client creates a JWT signed with its client secret using an HMAC algorithm and
 * sends it as a `client_assertion` parameter in the token request body. The server
 * decodes the assertion to identify the client, then retrieves the client secret via
 * the {@link ClientSecretJwt.getClientSecret} handler to verify the signature.
 *
 * @see https://datatracker.ietf.org/doc/html/rfc7523
 */
export class ClientSecretJwt implements ClientAuthMethod {
  /**
   * Convenience reference to the {@link ClientSecretJwtAlgorithms} enum,
   * allowing callers to reference algorithms without a separate import.
   *
   * @example
   * ```ts
   * jwt.addAlgorithm(ClientSecretJwt.algo.HS384);
   * ```
   */
  static algo = ClientSecretJwtAlgorithms;

  /**
   * The identifier for this authentication method.
   * Always `"client_secret_jwt"`.
   */
  get method(): "client_secret_jwt" {
    return "client_secret_jwt";
  }

  /**
   * Whether the client secret is optional for this method.
   * Always `false` - a client secret is required to verify the JWT assertion.
   */
  get secretIsOptional(): boolean {
    return false;
  }

  /**
   * The list of accepted HMAC signing algorithms.
   * Defaults to `[HS256]` if no algorithms have been added via {@link ClientSecretJwt.addAlgorithm}.
   */
  get algorithms(): ClientSecretJwtAlgorithms[] {
    return this.#algorithms.length ? this.#algorithms : [ClientSecretJwtAlgorithms.HS256];
  }

  #algorithms: ClientSecretJwtAlgorithms[] = [];

  #handler: (
    clientId: string,
    decoded: JwtPayload,
    clientAssertion: string,
  ) => Promise<Uint8Array | string | null>;

  /**
   * to avoid adding jose as a dependency for users who don't need JWT client authentication,
   * the JWT decoding and verification logic is injected via the constructor
   */
  #jwtDecode: JwtDecode;

  /**
   * to avoid adding jose as a dependency for users who don't need JWT client authentication,
   * the JWT decoding and verification logic is injected via the constructor
   */
  #jwtVerify: ClientAssertionJwtVerify;

  /**
   * Creates a new `ClientSecretJwt` instance.
   *
   * @param jwtDecode - A function that decodes a JWT without verifying its signature,
   *   used to extract the `aud` claim to identify the client before looking up its secret.
   * @param jwtVerify - A function that verifies a JWT using a symmetric key.
   */
  constructor(
    jwtDecode: JwtDecode,
    jwtVerify: ClientAssertionJwtVerify,
  ) {
    this.#handler = () => Promise.resolve(null);
    this.#jwtDecode = jwtDecode;
    this.#jwtVerify = jwtVerify;
  }

  /**
   * Adds an HMAC algorithm to the list of accepted signing algorithms.
   * Duplicate entries are ignored. The list is kept sorted.
   *
   * @param algo - The algorithm to accept.
   */
  addAlgorithm(algo: ClientSecretJwtAlgorithms): this {
    if (!this.#algorithms.includes(algo)) {
      this.#algorithms.push(algo);
      this.#algorithms.sort();
    }
    return this;
  }

  /**
   * Registers the handler used to retrieve the client secret for JWT signature verification.
   *
   * The handler receives the client ID (from the `aud` claim), the decoded JWT payload,
   * and the raw client assertion string. It should return the client's secret as a string
   * or `Uint8Array`, or `null` if the client is not found.
   *
   * @param handler - An async function that returns the client secret or `null`.
   */
  getClientSecret(
    handler: (
      clientId: string,
      decoded: JwtPayload,
      clientAssertion: string,
    ) => Promise<Uint8Array | string | null>,
  ): this {
    this.#handler = handler;
    return this;
  }

  /**
   * Extracts and verifies the client assertion JWT from the request body.
   *
   * Looks for `client_assertion_type` set to
   * `"urn:ietf:params:oauth:client-assertion-type:jwt-bearer"` and a
   * `client_assertion` JWT string. The `aud` claim is used as the `client_id`.
   * The JWT signature is verified using the secret returned by the
   * {@link ClientSecretJwt.getClientSecret} handler.
   *
   * Supports `application/x-www-form-urlencoded` and `application/json` content types.
   *
   * @param req - The incoming HTTP request.
   * @returns The extracted client credentials, or `{ hasAuthMethod: false }` if the
   *   request does not contain a valid JWT client assertion.
   */
  async extractClientCredentials(req: Request): Promise<ClientAuthMethodResponse> {
    const res: ClientAuthMethodResponse = {
      hasAuthMethod: false,
    };

    const request = req.clone(); // Clone the request to avoid consuming the body

    // Extract info from the request body (either form-urlencoded or JSON)
    let body: unknown;
    const contentType = req.headers.get("content-type") || "";
    if (contentType.includes("application/x-www-form-urlencoded")) {
      const form = await req.formData();
      body = {
        client_id: form.get("client_id"),
        client_assertion_type: form.get("client_assertion_type"),
        client_assertion: form.get("client_assertion"),
      };
    } else if (contentType.includes("application/json")) {
      body = req.json ? await req.json() : null;
    } else {
      body = null;
    }

    if (
      body &&
      typeof body === "object" &&
      "client_assertion_type" in body &&
      body.client_assertion_type == "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" &&
      "client_assertion" in body &&
      typeof body.client_assertion === "string"
    ) {
      res.hasAuthMethod = true;

      const decoded = await this.#jwtDecode(body.client_assertion);

      // RFC 7523 compliance: Both must exist and they must match the client_id
      if (typeof decoded.sub === "string" && decoded.sub === decoded.iss) {
        if ("client_id" in body && body.client_id != null && body.client_id != decoded.sub) {
          res.error = new InvalidClientError(
            "client_secret_jwt authentication requires matching 'sub' and 'client_id'",
          );
        } else {
          res.clientId = decoded.sub;
          const clientSecret = await this.#handler(decoded.sub, decoded, body.client_assertion);

          if (clientSecret) {
            try {
              const payload = await this.#jwtVerify(
                {
                  clientId: decoded.sub,
                  clientAssertion: body.client_assertion,
                  clientAssertionType: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                },
                request,
                typeof clientSecret === "string"
                  ? new TextEncoder().encode(clientSecret)
                  : clientSecret,
                {
                  algorithms: this.algorithms,
                },
              );
              if (payload) {
                res.clientSecret = typeof clientSecret === "string"
                  ? clientSecret
                  : new TextDecoder().decode(clientSecret);
              } else {
                res.error = new InvalidClientError(
                  "client_secret_jwt authentication failed: invalid signature or algorithm",
                );
              }
            } catch (_err) {
              res.error = new InvalidClientError(
                "client_secret_jwt authentication failed: invalid signature or algorithm",
              );
            }
          } else {
            res.error = new InvalidClientError(
              "client_secret_jwt authentication requires a valid client secret for signature verification",
            );
          }
        }
      } else {
        res.error = new InvalidClientError(
          "client_secret_jwt authentication requires matching 'sub' and 'iss' claims in the JWT",
        );
      }
    }

    return res;
  }
}
