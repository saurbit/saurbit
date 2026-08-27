/**
 * @module
 *
 * Implements the `private_key_jwt` client authentication method, where the
 * client authenticates using a JWT signed with its private key (asymmetric cryptography).
 * The JWT is sent as a `client_assertion` in the request body, and the server
 * verifies it using the corresponding public key.
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
 * Asymmetric signing algorithms supported by the `private_key_jwt` authentication method.
 *
 * @see https://datatracker.ietf.org/doc/html/rfc7518#section-3
 */
export enum PrivateKeyJwtAlgorithms {
  /** RSASSA-PKCS1-v1_5 using SHA-256. */
  RS256 = "RS256",
  /** RSASSA-PKCS1-v1_5 using SHA-384. */
  RS384 = "RS384",
  /** RSASSA-PKCS1-v1_5 using SHA-512. */
  RS512 = "RS512",
  /** RSASSA-PSS using SHA-256. */
  PS256 = "PS256",
  /** RSASSA-PSS using SHA-384. */
  PS384 = "PS384",
  /** RSASSA-PSS using SHA-512. */
  PS512 = "PS512",
  /** ECDSA using P-256 and SHA-256. */
  ES256 = "ES256",
  /** ECDSA using P-384 and SHA-384. */
  ES384 = "ES384",
  /** ECDSA using P-521 and SHA-512. */
  ES512 = "ES512",
  /** Edwards-curve Digital Signature Algorithm (Ed25519 / Ed448). */
  EdDSA = "EdDSA",
}

/**
 * {@link ClientAuthMethod} implementation for the `private_key_jwt` authentication method.
 *
 * The client creates a JWT signed with its private key and sends it as a
 * `client_assertion` parameter in the token request body. The server decodes the
 * assertion to identify the client, then retrieves the client's public key via the
 * {@link PrivateKeyJwt.getPublicKeyForClient} handler to verify the signature.
 *
 * @see https://datatracker.ietf.org/doc/html/rfc7523
 */
export class PrivateKeyJwt implements ClientAuthMethod {
  /**
   * Convenience reference to the {@link PrivateKeyJwtAlgorithms} enum,
   * allowing callers to reference algorithms without a separate import.
   *
   * @example
   * ```ts
   * jwt.addAlgorithm(PrivateKeyJwt.algo.ES256);
   * ```
   */
  static algo = PrivateKeyJwtAlgorithms;

  /**
   * The identifier for this authentication method.
   * Always `"private_key_jwt"`.
   */
  get method(): "private_key_jwt" {
    return "private_key_jwt";
  }

  /**
   * Whether the client secret is optional for this method.
   * Always `false` - a public key is required to verify the JWT assertion.
   */
  get secretIsOptional(): boolean {
    return false;
  }

  /**
   * The list of accepted asymmetric signing algorithms.
   * Defaults to `[RS256]` if no algorithms have been added via {@link PrivateKeyJwt.addAlgorithm}.
   */
  get algorithms(): PrivateKeyJwtAlgorithms[] {
    return this.#algorithms.length ? this.#algorithms : [PrivateKeyJwtAlgorithms.RS256];
  }

  #algorithms: PrivateKeyJwtAlgorithms[] = [];

  #handler: (
    clientId: string,
    decoded: JwtPayload,
    clientAssertion: string,
  ) => Promise<object | null>;

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
   * Creates a new `PrivateKeyJwt` instance.
   *
   * @param jwtDecode - A function that decodes a JWT without verifying its signature,
   *   used to extract the `aud` claim to identify the client before looking up its public key.
   * @param jwtVerify - A function that verifies a JWT using an asymmetric public key.
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
   * Adds an asymmetric signing algorithm to the list of accepted algorithms.
   * Duplicate entries are ignored. The list is kept sorted.
   *
   * @param algo - The algorithm to accept.
   */
  addAlgorithm(algo: PrivateKeyJwtAlgorithms): this {
    if (!this.#algorithms.includes(algo)) {
      this.#algorithms.push(algo);
      this.#algorithms.sort();
    }
    return this;
  }

  /**
   * Registers the handler used to retrieve the client's public key for JWT signature verification.
   *
   * The handler receives the client ID (from the `aud` claim), the decoded JWT payload,
   * and the raw client assertion string. It should return the client's public key as a
   * `Uint8Array` or PEM string, or `null` if the client is not found.
   *
   * @param handler - An async function that returns the public key or `null`.
   */
  getPublicKeyForClient(
    handler: (
      clientId: string,
      decoded: JwtPayload,
      clientAssertion: string,
    ) => Promise<object | null>,
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
   * The JWT signature is verified using the public key returned by the
   * {@link PrivateKeyJwt.getPublicKeyForClient} handler. On success, the raw
   * `client_assertion` string is stored as `clientSecret` to satisfy the
   * {@link ClientAuthMethodResponse} contract.
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

      if (typeof decoded.sub === "string" && decoded.sub === decoded.iss) {
        if ("client_id" in body && body.client_id != null && body.client_id != decoded.sub) {
          res.error = new InvalidClientError(
            "private_key_jwt authentication requires matching 'sub' and 'client_id'",
          );
        } else {
          res.clientId = decoded.sub;
          const publicKey = await this.#handler(decoded.sub, decoded, body.client_assertion);

          if (publicKey) {
            try {
              const payload = await this.#jwtVerify(
                {
                  clientId: decoded.sub,
                  clientAssertion: body.client_assertion,
                  clientAssertionType: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                },
                request,
                publicKey,
                {
                  algorithms: this.algorithms,
                },
              );
              if (payload) {
                res.clientSecret = body.client_assertion;
              } else {
                res.error = new InvalidClientError(
                  "private_key_jwt authentication failed: invalid signature or algorithm",
                );
              }
            } catch (_err) {
              res.error = new InvalidClientError(
                "private_key_jwt authentication failed: invalid signature or algorithm",
              );
            }
          } else {
            res.error = new InvalidClientError(
              "private_key_jwt authentication requires a valid public key for signature verification",
            );
          }
        }
      } else {
        res.error = new InvalidClientError(
          "private_key_jwt authentication requires matching 'sub' and 'iss' claims in the JWT",
        );
      }
    }

    return res;
  }
}
