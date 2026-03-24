import { JwtDecode, JwtPayload, JwtVerify } from "../utils/jwt_types.ts";
import { ClientAuthMethod, ClientAuthMethodResponse } from "./types.ts";

export enum PrivateKeyJwtAlgorithms {
  RS256 = "RS256",
  RS384 = "RS384",
  RS512 = "RS512",
  PS256 = "PS256",
  PS384 = "PS384",
  PS512 = "PS512",
  ES256 = "ES256",
  ES384 = "ES384",
  ES512 = "ES512",
  EdDSA = "EdDSA",
}

export class PrivateKeyJwt implements ClientAuthMethod {
  static algo = PrivateKeyJwtAlgorithms;

  get method(): "private_key_jwt" {
    return "private_key_jwt";
  }

  get secretIsOptional(): boolean {
    return false;
  }

  get algorithms(): PrivateKeyJwtAlgorithms[] {
    return this.#algorithms.length ? this.#algorithms : [PrivateKeyJwtAlgorithms.RS256];
  }

  #algorithms: PrivateKeyJwtAlgorithms[] = [];

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
  #jwtVerify: JwtVerify;

  constructor(
    jwtDecode: JwtDecode,
    jwtVerify: JwtVerify,
  ) {
    this.#handler = () => Promise.resolve(null);
    this.#jwtDecode = jwtDecode;
    this.#jwtVerify = jwtVerify;
  }

  addAlgorithm(algo: PrivateKeyJwtAlgorithms): this {
    if (!this.#algorithms.includes(algo)) {
      this.#algorithms.push(algo);
      this.#algorithms.sort();
    }
    return this;
  }

  getPublicKeyForClient(
    handler: (
      clientId: string,
      decoded: JwtPayload,
      clientAssertion: string,
    ) => Promise<Uint8Array | string | null>,
  ): this {
    this.#handler = handler;
    return this;
  }

  async extractClientCredentials(req: Request): Promise<ClientAuthMethodResponse> {
    const res: ClientAuthMethodResponse = {
      hasAuthMethod: false,
    };

    // Extract info from the request body (either form-urlencoded or JSON)
    let body: unknown;
    const contentType = req.headers.get("content-type") || "";
    if (contentType.includes("application/x-www-form-urlencoded")) {
      const form = await req.formData();
      body = {
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
      const decoded = await this.#jwtDecode(body.client_assertion);

      if (decoded.aud && typeof decoded.aud === "string") {
        res.clientId = decoded.aud;
        const publicKey = await this.#handler(decoded.aud, decoded, body.client_assertion);

        if (publicKey) {
          const { payload } = await this.#jwtVerify(
            body.client_assertion,
            typeof publicKey === "string" ? new TextEncoder().encode(publicKey) : publicKey,
            {
              algorithms: this.algorithms,
            },
          );
          if (payload) {
            res.clientSecret = body.client_assertion;
          }
        }
      }
    }

    return res;
  }
}
