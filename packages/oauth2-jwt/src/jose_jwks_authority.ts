import {
  exportJWK,
  generateKeyPair,
  importJWK,
  JWK,
  JWTHeaderParameters,
  JWTPayload,
  jwtVerify,
  SignJWT,
} from "jose";
import { JwksKeyStore, JwtAuthority, RawKey, RSA } from "./types.ts";

// Fast path for Node/Bun
declare const Buffer: {
  from(input: string, encoding: string): { toString(encoding?: string): string };
};

function base64UrlToString(b64url: string): string {
  // Fast path for Node/Bun
  if (typeof Buffer !== "undefined") {
    return Buffer.from(b64url, "base64url").toString();
  }

  // Convert Base64URL → standard Base64
  const base64 = b64url.replace(/-/g, "+").replace(/_/g, "/");

  // Add padding if missing
  const padded = base64.padEnd(base64.length + (4 - (base64.length % 4)) % 4, "=");

  // Decode
  const binary = atob(padded);
  const bytes = Uint8Array.from(binary, (c) => c.charCodeAt(0));

  return new TextDecoder().decode(bytes);
}

export class JoseJwksAuthority implements JwtAuthority {
  #store: JwksKeyStore;
  /**
   * seconds
   */
  #ttl: number;

  /**
   * @param store The key store used to manage JWKS keys.
   * @param ttl Time-to-live for the keys in seconds.
   */
  constructor(store: JwksKeyStore, ttl: number = 36000) {
    this.#store = store;
    this.#ttl = ttl;
  }

  async #generateAndStoreKeyPair(): Promise<{ privateJwk: JWK; publicJwk: JWK }> {
    const { publicKey, privateKey } = await generateKeyPair("RS256", {
      modulusLength: 2048,
      extractable: true,
    });

    // Convert to JWK format and add necessary properties
    const privateJwk = await exportJWK(privateKey);
    const publicJwk = await exportJWK(publicKey);

    const kid = crypto.randomUUID();
    privateJwk.kid = kid;
    privateJwk.alg = "RS256";
    privateJwk.use = "sig";
    publicJwk.kid = kid;
    publicJwk.alg = "RS256";
    publicJwk.use = "sig";

    await this.#store.storeKeyPair(kid, privateJwk, publicJwk, this.#ttl);

    return { privateJwk, publicJwk };
  }

  async #getPrivateKey(): Promise<JWK> {
    const storedPrivateJwk = await this.#store.getPrivateKey();
    if (storedPrivateJwk) {
      return storedPrivateJwk;
    } else {
      const { privateJwk } = await this.#generateAndStoreKeyPair();
      return privateJwk;
    }
  }

  /**
   * Retrieves the current set of public keys from the key store.
   * @returns An object containing the array of public keys.
   */
  async getPublicKeys(): Promise<{ keys: RawKey[] }> {
    const publicJwks = await this.#store.getPublicKeys();
    const json = { keys: publicJwks } as { keys: RawKey[] };
    if (json && "keys" in json && Array.isArray(json.keys)) {
      json.keys = [...json.keys].reverse();
    }
    return json;
  }

  /**
   * Get current kid for observability/debugging
   */
  async getCurrentKid(): Promise<string | undefined> {
    const key = await this.#getPrivateKey();
    return key?.kid;
  }

  /**
   * Helps implement the JWKS endpoint by returning the current set of public keys in the expected format.
   * @returns The current set of public keys in the JWKS format.
   */
  getJwksEndpointResponse(): Promise<{ keys: RawKey[] }> {
    return this.getPublicKeys();
  }

  /**
   * Retrieves the public key corresponding to the given "kid" from the JWKS.
   * @param kid The key ID of the desired public key.
   * @returns The RSA public key if found, otherwise undefined.
   */
  async getPublicKey(kid: string): Promise<RSA | undefined> {
    const keyStore = await this.getPublicKeys();
    const key = keyStore.keys.find((k) => k.kid === kid);
    if (!key) return undefined;
    if (key.kty !== "RSA") return undefined;
    return key as RSA;
  }

  /**
   * Generates a new RSA key pair, stores it in the key store with the appropriate metadata
   * (kid, alg, use), and ensures that the public key is available for JWKS exposure.
   */
  async generateKeyPair(): Promise<void> {
    await this.#generateAndStoreKeyPair();
  }

  /**
   * Signs the given payload as a JWT using the current private key.
   * The "kid" of the signing key is included in the JWT header to allow verifiers
   * to select the correct public key from the JWKS for verification.
   * This method ensures that the JWT is signed with a valid key and that
   * the corresponding public key is available in the JWKS for future verification.
   * @param payload The payload to be signed as a JWT.
   * @returns An object containing the signed JWT and the key ID used for signing.
   */
  async sign(payload: JWTPayload): Promise<{ token: string; kid: string }> {
    const key = await this.#getPrivateKey();

    if (key.kty !== "RSA") {
      throw new Error("Invalid key type, expected RSA");
    }

    if (!key.kid) {
      throw new Error('Key is missing "kid" property');
    }

    const privateKey = await importJWK(key, "RS256");

    const token = await new SignJWT(payload as JWTPayload)
      .setProtectedHeader({ typ: "jwt", alg: "RS256", kid: key.kid })
      .sign(privateKey);

    return { token, kid: key.kid };
  }

  /**
   * Verifies the given JWT using the appropriate public key from the JWKS based on the "kid" in the JWT header.
   * It performs additional checks to ensure the integrity and expected structure of the JWT,
   * such as validating the algorithm and ensuring no unexpected JWK is present in the header.
   * @param token
   * @returns
   */
  async verify<P extends JWTPayload = JWTPayload>(token: string): Promise<P> {
    const [header] = token.split(".");

    if (!header) throw new Error("Invalid JWT format");

    const parsedHeader = JSON.parse(base64UrlToString(header)) as JWTHeaderParameters;
    const kid = parsedHeader.kid;

    if (!kid || typeof kid !== "string") throw new Error('Invalid or missing "kid" in JWT header');

    const key = await this.getPublicKey(kid);

    if (!key) throw new Error(`Key with kid "${kid}" not found`);

    const { payload, protectedHeader } = await jwtVerify<P>(token, key);

    if (protectedHeader.alg !== "RS256") {
      throw new Error(`Unexpected algorithm: ${protectedHeader.alg}`);
    }

    // additional checks hardening security
    if ("jwk" in protectedHeader) {
      throw new Error("Unexpected JWK in header — potential forgery attempt");
    }
    if (protectedHeader.typ && protectedHeader.typ.toLowerCase() !== "jwt") {
      throw new Error(`Unexpected typ: ${protectedHeader.typ}`);
    }

    return payload;
  }

  /**
   * Signs multiple payloads with the same private key, returning an array of tokens and their corresponding kids.
   * This is useful for batch operations where multiple JWTs need to be issued at once,
   * ensuring they all use the same key and can be verified against the same public key in the JWKS.
   * @param payloads The array of payloads to be signed as JWTs.
   * @returns An array of objects containing the signed JWTs and their corresponding key IDs.
   */
  async signMany(payloads: JWTPayload[]): Promise<{ token: string; kid: string }[]> {
    const key = await this.#getPrivateKey();

    if (key.kty !== "RSA") {
      throw new Error("Invalid key type, expected RSA");
    }

    if (!key.kid) {
      throw new Error('Key is missing "kid" property');
    }

    const privateKey = await importJWK(key, "RS256");

    const result: { token: string; kid: string }[] = [];

    for (const payload of payloads) {
      const token = await new SignJWT(payload as JWTPayload)
        .setProtectedHeader({ typ: "jwt", alg: "RS256", kid: key.kid })
        .sign(privateKey);

      result.push({ token, kid: key.kid });
    }

    return result;
  }
}
