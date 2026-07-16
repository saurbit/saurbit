import { JwkThumbprintCalculator, JwkVerify, JwtPayload } from "../utils/jwt_types.ts";
import { InMemoryReplayStore, ReplayDetector } from "../utils/replay_store.ts";
import type { TokenType, TokenTypeValidationResponse } from "./types.ts";

export interface DPoPTokenTypeValidationResponse extends TokenTypeValidationResponse {
  data?: {
    dpopPayload: Record<string, unknown>;
    dpopThumbprint?: string;
  };
}

/**
 * A custom handler for validating a DPoP-bound access token on a protected resource endpoint.
 *
 * @param request - The incoming HTTP request containing the `DPoP` proof header.
 * @param token - The DPoP-bound access token extracted from the `Authorization` header.
 * @param tokenLifetime - The maximum acceptable age of the DPoP proof in seconds.
 * @returns A validation response indicating whether the proof and token are valid.
 */
export type DPoPTokenTypeValidation = (
  request: Request,
  token: string,
  tokenLifetime: number,
) => DPoPTokenTypeValidationResponse | Promise<DPoPTokenTypeValidationResponse>;

/**
 * A custom handler for validating a DPoP proof on a token endpoint request,
 * before client credentials are checked.
 *
 * @param req - The incoming token endpoint HTTP request containing the `DPoP` proof header.
 * @param tokenLifetime - The maximum acceptable age of the DPoP proof in seconds.
 * @returns A validation response indicating whether the proof is valid.
 */
export type DPoPTokenTypeRequestValidation = (
  req: Request,
  tokenLifetime: number,
) => DPoPTokenTypeValidationResponse | Promise<DPoPTokenTypeValidationResponse>;

/**
 * {@link TokenType} implementation for the DPoP (Demonstration of Proof-of-Possession) token scheme.
 *
 * Validates DPoP proofs on both the token endpoint and protected resource endpoints,
 * and detects replayed JTI claims using a {@link ReplayDetector}.
 *
 * @see https://datatracker.ietf.org/doc/html/rfc9449
 */
export class DPoPTokenType implements TokenType {
  #handler: DPoPTokenTypeValidation;
  #tokenRequestHandler: DPoPTokenTypeRequestValidation;
  #tokenLifetime: number = 300;
  #replayDetector: ReplayDetector;

  /**
   * The token type prefix used in the `Authorization` header and `token_type` response field.
   * Always `"DPoP"`.
   */
  get prefix(): "DPoP" {
    return "DPoP";
  }

  /**
   * Returns the DPoP-related metadata to include in the OpenID Connect discovery document.
   */
  get configuration(): { dpop_signing_alg_values_supported: string[]; require_dpop: boolean } {
    return {
      dpop_signing_alg_values_supported: ["ES256"],
      require_dpop: true,
    };
  }

  #jwkVerify: JwkVerify;
  #jwkThumbprintCalculator: JwkThumbprintCalculator;

  /**
   * Creates a new `DPoPTokenType` instance.
   *
   * @param jwkVerify - A function that verifies a DPoP proof JWT against a JWK Set.
   * @param jwkThumbprintCalculator - A function that calculates the JWK thumbprint for a given JWK.
   * @param replayDetector - An optional replay detector for JTI tracking.
   *   Defaults to an {@link InMemoryReplayStore}.
   */
  constructor(
    jwkVerify: JwkVerify,
    jwkThumbprintCalculator: JwkThumbprintCalculator,
    replayDetector?: ReplayDetector,
  ) {
    this.#jwkVerify = jwkVerify;
    this.#jwkThumbprintCalculator = jwkThumbprintCalculator;
    this.#replayDetector = replayDetector ?? new InMemoryReplayStore<string>();
    this.#handler = async (req: Request, token, tokenLifetime: number) => {
      if (!token) return { isValid: false, message: "Missing token" };
      return await this._handleDefault(req, tokenLifetime);
    };

    this.#tokenRequestHandler = async (req: Request, tokenLifetime: number) => {
      return await this._handleDefault(req, tokenLifetime);
    };
  }

  private async _handleDefault(
    req: Request,
    tokenLifetime: number,
  ): Promise<DPoPTokenTypeValidationResponse> {
    const dpopHeader = req.headers.get("DPoP");
    if (!dpopHeader || typeof dpopHeader != "string") {
      return { message: "Missing Demonstration of Proof-of-Possession", isValid: false };
    }

    try {
      const { payload, protectedHeader } = await this.#jwkVerify(
        dpopHeader,
      );

      if (payload.htm !== req.method.toUpperCase()) {
        return { message: "HTM mismatch", isValid: false };
      }

      const url = new URL(req.url);
      const forwardedProto = req.headers.get("x-forwarded-proto");
      const protocol = forwardedProto ? forwardedProto : url.protocol.replace(":", "");
      const fullUrl = protocol + "://" + url.host + url.pathname;
      if (payload.htu !== fullUrl) return { message: "HTU mismatch", isValid: false };

      const now = Math.floor(Date.now() / 1000);

      if (!payload.iat) return { message: "Missing IAT", isValid: false };
      if (Math.abs(now - payload.iat) > tokenLifetime) {
        return { message: "Proof expired", isValid: false };
      }

      if (!payload.jti) return { message: "Missing JTI", isValid: false };

      if (await this.#replayDetector.has(payload.jti)) {
        return { message: "Replay detected", isValid: false };
      }
      await this.#replayDetector.add(payload.jti, tokenLifetime);

      const data: DPoPTokenTypeValidationResponse["data"] = {
        dpopPayload: payload,
      };

      if (protectedHeader.jwk) {
        data.dpopThumbprint = await this.#jwkThumbprintCalculator(protectedHeader.jwk);
        // const tokenThumbprint = ... extract from access token cnf.jkt
        // if (tokenThumbprint !== data.dpopThumbprint) throw new Error('Token binding mismatch');
      }

      return { isValid: true, data };
    } catch (err) {
      return { message: `${err}`, isValid: false };
    }
  }

  /**
   * Replaces the replay detector used for JTI tracking.
   * Use this to provide a distributed store (e.g. Redis) in multi-process deployments.
   *
   * @param value - The replay detector to use.
   */
  setReplayDetector(value: ReplayDetector): this {
    this.#replayDetector = value;
    return this;
  }

  /**
   * Set the token lifetime for DPoP proofs (in seconds). Default is 300 seconds (5 minutes).
   * @param tokenLifetime - token lifetime for DPoP proofs (in seconds)
   */
  setTokenLifetime(tokenLifetime: number): this {
    this.#tokenLifetime = tokenLifetime;
    return this;
  }

  /**
   * Overrides the default DPoP proof validation handler for token endpoint requests.
   *
   * @param handler - A custom {@link DPoPTokenTypeRequestValidation} function.
   */
  validateTokenRequest(handler: DPoPTokenTypeRequestValidation): this {
    this.#tokenRequestHandler = handler;
    return this;
  }

  /**
   * Overrides the default DPoP proof validation handler for protected resource requests.
   *
   * @param handler - A custom {@link DPoPTokenTypeValidation} function.
   */
  validate(handler: DPoPTokenTypeValidation): this {
    this.#handler = handler;
    return this;
  }

  /**
   * Validates the DPoP proof on an incoming token endpoint request.
   * Called before client credentials are verified.
   *
   * @param req - The incoming token endpoint HTTP request.
   * @returns A validation response indicating whether the DPoP proof is valid.
   */
  async isValidTokenRequest(req: Request): Promise<DPoPTokenTypeValidationResponse> {
    return await this.#tokenRequestHandler(req, this.#tokenLifetime);
  }

  /**
   * Validates the DPoP proof on an incoming protected resource request.
   *
   * @param req - The incoming HTTP request.
   * @param token - The DPoP-bound access token extracted from the `Authorization` header.
   * @returns A validation response indicating whether the proof and token are valid.
   */
  async isValid(req: Request, token: string): Promise<DPoPTokenTypeValidationResponse> {
    return await this.#handler(req, token, this.#tokenLifetime);
  }

  /**
   * Update the claims of a JWT payload to include the JWK thumbprint in the `cnf` claim.
   * Use this when issuing a DPoP-bound access token to bind it to the public key of the DPoP proof.
   *
   * @param claims - The JWT claims object to which the JWK thumbprint will be added.
   * @param thumbprint - The JWK thumbprint to add to the `cnf` claim.
   * @returns The updated JWT claims object.
   */
  addJwkThumbprintToCnfClaim(claims: JwtPayload, thumbprint: string): JwtPayload {
    if (!claims || typeof claims !== "object") {
      throw new Error("Invalid claims object");
    }
    if (!thumbprint || typeof thumbprint !== "string") {
      throw new Error("Invalid thumbprint");
    }
    const cnf: Record<string, unknown> = claims.cnf && typeof claims.cnf === "object"
      ? claims.cnf as Record<string, unknown>
      : {};
    cnf.jkt = thumbprint;
    claims.cnf = cnf;
    return claims;
  }
}
