import { type JwtPayload, type TokenType, type TokenTypeValidationResponse } from "@saurbit/oauth2";
import {
  safeArrayBufferToBase64Url,
  safeArrayBufferToHex,
  safeBase64ToArrayBuffer,
} from "../utils/methods.ts";

/**
 * Validation response for mTLS certificate-bound tokens.
 */
export interface CertificateBoundValidationResponse extends TokenTypeValidationResponse {
  data?: {
    mtlsPayload: JwtPayload;
    mtlsThumbprint?: string;
  };
}

/**
 * Represents the decoded payload of an mTLS-bound JWT token.
 */
export type MtlsJwtPayload = JwtPayload & { cnf?: { "x5t#S256"?: string } };

/**
 * A function that decodes a JWT string into its payload.
 * Optionnally considers whether the token is a refresh token if the `isRefreshToken` flag is set to `true`.
 *
 * @param token - The compact serialized JWT string to decode or the refresh token.
 * @param isRefreshToken - Indicates whether the token being decoded is a refresh token.
 * @returns The decoded payload, synchronously or as a Promise.
 */
export type MtlsJwtDecode = (
  token: string,
  isRefreshToken: boolean,
) => MtlsJwtPayload | Promise<MtlsJwtPayload>;

/**
 * {@link TokenType} implementation for the mTLS (Mutual TLS) token scheme.
 *
 * Validates mTLS-bound access tokens on both the token endpoint and protected resource endpoints,
 * ensuring that the presenting client certificate matches the token binding.
 *
 * Refresh tokens can also be bound to the client certificate if configured accordingly,
 * useful for public clients using mTLS for enhanced security.
 *
 * @see https://datatracker.ietf.org/doc/html/rfc8705
 */
export class MtlsCertificateBoundTokenType implements TokenType {
  /**
   * The prefix used in the `Authorization` header for mTLS-bound access tokens.
   */
  readonly prefix = "Bearer";

  /**
   * The callback function used to decode and verify the JWT token payload.
   */
  #decodeTokenPayload: MtlsJwtDecode;

  /**
   * Indicates whether the refresh token should be bound to the client certificate.
   */
  #boundRefreshToken: boolean;

  /**
   * The HTTP header name where the client certificate is expected.
   */
  #certHeaderName: string;

  /**
   * Creates a new `MtlsCertificateBoundTokenType` instance.
   *
   * @param decodeTokenPayload - Callback to decode/verify your JWT token payload.
   * @param boundRefreshToken - Indicates whether the refresh token should be bound to the client certificate (default: false).
   *   If set to `true`, `decodeTokenPayload` will be invoked at the time of decoding the refresh token and will receive the
   *   `isRefreshToken` flag as `true`.
   * @param certHeaderName - The HTTP header name where the client certificate is expected (default: "x-ssl-client-cert").
   */
  constructor(
    decodeTokenPayload: MtlsJwtDecode,
    boundRefreshToken: boolean = false,
    certHeaderName: string = "x-ssl-client-cert",
  ) {
    this.#decodeTokenPayload = decodeTokenPayload;
    this.#boundRefreshToken = boundRefreshToken;
    this.#certHeaderName = certHeaderName;
  }

  /**
   * Converts a PEM-encoded client certificate into a SHA-256 hash buffer.
   *
   * @param pem - The PEM-encoded client certificate.
   * @returns A promise that resolves to the SHA-256 hash of the certificate as an ArrayBuffer.
   */
  private async pemToHashBuffer(pem: string): Promise<ArrayBuffer> {
    // Clean URL-encoded format if it exists, headers, footers, and whitespace to extract the raw base64 data
    const decodedPem = pem.includes("%") ? decodeURIComponent(pem) : pem;
    const cleanBase64 = decodedPem
      .replace(/-----BEGIN CERTIFICATE-----/, "")
      .replace(/-----END CERTIFICATE-----/, "")
      .replace(/\s+/g, "");

    // Digest via the WebCrypto API
    return await crypto.subtle.digest("SHA-256", safeBase64ToArrayBuffer(cleanBase64));
  }

  private async handleRequest(
    request: Request,
    token: string,
    isRefreshToken: boolean,
  ): Promise<CertificateBoundValidationResponse> {
    if (!token) {
      return {
        isValid: false,
        message: "Access token is missing.",
      };
    }
    try {
      // Extract the client certificate from the current request
      const currentCertPem = request.headers.get(this.#certHeaderName);
      if (!currentCertPem) {
        return {
          isValid: false,
          message: "Client certificate missing on protected resource request.",
        };
      }

      // Decode the JWT payload
      const payload = await this.#decodeTokenPayload(token, isRefreshToken);
      const cnf = payload?.cnf;

      // Confirm the token contains the sender-constrained confirmation claim
      if (!(cnf && typeof cnf === "object" && "x5t#S256" in cnf && cnf["x5t#S256"])) {
        return {
          isValid: false,
          message: "Token validation failed: Missing mTLS token confirmation (cnf) claim.",
        };
      }

      // Compare the WebCrypto-generated thumbprint against the token binding
      const currentThumbprint = await this.calculateX5tS256(currentCertPem);
      if (currentThumbprint !== cnf["x5t#S256"]) {
        return {
          isValid: false,
          message: "Token sender mismatch: Presenting certificate does not match token binding.",
        };
      }

      return {
        isValid: true,
        data: {
          mtlsPayload: payload,
          mtlsThumbprint: currentThumbprint,
        },
      };
    } catch (error) {
      return {
        isValid: false,
        message: `mTLS token validation encountered an error: ${
          error instanceof Error ? error.message : "Unknown error"
        }`,
      };
    }
  }

  /**
   * Validates the token request at the token endpoint,
   * ensuring that any required mTLS-bound refresh token is properly presented
   * and verified.
   *
   * @param request - The incoming token endpoint HTTP request.
   * @param ctxt - Contextual information about the token request, such as the grant type and refresh token if applicable.
   * @returns A validation response indicating whether the request is valid.
   */
  async isValidTokenRequest(
    request: Request,
    ctxt: { grantType: string; refreshToken?: string },
  ): Promise<CertificateBoundValidationResponse> {
    // It should only validate the token request if refresh token binding is required
    // and if grant type is refresh token.
    if (this.#boundRefreshToken && ctxt.grantType === "refresh_token") {
      if (ctxt.refreshToken) {
        // Refresh token binding validation
        return await this.handleRequest(request, ctxt.refreshToken, true);
      } else {
        return {
          isValid: false,
          message: "Refresh token is missing.",
        };
      }
    }

    return { isValid: true };
  }

  /**
   * Validates the mTLS client certificate on an incoming protected resource request.
   *
   * @param request - The incoming HTTP request.
   * @param token - The mTLS-bound access token extracted from the `Authorization` header.
   * @returns A validation response indicating whether the proof and token are valid.
   */
  async isValid(request: Request, token: string): Promise<CertificateBoundValidationResponse> {
    return await this.handleRequest(request, token, false);
  }

  /**
   * Update the claims of a JWT payload to include the mTLS certificate thumbprint in the `cnf` claim.
   * Use this when issuing an mTLS-bound access token to bind it to the public key of the client certificate.
   *
   * @param claims - The JWT claims object to which the mTLS certificate thumbprint will be added.
   * @param thumbprint - The mTLS certificate thumbprint to add to the `cnf` claim.
   * @returns The updated JWT claims object.
   * @throws If the claims object is invalid or the thumbprint is not a non-empty string.
   */
  addThumbprintToCnfClaim(claims: JwtPayload, thumbprint: string): JwtPayload {
    if (!claims || typeof claims !== "object") {
      throw new Error("Invalid claims object");
    }
    let tmpThumbprint: string | undefined;
    if (typeof thumbprint === "string" && thumbprint.length > 0) {
      tmpThumbprint = thumbprint;
    } else {
      throw new Error("Invalid thumbprint argument");
    }
    const cnf: Record<string, unknown> = claims.cnf && typeof claims.cnf === "object"
      ? (claims.cnf as Record<string, unknown>)
      : {};
    cnf["x5t#S256"] = tmpThumbprint;
    claims.cnf = cnf;
    return claims;
  }

  /**
   * Applies the mTLS binding to the given JWT claims by adding the certificate thumbprint to the `cnf` claim.
   *
   * @param claims - The JWT claims object to which the mTLS certificate thumbprint will be added.
   * @param pemOrThumbprint - The PEM-encoded client certificate or the precomputed base64url-encoded SHA-256 thumbprint.
   * @returns The updated JWT claims object with the mTLS binding applied.
   */
  async applyBinding(claims: JwtPayload, pemOrThumbprint: string): Promise<JwtPayload> {
    const { x5tS256 } = pemOrThumbprint.includes("-----BEGIN CERTIFICATE-----")
      ? await this.computeThumbprint(pemOrThumbprint)
      : { x5tS256: pemOrThumbprint };
    return this.addThumbprintToCnfClaim(claims, x5tS256);
  }

  /**
   * Calculates the lowercase hexadecimal SHA-256 thumbprint of a PEM-encoded client certificate.
   * This method could be useful for other verification purposes.
   *
   * Not officially part of the mTLS binding process.
   *
   * @param pem - The PEM-encoded client certificate.
   * @returns The lowercase hexadecimal SHA-256 thumbprint of the certificate.
   */
  async calculateHexThumbprint(pem: string): Promise<string> {
    const hashBuffer = await this.pemToHashBuffer(pem);
    return safeArrayBufferToHex(hashBuffer);
  }

  /**
   * Parses a PEM string, extracts the binary DER bytes, and hashes it
   * using WebCrypto to produce an RFC 8705 compliant base64url SHA-256 thumbprint.
   *
   * @param pem - The PEM-encoded client certificate.
   * @returns The base64url-encoded SHA-256 thumbprint of the certificate.
   */
  async calculateX5tS256(pem: string): Promise<string> {
    const hashBuffer = await this.pemToHashBuffer(pem);
    // Convert the resulting ArrayBuffer to a base64url encoded string without padding
    return safeArrayBufferToBase64Url(hashBuffer);
  }

  /**
   * Computes the base64url-encoded SHA-256 thumbprint of a PEM-encoded client certificate.
   *
   * @param pem - The PEM-encoded client certificate.
   * @returns An object containing the base64url-encoded SHA-256 thumbprint under the key `x5tS256`.
   */
  async computeThumbprint(pem: string): Promise<{ x5tS256: string }> {
    const x5tS256 = await this.calculateX5tS256(pem);
    return { x5tS256 };
  }
}
