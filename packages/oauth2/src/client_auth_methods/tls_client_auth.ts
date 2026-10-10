/**
 * @module
 *
 * Implements the `tls_client_auth` (mTLS) client authentication method, where the
 * client authenticates using a client certificate over a mutually TLS connection.
 * The client certificate is sent in the request headers, typically forwarded by a reverse proxy.
 *
 * JWT decoding and verification logic is injected via the constructor to avoid
 * a hard dependency on any particular JWT library.
 *
 * @see https://datatracker.ietf.org/doc/html/rfc8705
 */

import { MtlsCertificateBoundTokenType } from "../token_types/mtls_certificate_bound_token_type.ts";
import type { OAuth2Client } from "../types.ts";
import type { JwtDecode } from "../utils/jwt_types.ts";
import type { TlsClientAuthHeadersValues } from "./types.ts";
import type {
  ClientAuthMethod,
  ClientAuthMethodResponse,
  TokenEndpointAuthMethod,
} from "./types.ts";

/**
 * Handler function type for validating the client certificate in TLS client authentication.
 */
export interface TlsClientAuthHandler {
  (
    clientId: string,
    headers: TlsClientAuthHeadersValues,
    clientData?: Partial<OAuth2Client> | undefined,
  ): boolean | Promise<boolean>;
}

/**
 * Options for configuring the TLS client authentication method.
 */
export interface TlsClientAuthOptions {
  certHeaderName?: string;
  certVerifyHeaderName?: string;
  certDnHeaderName?: string;
  certSanHeaderName?: string;
  certExpireHeaderName?: string;
  additionalHeadersNames?: string[];
  validateClientSubject?: TlsClientAuthHandler;
  getClientData?: (
    clientId: string,
    headers: TlsClientAuthHeadersValues,
  ) => Promise<Partial<OAuth2Client> | undefined> | Partial<OAuth2Client> | undefined;
}

/**
 * TLS client authentication method as defined in RFC 8705.
 *
 * @see https://datatracker.ietf.org/doc/html/rfc8705
 *
 * This class provides a way to extract and validate client certificates from HTTP requests.
 * It allows you to configure the headers used to forward the client certificate and its verification status.
 * It also provides a mechanism to validate the client certificate against the client ID.
 * This class is useful in scenarios where client authentication needs to be performed using TLS client certificates, such as in secure API communications.
 * @example
 * const tlsAuth = new TlsClientAuthMethod({
 *   certHeaderName: "x-ssl-client-cert",
 *   certVerifyHeaderName: "x-ssl-client-verify",
 *   certDnHeaderName: "x-ssl-client-dn",
 *   certSanHeaderName: "x-ssl-client-san",
 *   certExpireHeaderName: "x-ssl-client-expire",
 *   additionalHeadersNames: ["x-ssl-client-extra-header"],
 * });
 *
 * tlsAuth.validateClientSubject(async (clientId, headers) => {
 *   // Implement your certificate validation logic here
 *   return true;
 * });
 */
export class TlsClientAuthMethod implements ClientAuthMethod {
  // RFC 8705 official registered name
  readonly method: TokenEndpointAuthMethod = "tls_client_auth";

  // mTLS relies on private key possession, not a symmetric client secret
  // But we still need to extract the client certificate as a secret equivalent for validation.
  readonly secretIsOptional = false;

  #certHeaderName: string;
  #certVerifyHeaderName: string;
  #certDnHeaderName: string;
  #certSanHeaderName: string;
  #certExpireHeaderName: string;
  #additionalHeadersNames: string[];

  #handler: (
    clientId: string,
    headers: TlsClientAuthHeadersValues,
    clientData?: Partial<OAuth2Client> | undefined,
  ) => boolean | Promise<boolean>;

  #getClientDataHandler?: (
    clientId: string,
    headers: TlsClientAuthHeadersValues,
  ) => Promise<Partial<OAuth2Client> | undefined> | Partial<OAuth2Client> | undefined;

  /**
   * Initializes a new instance of the TLS client authentication method.
   *
   * @param headers - The headers configuration for the TLS client authentication method.
   * Defaults will be used if not provided.
   */
  constructor(options: TlsClientAuthOptions = {}) {
    this.#certHeaderName = options.certHeaderName ?? "x-ssl-client-cert";
    this.#certVerifyHeaderName = options.certVerifyHeaderName ?? "x-ssl-client-verify";
    this.#certDnHeaderName = options.certDnHeaderName ?? "x-ssl-client-dn";
    this.#certSanHeaderName = options.certSanHeaderName ?? "x-ssl-client-san";
    this.#certExpireHeaderName = options.certExpireHeaderName ?? "x-ssl-client-expire";
    this.#additionalHeadersNames = options.additionalHeadersNames ?? [];

    this.#handler = options.validateClientSubject ?? (() => Promise.resolve(false));
    this.#getClientDataHandler = options.getClientData;
  }

  /**
   * Sets the handler function used to validate the client certificate.
   *
   * Validate the Subject Distinguished Name (DN) or Subject Alternative Name (SAN)
   * and other relevant information extracted from the client certificate.
   *
   * @param handler - A function that validates the client certificate for the given client ID.
   * @returns The current instance for method chaining.
   */
  validateClientSubject(
    handler: (
      clientId: string,
      headers: TlsClientAuthHeadersValues,
      clientData?: Partial<OAuth2Client> | undefined,
    ) => boolean | Promise<boolean>,
  ): this {
    this.#handler = handler;
    return this;
  }

  /**
   * Optionally retrieves the client information based on the TLS client authentication headers.
   *
   * Particularly useful when the client information is needed for further processing after TLS client authentication.
   *
   * @param handler - An async function that returns the client information or `undefined`.
   * @returns The current `TlsClientAuthMethod` instance for chaining.
   */
  getClientData(
    handler: (
      clientId: string,
      headers: TlsClientAuthHeadersValues,
    ) => Promise<Partial<OAuth2Client> | undefined> | Partial<OAuth2Client> | undefined,
  ): this {
    this.#getClientDataHandler = handler;
    return this;
  }

  /**
   * Creates a {@link MtlsCertificateBoundTokenType} configured to reuse this method's
   * client certificate header, so issued access (and optionally refresh) tokens can be
   * bound to the same client certificate used here.
   *
   * @param decodeTokenPayload - Callback to decode/verify the JWT access token payload.
   * @param boundRefreshToken - Indicates whether the refresh token should also be bound
   *   to the client certificate (default: `false`).
   *   If set to `true`, `decodeTokenPayload` will be invoked at the time of decoding the
   *   refresh token and will receive the `isRefreshToken` flag as `true`.
   * @returns A new `MtlsCertificateBoundTokenType` instance using this method's
   *   `certHeaderName`.
   */
  createCertificateBoundTokenType(
    decodeTokenPayload: JwtDecode,
    boundRefreshToken: boolean = false,
  ): MtlsCertificateBoundTokenType {
    return new MtlsCertificateBoundTokenType(
      decodeTokenPayload,
      boundRefreshToken,
      this.#certHeaderName,
    );
  }

  /**
   * Extracts and verifies the client certificate from the request headers.
   *
   * Looks for the client certificate in the request headers as specified by the
   * `certHeaderName` provided in the constructor. The `client_id` is expected to
   * be included in the request body as per RFC 8705.
   *
   * Supports `application/x-www-form-urlencoded` content type.
   *
   * @param request - The incoming HTTP request.
   * @returns The extracted client credentials, or `{ hasAuthMethod: false }` if the
   *   request does not contain a valid client certificate.
   */
  async extractClientCredentials(request: Request): Promise<ClientAuthMethodResponse> {
    // mTLS authentication must only happen on POST requests to the token endpoint
    if (request.method !== "POST") {
      return { hasAuthMethod: false };
    }

    // Look for the TLS client certificate forwarded by the reverse proxy
    const clientCertPem = request.headers.get(this.#certHeaderName);
    const clientCertVerify = request.headers.get(this.#certVerifyHeaderName);
    const clientCertDn = request.headers.get(this.#certDnHeaderName);
    const clientCertSan = request.headers.get(this.#certSanHeaderName);
    const clientCertExpire = request.headers.get(this.#certExpireHeaderName);
    const additionalHeaders: Record<string, string> = {};
    if (!clientCertPem || clientCertVerify !== "SUCCESS") {
      return { hasAuthMethod: false };
    }
    for (const headerName of this.#additionalHeadersNames) {
      const headerValue = request.headers.get(headerName);
      if (headerValue) {
        additionalHeaders[headerName] = headerValue;
      }
    }

    try {
      // RFC 8705 states the client MUST include its 'client_id' in the request body
      // We parse the urlencoded body to extract it.
      const contentType = request.headers.get("content-type") || "";
      if (!contentType.includes("application/x-www-form-urlencoded")) {
        return { hasAuthMethod: false };
      }

      // Clone the request because reading body consumes the stream
      const clonedRequest = request.clone();
      const formData = await clonedRequest.formData();
      const clientId = formData.get("client_id")?.toString();

      if (!clientId) {
        return { hasAuthMethod: false };
      }

      // Optionally retrieve client data based on the TLS client authentication headers
      const clientData = await this.#getClientDataHandler?.(clientId, {
        cert: clientCertPem,
        certVerify: clientCertVerify,
        certDn: clientCertDn ?? undefined,
        certSan: clientCertSan ?? undefined,
        certExpire: clientCertExpire ?? undefined,
        additionalHeaders,
      });

      // Implement proper client certificate validation here.
      // This may include checking the certificate's signature, expiration,
      // and matching it against the registered client information (e.g. array of allowed certificates/thumbprints).
      const isValidClient = await this.#handler(
        clientId,
        {
          cert: clientCertPem,
          certVerify: clientCertVerify,
          certDn: clientCertDn ?? undefined,
          certSan: clientCertSan ?? undefined,
          certExpire: clientCertExpire ?? undefined,
          additionalHeaders,
        },
        clientData ? { ...clientData } : undefined,
      );
      if (!isValidClient) {
        return { hasAuthMethod: false };
      }

      // Return the extracted credentials.
      // Instead of client_secret, we forward the client certificate payload
      // under the generic response fields required by @saurbit/oauth2.
      return {
        hasAuthMethod: true,
        clientId,
        // Passing the certificate as the secret equivalent so the flow's
        // getClient() callback can validate it against the registered public key/cert.
        clientSecret: clientCertPem,
        clientData,
      };
    } catch {
      return { hasAuthMethod: false };
    }
  }
}
