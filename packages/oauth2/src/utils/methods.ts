// Fast path for Node/Bun
declare const Buffer: {
  from(input: ArrayBuffer): Uint8Array<ArrayBuffer> & { toString(encoding: string): string };
  from(
    input: string,
    encoding: string,
  ): Uint8Array<ArrayBuffer> & { toString(encoding: string): string };
};

/**
 * Convert the ASCII string to a Uint8Array
 *
 * @param ascii - The ASCII string to convert
 * @returns The Uint8Array representation of the ASCII string
 */
function asciiToUint8Array(ascii: string): Uint8Array<ArrayBuffer> {
  // Fast path for Node/Bun
  if (typeof Buffer !== "undefined") {
    return Buffer.from(ascii, "ascii");
  }
  const encoder = new TextEncoder();
  return encoder.encode(ascii);
}

/**
 * Convert the ArrayBuffer to a Base64URL string
 *
 * @param buffer - The ArrayBuffer to convert
 * @returns The Base64URL string representation of the ArrayBuffer
 */
function arrayBufferToBase64Url(buffer: ArrayBuffer): string {
  // Fast path for Node/Bun
  if (typeof Buffer !== "undefined") {
    return Buffer.from(buffer).toString("base64url");
  }
  // Convert the ArrayBuffer to a Base64URL string
  const hashArray = Array.from(new Uint8Array(buffer));
  const base64 = btoa(String.fromCharCode(...hashArray));

  // Make it URL-safe: swap characters and remove padding
  return base64
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

/**
 * Generates the access token hash (ath) for a given access token.
 * The hash is computed using SHA-256 and then base64url-encoded.
 *
 * @param accessToken - The access token to hash
 * @returns A promise that resolves to the base64url-encoded SHA-256 hash of the access token
 */
export async function generateAccessTokenHash(accessToken: string): Promise<string> {
  // Convert the ASCII string to a Uint8Array
  const data = asciiToUint8Array(accessToken);

  // Compute the SHA-256 hash using the Web Crypto API
  const hashBuffer = await crypto.subtle.digest("SHA-256", data);

  // Convert the ArrayBuffer to a Base64URL string
  return arrayBufferToBase64Url(hashBuffer);
}
