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
 * Safely converts an ArrayBuffer to a Base64URL string.
 * This function works in Node/Bun/Deno/Cloudflare Workers and browser environments.
 *
 * @param buffer - The ArrayBuffer to convert
 * @returns The Base64URL string representation of the ArrayBuffer
 */
export function safeArrayBufferToBase64Url(buffer: ArrayBuffer): string {
  // Fast path for Node/Bun
  if (typeof Buffer !== "undefined") {
    return Buffer.from(buffer).toString("base64url");
  }

  // Convert the ArrayBuffer to a Base64URL string
  const bytes = new Uint8Array(buffer);
  let binary = "";
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]!);
  }

  // Make it URL-safe: swap characters and remove padding
  return btoa(binary)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

export function safeArrayBufferToHex(buffer: ArrayBuffer): string {
  // Fast path for Node/Bun
  if (typeof Buffer !== "undefined") {
    return Buffer.from(buffer).toString("hex");
  }

  // Convert the ArrayBuffer to a hex string
  const bytes = new Uint8Array(buffer);
  let hex = "";
  for (let i = 0; i < bytes.byteLength; i++) {
    hex += bytes[i]!.toString(16).padStart(2, "0");
  }
  return hex;
}

/**
 * Safely converts a Base64-encoded string to an ArrayBuffer.
 * This function works in Node/Bun/Deno/Cloudflare Workers and browser environments.
 *
 * @param base64 - The Base64 string to convert to an ArrayBuffer
 * @returns The ArrayBuffer representation of the Base64 string
 */
export function safeBase64ToArrayBuffer(base64: string): ArrayBuffer {
  // Fast path for Node/Bun
  if (typeof Buffer !== "undefined") {
    return Buffer.from(base64, "base64").buffer;
  }

  // Decode the Base64 string to a binary string
  const binaryString = atob(base64);
  // Convert the binary string to an ArrayBuffer
  const bytes = new Uint8Array(binaryString.length);
  for (let i = 0; i < binaryString.length; i++) {
    bytes[i] = binaryString.charCodeAt(i);
  }
  return bytes.buffer;
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
