import { hexEncode, base64Encode, base64UrlEncode } from "./utils.ts";

export type DigestAlgorithm = "SHA-256" | "SHA-384" | "SHA-512";
export type DigestReturnAs =
  | "hex"
  | "base64"
  | "b64"
  | "base64url"
  | "b64url"
  | "uint8array"
  | "bytes";

export interface DigestOptions {
  /**
   * The hashing algorithm to use.
   *
   * @default 'SHA-256'
   */
  algorithm?: DigestAlgorithm;
  /**
   * Whether to output to HEX, Base64, Base64URL or Uint8Array
   *
   * @default 'hex'
   */
  returnAs?: DigestReturnAs;
}

/**
 * Hashes input data using a specified cryptographic algorithm. The function is
 * designed to work in any modern JavaScript runtime (browsers, Node, Bun, Deno, etc.)
 * that supports the Web Crypto API.
 *
 * @param data The input data to hash. Can be a string or any BufferSource
 * (e.g., Uint8Array, ArrayBuffer).
 * @param options Configuration options for the hashing operation.
 * @returns A Promise that resolves to a string (HEX, Base64, Base64URL) or Uint8Array containing the raw hash. (default HEX)
 *
 * @example
 * // Hash a string using the default SHA-256
 * const hashHex = await hash('hello world');
 *
 * // Hash a Uint8Array using SHA-512
 * const buffer = new TextEncoder().encode('some binary data');
 * const hashBytes512 = await hash(buffer, { algorithm: 'SHA-512', returnAs: "uint8array" });
 */
export async function hash(data: string | BufferSource): Promise<string>;
export async function hash<T extends DigestReturnAs>(
  data: string | BufferSource,
  options: Omit<DigestOptions, "returnAs"> & { returnAs?: T },
): Promise<T extends "uint8array" | "bytes" ? Uint8Array : string>;
export async function hash(
  data: string | BufferSource,
  options: DigestOptions = {},
): Promise<Uint8Array | string> {
  const { algorithm = "SHA-256", returnAs = "hex" } = options;

  const dataBuffer =
    typeof data === "string" ? new TextEncoder().encode(data) : data;

  const hashBytes = new Uint8Array(
    await crypto.subtle.digest(algorithm, dataBuffer),
  );

  switch (returnAs) {
    case "bytes":
    case "uint8array": {
      return hashBytes;
    }
    case "hex": {
      return hexEncode(hashBytes);
    }
    case "b64":
    case "base64": {
      return base64Encode(hashBytes);
    }
    case "b64url":
    case "base64url": {
      return base64UrlEncode(hashBytes);
    }
    default: {
      throw new Error(`Unsupported hash "returnAs" option: ${returnAs}`);
    }
  }
}
