import { hexEncode, base64Encode, base64UrlEncode, textEncoder } from "./utils.ts";

export type DigestAlgorithm = "SHA-1" | "SHA-256" | "SHA-384" | "SHA-512";
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
   * Whether to output to HEX, Base64, Base64URL or Uint8Array.
   *
   * When not specified, mirrors the input type:
   * - `string` input defaults to `'hex'`
   * - `BufferSource` input defaults to `'uint8array'`
   */
  returnAs?: DigestReturnAs;
}

/**
 * Hashes input data using a specified cryptographic algorithm. The function is
 * designed to work in any modern JavaScript runtime (browsers, Node, Bun, Deno, etc.)
 * that supports the Web Crypto API.
 *
 * When `returnAs` is not specified, the return type mirrors the input:
 * - `string` input returns a hex `string`
 * - `BufferSource` input returns a `Uint8Array`
 *
 * Use the `returnAs` option to explicitly override the output format.
 *
 * @param data The input data to hash. Can be a string or any BufferSource
 * (e.g., Uint8Array, ArrayBuffer).
 * @param options Configuration options for the hashing operation.
 * @returns A Promise that resolves to a string (HEX, Base64, Base64URL) or Uint8Array containing the raw hash.
 *
 * @example
 * // Hash a string — returns hex string by default
 * const hashHex = await hash('hello world');
 *
 * // Hash a Uint8Array — returns Uint8Array by default
 * const buffer = new TextEncoder().encode('some binary data');
 * const hashBytes = await hash(buffer);
 *
 * // Explicit returnAs overrides the default
 * const hashBytes512 = await hash('hello', { algorithm: 'SHA-512', returnAs: 'uint8array' });
 * const hashHexFromBuffer = await hash(buffer, { returnAs: 'hex' });
 */
export async function hash<T extends DigestReturnAs>(
  data: string | BufferSource,
  options: DigestOptions & { returnAs: T },
): Promise<T extends "uint8array" | "bytes" ? Uint8Array : string>;
export async function hash(
  data: string,
  options?: Omit<DigestOptions, "returnAs">,
): Promise<string>;
export async function hash(
  data: BufferSource,
  options?: Omit<DigestOptions, "returnAs">,
): Promise<Uint8Array>;
export async function hash(
  data: string | BufferSource,
  options: DigestOptions = {},
): Promise<Uint8Array | string> {
  const { algorithm = "SHA-256", returnAs } = options;

  const isBufferInput = typeof data !== "string";
  const dataBuffer = isBufferInput ? data : textEncoder.encode(data);

  const hashBytes = new Uint8Array(await crypto.subtle.digest(algorithm, dataBuffer));

  const effectiveReturnAs = returnAs ?? (isBufferInput ? "uint8array" : "hex");

  switch (effectiveReturnAs) {
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
