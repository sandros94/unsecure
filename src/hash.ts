import type { DigestOptions } from "./types";
import { hexEncode } from "./utils";

/**
 * Hashes input data using a specified cryptographic algorithm. The function is
 * designed to work in any modern JavaScript runtime (browsers, Node, Bun, Deno, etc.)
 * that supports the Web Crypto API.
 *
 * @param data The input data to hash. Can be a string or any BufferSource
 * (e.g., Uint8Array, ArrayBuffer).
 * @param options Configuration options for the hashing operation.
 * @returns A Promise that resolves to a HEX string or Uint8Array containing the raw hash.
 *
 * @example
 * // Hash a string using the default SHA-256
 * const hashBytes = await hash('hello world');
 *
 * // Hash a Uint8Array using SHA-512
 * const buffer = new TextEncoder().encode('some binary data');
 * const hashBytes512 = await hash(buffer, { algorithm: 'SHA-512' });
 */
export async function hash(data: string | BufferSource): Promise<string>;
export async function hash<T extends boolean>(
  data: string | BufferSource,
  options: Omit<DigestOptions, "asString"> & { asString: T },
): Promise<T extends false ? Uint8Array : string>;
export async function hash<T extends boolean | undefined>(
  data: string | BufferSource,
  options: Omit<DigestOptions, "asString"> & { asString?: T },
): Promise<string>;
export async function hash(
  data: string | BufferSource,
  options?: DigestOptions,
): Promise<Uint8Array | string> {
  const { algorithm = "SHA-256", asString } = options || {};

  const dataBuffer =
    typeof data === "string" ? new TextEncoder().encode(data) : data;

  const hashBytes = new Uint8Array(
    await crypto.subtle.digest(algorithm, dataBuffer),
  );

  return asString === false ? hashBytes : hexEncode(hashBytes);
}
