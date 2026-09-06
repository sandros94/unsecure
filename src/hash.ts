import { assertReturnAs, encodeBytes } from "./_internal/encoding.ts";
import { normalizeAlgorithm } from "./_internal/algorithm.ts";
import { type BytesSource, toCryptoBytes } from "./_internal/bytes.ts";
import { viaWebCrypto } from "./_internal/platform.ts";

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
   * - `BytesSource` input defaults to `'uint8array'`
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
 * - `BytesSource` input returns a `Uint8Array<ArrayBuffer>`
 *
 * Use the `returnAs` option to explicitly override the output format.
 *
 * @param data The input data to hash. Can be a string or any BytesSource
 * (e.g., Uint8Array, ArrayBuffer).
 * @param options Configuration options for the hashing operation.
 * @returns A Promise that resolves to a string (HEX, Base64, Base64URL) or Uint8Array<ArrayBuffer> containing the raw hash.
 *
 * @throws {UnsecureError} `INVALID_TYPE` if `data` is neither text nor bytes;
 *                         `UNSUPPORTED` for an unknown `algorithm` or `returnAs`;
 *                         `PLATFORM` if the runtime's Web Crypto refuses the digest.
 *
 * @example
 * // Hash a string — returns hex string by default
 * const hashHex = await hash('hello world');
 *
 * // Hash a Uint8Array — returns Uint8Array<ArrayBuffer> by default
 * const buffer = new TextEncoder().encode('some binary data');
 * const hashBytes = await hash(buffer);
 *
 * // Explicit returnAs overrides the default
 * const hashBytes512 = await hash('hello', { algorithm: 'SHA-512', returnAs: 'uint8array' });
 * const hashHexFromBuffer = await hash(buffer, { returnAs: 'hex' });
 */
export async function hash<T extends DigestReturnAs>(
  data: string | BytesSource,
  options: DigestOptions & { returnAs: T },
): Promise<T extends "uint8array" | "bytes" ? Uint8Array<ArrayBuffer> : string>;
export async function hash(
  data: string,
  options?: Omit<DigestOptions, "returnAs">,
): Promise<string>;
export async function hash(
  data: BytesSource,
  options?: Omit<DigestOptions, "returnAs">,
): Promise<Uint8Array<ArrayBuffer>>;
export async function hash(
  data: string | BytesSource,
  options?: Omit<DigestOptions, "returnAs">,
): Promise<Uint8Array<ArrayBuffer> | string>;
export async function hash(
  data: string | BytesSource,
  options: DigestOptions = {},
): Promise<Uint8Array<ArrayBuffer> | string> {
  const { returnAs } = options;
  assertReturnAs(returnAs, "hash");
  const algorithm = normalizeAlgorithm(options.algorithm ?? "SHA-256", "hash");

  const isBufferInput = typeof data !== "string";
  const dataBytes = toCryptoBytes(data, "hash");

  const hashBytes = new Uint8Array(
    await viaWebCrypto("hash", "digest", () => crypto.subtle.digest(algorithm, dataBytes)),
  );

  const effectiveReturnAs = returnAs ?? (isBufferInput ? "uint8array" : "hex");

  return encodeBytes(hashBytes, effectiveReturnAs, "hash");
}
