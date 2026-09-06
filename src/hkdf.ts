import type { DigestAlgorithm, DigestReturnAs } from "./hash.ts";
import { assertReturnAs, encodeBytes } from "./_internal/encoding.ts";
import { HASH_LENGTH, normalizeAlgorithm } from "./_internal/algorithm.ts";
import { assertInteger } from "./_internal/assert.ts";
import { type BytesSource, toCryptoBytes } from "./_internal/bytes.ts";
import { viaWebCrypto } from "./_internal/platform.ts";

/** RFC 5869 treats an absent salt or info as a zero-length one. */
const EMPTY: Uint8Array<ArrayBuffer> = /* @__PURE__ */ new Uint8Array(0);

export interface HKDFOptions {
  /**
   * Hash algorithm used by the underlying HMAC.
   *
   * @default "SHA-256"
   */
  algorithm?: DigestAlgorithm;
  /**
   * Desired output length in bytes.
   *
   * Per RFC 5869, the maximum is `255 * HashLen` (8160 for SHA-256).
   * Requests above that limit throw an {@link UnsecureError} with code
   * `OUT_OF_RANGE` before reaching the Web Crypto layer.
   *
   * @default 32
   */
  length?: number;
  /**
   * Optional salt value. Non-secret but strongly recommended — a unique
   * salt per deployment / deriver makes the extract step stronger.
   *
   * If omitted, an empty salt is used. HMAC-based HKDF treats an empty
   * salt as equivalent to a HashLen-of-zeros salt per RFC 5869.
   */
  salt?: string | BytesSource;
  /**
   * Optional context and application-specific information used for domain
   * separation. Two derivations from the same IKM/salt with different
   * `info` values produce independent keys.
   *
   * @default "" (empty)
   */
  info?: string | BytesSource;
  /**
   * Output format.
   *
   * When not specified, mirrors the `ikm` input type:
   * - `string` ikm defaults to `'hex'`
   * - `BytesSource` ikm defaults to `'uint8array'`
   */
  returnAs?: DigestReturnAs;
}

/**
 * Derive key material using HKDF (RFC 5869) over the Web Crypto API.
 *
 * HKDF is a two-step KDF: an `extract` step condenses potentially
 * non-uniform input keying material (`ikm`) into a pseudorandom key, and
 * an `expand` step produces `length` bytes of output keyed with optional
 * `info` for domain separation.
 *
 * When `returnAs` is not specified, the return type mirrors the `ikm` input:
 * - `string` ikm returns a hex `string`
 * - `BytesSource` ikm returns a `Uint8Array<ArrayBuffer>`
 *
 * Use the `returnAs` option to explicitly override the output format.
 *
 * @param ikm Input keying material. Use a high-entropy secret — a shared
 *            secret, ECDH output, or seed. Do not pass a low-entropy
 *            password; use PBKDF2/Argon2 for password → key derivation.
 * @param options Algorithm, length, salt, info, and output format.
 * @returns Derived bytes encoded according to `returnAs`, or mirroring the
 *          `ikm` input type when `returnAs` is omitted.
 *
 * @throws {UnsecureError} `OUT_OF_RANGE` if `length` is not an integer from 1 to
 *                         `255 * HashLen` for the chosen algorithm (8160 for
 *                         SHA-256); `UNSUPPORTED` for an unknown `algorithm` or
 *                         `returnAs`; `INVALID_TYPE` if `ikm`, `salt` or `info` is
 *                         neither text nor bytes; `PLATFORM` if the runtime's Web
 *                         Crypto refuses.
 *
 * @example
 * // BytesSource ikm -> Uint8Array output (default)
 * const key = await hkdf(sharedSecret, { salt, info: "my-app/auth/v1" });
 *
 * @example
 * // Base64url-encoded output, explicit SHA-512, 64-byte key
 * const keyB64 = await hkdf(ikm, {
 *   algorithm: "SHA-512",
 *   length: 64,
 *   info: "encryption-key",
 *   returnAs: "base64url",
 * });
 *
 * @example
 * // Domain separation: same IKM, different contexts -> independent keys
 * const encKey = await hkdf(ikm, { salt, info: "enc" });
 * const macKey = await hkdf(ikm, { salt, info: "mac" });
 */
export async function hkdf<T extends DigestReturnAs>(
  ikm: string | BytesSource,
  options: HKDFOptions & { returnAs: T },
): Promise<T extends "uint8array" | "bytes" ? Uint8Array<ArrayBuffer> : string>;
export async function hkdf(ikm: string, options?: Omit<HKDFOptions, "returnAs">): Promise<string>;
export async function hkdf(
  ikm: BytesSource,
  options?: Omit<HKDFOptions, "returnAs">,
): Promise<Uint8Array<ArrayBuffer>>;
export async function hkdf(
  ikm: string | BytesSource,
  options?: Omit<HKDFOptions, "returnAs">,
): Promise<Uint8Array<ArrayBuffer> | string>;
export async function hkdf(
  ikm: string | BytesSource,
  options: HKDFOptions = {},
): Promise<Uint8Array<ArrayBuffer> | string> {
  const { length = 32, salt, info, returnAs } = options;
  assertReturnAs(returnAs, "hkdf");
  const algorithm = normalizeAlgorithm(options.algorithm ?? "SHA-256", "hkdf");

  // RFC 5869 caps one derivation at 255 * HashLen bytes; both ends of the
  // range are the same check, so the message reads like every other one.
  assertInteger("hkdf", "length", length, 1, 255 * HASH_LENGTH[algorithm]);

  const isBufferInput = typeof ikm !== "string";
  const ikmBytes = toCryptoBytes(ikm, "hkdf");
  const saltBytes = salt === undefined ? EMPTY : toCryptoBytes(salt, "hkdf");
  const infoBytes = info === undefined ? EMPTY : toCryptoBytes(info, "hkdf");

  const cryptoKey = await viaWebCrypto("hkdf", "importKey", () =>
    crypto.subtle.importKey("raw", ikmBytes, "HKDF", false, ["deriveBits"]),
  );

  const derivedBits = await viaWebCrypto("hkdf", "deriveBits", () =>
    crypto.subtle.deriveBits(
      {
        name: "HKDF",
        hash: algorithm,
        salt: saltBytes,
        info: infoBytes,
      },
      cryptoKey,
      length * 8,
    ),
  );

  const bytes = new Uint8Array(derivedBits);
  const effectiveReturnAs = returnAs ?? (isBufferInput ? "uint8array" : "hex");
  return encodeBytes(bytes, effectiveReturnAs, "hkdf");
}
