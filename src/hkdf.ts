import type { DigestAlgorithm, DigestReturnAs } from "./hash.ts";
import { encodeBytes } from "./_internal/encoding.ts";
import { textEncoder } from "./utils/index.ts";

/** Output byte length per hash algorithm (RFC 5869 HashLen). */
const _HASH_LEN: Record<DigestAlgorithm, number> = {
  "SHA-1": 20,
  "SHA-256": 32,
  "SHA-384": 48,
  "SHA-512": 64,
};

export interface HKDFOptions<T extends DigestReturnAs = DigestReturnAs> {
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
   * Requests above that limit throw a {@link RangeError} before reaching
   * the Web Crypto layer.
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
  salt?: string | BufferSource;
  /**
   * Optional context and application-specific information used for domain
   * separation. Two derivations from the same IKM/salt with different
   * `info` values produce independent keys.
   *
   * @default "" (empty)
   */
  info?: string | BufferSource;
  /**
   * Output format.
   *
   * @default "uint8array"
   */
  returnAs?: T;
}

/**
 * Derive key material using HKDF (RFC 5869) over the Web Crypto API.
 *
 * HKDF is a two-step KDF: an `extract` step condenses potentially
 * non-uniform input keying material (`ikm`) into a pseudorandom key, and
 * an `expand` step produces `length` bytes of output keyed with optional
 * `info` for domain separation.
 *
 * @param ikm Input keying material. Use a high-entropy secret — a shared
 *            secret, ECDH output, or seed. Do not pass a low-entropy
 *            password; use PBKDF2/Argon2 for password → key derivation.
 * @param options Algorithm, length, salt, info, and output format.
 * @returns Derived bytes as a {@link Uint8Array} (default) or the encoded
 *          form selected by `returnAs`.
 *
 * @throws {RangeError} If `length` is not a positive integer or exceeds
 *                      `255 * HashLen` for the chosen algorithm.
 *
 * @example
 * // Raw bytes (default)
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
  ikm: string | BufferSource,
  options?: HKDFOptions<T>,
): Promise<T extends "uint8array" | "bytes" ? Uint8Array<ArrayBuffer> : string>;
export async function hkdf(
  ikm: string | BufferSource,
  options?: Omit<HKDFOptions, "returnAs">,
): Promise<Uint8Array<ArrayBuffer>>;
export async function hkdf<T extends DigestReturnAs>(
  ikm: string | BufferSource,
  options: HKDFOptions<T> = {},
): Promise<T extends "uint8array" | "bytes" ? Uint8Array<ArrayBuffer> : string> {
  const { algorithm = "SHA-256", length = 32, salt, info, returnAs = "uint8array" as T } = options;

  if (!Number.isInteger(length) || length < 1) {
    throw new RangeError("length must be a positive integer.");
  }
  const maxLen = 255 * _HASH_LEN[algorithm];
  if (length > maxLen) {
    throw new RangeError(
      `HKDF with ${algorithm} can derive at most ${maxLen} bytes, requested ${length}.`,
    );
  }

  const ikmBytes = typeof ikm === "string" ? textEncoder.encode(ikm) : ikm;
  const saltBytes = _coerceOptionalBytes(salt);
  const infoBytes = _coerceOptionalBytes(info);

  const cryptoKey = await crypto.subtle.importKey("raw", ikmBytes, "HKDF", false, ["deriveBits"]);

  const derivedBits = await crypto.subtle.deriveBits(
    {
      name: "HKDF",
      hash: algorithm,
      salt: saltBytes,
      info: infoBytes,
    },
    cryptoKey,
    length * 8,
  );

  const bytes = new Uint8Array(derivedBits);
  return encodeBytes<T>(bytes, returnAs, "hkdf");
}

function _coerceOptionalBytes(value: string | BufferSource | undefined): BufferSource {
  if (value === undefined) return new Uint8Array(0);
  if (typeof value === "string") return textEncoder.encode(value);
  return value;
}
