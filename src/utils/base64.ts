import { type Base64Alphabet, base64ParseText, base64StringifyBytes } from "../_internal/base64.ts";
import { type BytesSource, toBytes } from "../_internal/bytes.ts";
import {
  type DecodeReturnAs,
  type PaddedDecodeOptions,
  assertData,
  parseFinalize,
  parsePrep,
} from "../_internal/codec.ts";

export type { Base64Alphabet };

export interface Base64StringifyOptions {
  /**
   * Alphabet: `"base64"` (`+/`) or `"base64url"` (`-_`).
   * @default "base64"
   */
  alphabet?: Base64Alphabet;
  /**
   * Emit `=` padding. `base64url` defaults to unpadded.
   * @default true
   */
  padding?: boolean;
}

export interface Base64ParseOptions extends PaddedDecodeOptions {
  /**
   * Alphabet to enforce in strict mode. `loose` accepts either alphabet and
   * ignores this.
   * @default "base64"
   */
  alphabet?: Base64Alphabet;
}

export interface Base64Codec {
  /** See {@link base64Stringify}. */
  stringify: typeof base64Stringify;
  /** See {@link base64Parse}. */
  parse: typeof base64Parse;
}

/**
 * Encode bytes to base64.
 *
 * @param data - raw bytes (any `BytesSource`), or a `string` (UTF-8 encoded first)
 * @param options - see {@link Base64StringifyOptions}
 * @returns the base64 string
 * @throws {UnsecureError} `INVALID_TYPE` if `data` is not a string, `ArrayBuffer` or view over one
 * @example
 * base64Stringify(bytes, { alphabet: "base64url" });
 */
/* @__NO_SIDE_EFFECTS__ */
export function base64Stringify(
  data: string | BytesSource,
  options?: Base64StringifyOptions,
): string {
  return base64StringifyBytes(toBytes(data, "Base64.stringify"), options);
}

/**
 * Decode a base64 string. Strict by default: the text must be the canonical
 * encoding of some byte string — alphabet characters only, no whitespace,
 * padding either absent or exactly right, no set bits past the final byte.
 * `{ padding: false }` refuses `=` and `{ padding: true }` requires it.
 * `{ loose: true }` drops whatever it cannot use instead of throwing.
 *
 * @param input - base64 text, or its ASCII bytes
 * @param options - see {@link Base64ParseOptions}
 * @returns decoded bytes, or a UTF-8 `string` when `returnAs` is `"string"`
 * @throws {UnsecureError} `MALFORMED` on anything but a canonical encoding, unless `loose`
 * @throws {UnsecureError} `INVALID_TYPE` if `input` is nullish
 * @example
 * base64Parse(token, { alphabet: "base64url", returnAs: "bytes" });
 */
export function base64Parse<T extends DecodeReturnAs>(
  input: string | Uint8Array,
  options: Base64ParseOptions & { returnAs: T },
): T extends "string" ? string : Uint8Array<ArrayBuffer>;
export function base64Parse(input: string, options?: Base64ParseOptions): string;
export function base64Parse(
  input: Uint8Array,
  options?: Base64ParseOptions,
): Uint8Array<ArrayBuffer>;
/* @__NO_SIDE_EFFECTS__ */
export function base64Parse(
  input: string | Uint8Array,
  options?: Base64ParseOptions,
): string | Uint8Array {
  assertData(input, "Base64.parse");
  const { text, wantString } = parsePrep(input, options);
  if (!text) return wantString ? "" : new Uint8Array(0);
  const loose = options?.loose ?? false;
  const bytes = base64ParseText(text, "Base64.parse", options);
  return parseFinalize(bytes, wantString, !loose, "Base64.parse");
}

/**
 * Base64 codec: `Base64.stringify(bytes)` / `Base64.parse(text)`. Strict decode
 * by default. Pass `{ alphabet: "base64url" }` for URL-safe (unpadded by default).
 */
export const Base64: Base64Codec = {
  stringify: base64Stringify,
  parse: base64Parse,
};
