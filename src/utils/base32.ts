import {
  type Base32Alphabet,
  base32Chars,
  base32ParseText,
  base32StringifyBytes,
} from "../_internal/base32.ts";
import { type BytesSource, toBytes } from "../_internal/bytes.ts";
import {
  type DecodeReturnAs,
  type PaddedDecodeOptions,
  assertData,
  parseFinalize,
  parsePrep,
} from "../_internal/codec.ts";
import { ownOptions } from "../_internal/options.ts";

export type { Base32Alphabet };

export interface Base32StringifyOptions {
  /**
   * `"base32"` (RFC 4648), `"base32hex"`, `"crockford"`, or a custom 32-char string.
   * @default "base32"
   */
  alphabet?: Base32Alphabet;
  /**
   * Emit `=` padding. `crockford` defaults to unpadded.
   * @default true
   */
  padding?: boolean;
}

export interface Base32ParseOptions extends PaddedDecodeOptions {
  /**
   * `"base32"`, `"base32hex"`, `"crockford"`, or a custom 32-char string.
   * @default "base32"
   */
  alphabet?: Base32Alphabet;
}

export interface Base32Codec {
  /** See {@link base32Stringify}. */
  stringify: typeof base32Stringify;
  /** See {@link base32Parse}. */
  parse: typeof base32Parse;
}

/**
 * Encode bytes to base32.
 *
 * @param data - raw bytes (any `BytesSource`), or a `string` (UTF-8 encoded first)
 * @param options - see {@link Base32StringifyOptions}
 * @returns the base32 string
 * @throws {UnsecureError} `INVALID_TYPE` if `data` is not a string, `ArrayBuffer` or view over one
 * @throws {UnsecureError} `OUT_OF_RANGE` if `alphabet` is not a usable 32-character alphabet
 * @example
 * base32Stringify(secret, { padding: false }); // unpadded (e.g. OTP secrets)
 */
/* @__NO_SIDE_EFFECTS__ */
export function base32Stringify(
  data: string | BytesSource,
  options?: Base32StringifyOptions,
): string {
  return base32StringifyBytes(
    toBytes(data, "Base32.stringify"),
    "Base32.stringify",
    ownOptions(options),
  );
}

/**
 * Decode a base32 string. Strict by default: the text must be the canonical
 * encoding of some byte string — alphabet characters only (uppercase for the
 * RFC variants), no whitespace, padding either absent or exactly right, no set
 * bits past the final byte. `{ padding: false }` refuses `=` and
 * `{ padding: true }` requires it. `{ loose: true }` drops whatever it cannot
 * use, folding case for the named variants, instead of throwing.
 *
 * @param input - base32 text, or its ASCII bytes
 * @param options - see {@link Base32ParseOptions}
 * @returns decoded bytes, or a UTF-8 `string` when `returnAs` is `"string"`
 * @throws {UnsecureError} `OUT_OF_RANGE` on an unusable `alphabet`
 * @throws {UnsecureError} `MALFORMED` on anything but a canonical encoding, unless `loose`
 * @throws {UnsecureError} `INVALID_TYPE` if `input` is nullish
 * @example
 * base32Parse(secret, { loose: true, returnAs: "bytes" });
 */
export function base32Parse<T extends DecodeReturnAs>(
  input: string | Uint8Array,
  options: Base32ParseOptions & { returnAs: T },
): T extends "string" ? string : Uint8Array<ArrayBuffer>;
export function base32Parse(input: string, options?: Base32ParseOptions): string;
export function base32Parse(
  input: Uint8Array,
  options?: Base32ParseOptions,
): Uint8Array<ArrayBuffer>;
/* @__NO_SIDE_EFFECTS__ */
export function base32Parse(
  input: string | Uint8Array,
  input_?: Base32ParseOptions,
): string | Uint8Array {
  assertData(input, "Base32.parse");
  const options = ownOptions(input_);
  // Refused before the empty-input return, so an unusable alphabet never passes silently.
  base32Chars(options.alphabet ?? "base32", "Base32.parse");
  const loose = options.loose ?? false;
  const { text, wantString } = parsePrep(input, options, "Base32.parse");
  if (!text) return wantString ? "" : new Uint8Array(0);
  const bytes = base32ParseText(text, "Base32.parse", options);
  return parseFinalize(bytes, wantString, !loose, "Base32.parse");
}

/**
 * Base32 codec: `Base32.stringify(bytes)` / `Base32.parse(text)`. Strict by default.
 * `alphabet` accepts `"base32"` | `"base32hex"` | `"crockford"` | a custom 32-char string.
 */
export const Base32: Base32Codec = {
  stringify: base32Stringify,
  parse: base32Parse,
};
