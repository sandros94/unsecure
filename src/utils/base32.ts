import {
  type BytesSource,
  type DecodeOptions,
  type DecodeReturnAs,
  _assertData,
  _malformed,
  _parseFinalize,
  _parsePrep,
  toBytes,
} from "./_codec.ts";

const _NAMED_ALPHABETS = {
  base32: "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567", // RFC 4648 §6
  base32hex: "0123456789ABCDEFGHIJKLMNOPQRSTUV", // RFC 4648 §7
  crockford: "0123456789ABCDEFGHJKMNPQRSTVWXYZ", // excludes I, L, O, U
} as const;

/** A named variant, or a custom 32-character alphabet string. */
// oxlint-disable-next-line typescript/no-redundant-type-constituents
export type Base32Alphabet = "base32" | "base32hex" | "crockford" | (string & {});

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

export interface Base32ParseOptions extends DecodeOptions {
  /**
   * `"base32"`, `"base32hex"`, `"crockford"`, or a custom 32-char string.
   * @default "base32"
   */
  alphabet?: Base32Alphabet;
}

/* @__NO_SIDE_EFFECTS__ */
function _resolveChars(alphabet: Base32Alphabet, label: string): string {
  const chars = _NAMED_ALPHABETS[alphabet as keyof typeof _NAMED_ALPHABETS] ?? alphabet;
  if (chars.length !== 32) {
    throw _malformed(label, `alphabet must be exactly 32 characters (got ${chars.length}).`);
  }
  return chars;
}

const _isNamed = (a: Base32Alphabet): boolean =>
  a === "base32" || a === "base32hex" || a === "crockford";

// charCode → 5-bit value; `-1` marks invalid. Cached per alphabet.
const _tables: Map<string, Int8Array> = /* @__PURE__ */ new Map<string, Int8Array>();

/* @__NO_SIDE_EFFECTS__ */
function _decodeTable(alphabet: Base32Alphabet, chars: string): Int8Array {
  let table = _tables.get(alphabet);
  if (table) return table;

  table = new Int8Array(128).fill(-1);
  const named = _isNamed(alphabet);
  for (let i = 0; i < 32; i++) {
    const c = chars.charCodeAt(i);
    if (c < 128) table[c] = i;
    if (named) {
      table[chars[i]!.toLowerCase().charCodeAt(0)] = i;
      table[chars[i]!.toUpperCase().charCodeAt(0)] = i;
    }
  }
  if (alphabet === "crockford") {
    // Crockford decode aliases: O→0, I/L→1 (case-insensitive).
    table[79] = table[111] = 0;
    table[73] = table[105] = table[76] = table[108] = 1;
  }
  _tables.set(alphabet, table);
  return table;
}

/* @__NO_SIDE_EFFECTS__ */
function _encodeBase32(bytes: Uint8Array, chars: string, padding: boolean): string {
  if (bytes.length === 0) return "";
  let result = "";
  let bits = 0;
  let value = 0;
  for (let i = 0; i < bytes.length; i++) {
    value = (value << 8) | bytes[i]!;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      result += chars[(value >>> bits) & 0x1f];
    }
  }
  if (bits > 0) {
    result += chars[(value << (5 - bits)) & 0x1f];
  }
  if (padding) {
    while (result.length % 8) result += "=";
  }
  return result;
}

/* @__NO_SIDE_EFFECTS__ */
function _decodeBase32(
  text: string,
  alphabet: Base32Alphabet,
  chars: string,
  loose: boolean,
  label: string,
): Uint8Array<ArrayBuffer> {
  const table = _decodeTable(alphabet, chars);
  const output = new Uint8Array(Math.floor((text.length * 5) / 8));
  let bits = 0;
  let value = 0;
  let index = 0;

  for (let i = 0; i < text.length; i++) {
    const c = text.charCodeAt(i);
    if (c === 61) continue; // padding
    const v = c < 128 ? table[c]! : -1;
    if (v === -1) {
      if (loose) continue;
      throw _malformed(label, "invalid base32 input.");
    }
    value = (value << 5) | v;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      output[index++] = (value >>> bits) & 0xff;
    }
  }

  return output.subarray(0, index);
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
 * @throws {TypeError} if `data` is not a string, `ArrayBuffer` or view over one
 * @throws {SyntaxError} if `alphabet` is not a usable 32-character alphabet
 * @example
 * base32Stringify(secret, { padding: false }); // unpadded (e.g. OTP secrets)
 */
/* @__NO_SIDE_EFFECTS__ */
export function base32Stringify(
  data: string | BytesSource,
  options?: Base32StringifyOptions,
): string {
  const alphabet = options?.alphabet ?? "base32";
  const chars = _resolveChars(alphabet, "Base32.stringify");
  const padding = options?.padding ?? alphabet !== "crockford";
  return _encodeBase32(toBytes(data, "Base32.stringify"), chars, padding);
}

/**
 * Decode a base32 string. Strict by default.
 *
 * @param input - base32 text, or its ASCII bytes
 * @param options - see {@link Base32ParseOptions}
 * @returns decoded bytes, or a UTF-8 `string` when `returnAs` is `"string"`
 * @throws {SyntaxError} on characters outside the `alphabet` (whitespace included), unless `loose`
 * @throws {TypeError} if `input` is nullish
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
  options?: Base32ParseOptions,
): string | Uint8Array {
  _assertData(input, "Base32.parse");
  const { text, wantString } = _parsePrep(input, options);
  if (!text) return wantString ? "" : new Uint8Array(0);
  const alphabet = options?.alphabet ?? "base32";
  const chars = _resolveChars(alphabet, "Base32.parse");
  const bytes = _decodeBase32(text, alphabet, chars, options?.loose ?? false, "Base32.parse");
  return _parseFinalize(bytes, wantString);
}

/**
 * Base32 codec: `Base32.stringify(bytes)` / `Base32.parse(text)`. Strict by default.
 * `alphabet` accepts `"base32"` | `"base32hex"` | `"crockford"` | a custom 32-char string.
 */
export const Base32: Base32Codec = /* @__PURE__ */ {
  stringify: base32Stringify,
  parse: base32Parse,
};
