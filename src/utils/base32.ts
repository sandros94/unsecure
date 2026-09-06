import {
  type _BlockShape,
  type BytesSource,
  type DecodeOptions,
  type DecodeReturnAs,
  _assertData,
  _badOption,
  _decodeSymbols,
  _looseCount,
  _parseFinalize,
  _parsePrep,
  _strictBody,
  _symbols,
  toBytes,
} from "./_codec.ts";

const _B32_SHAPE: _BlockShape = { bits: 5, group: 8, name: "base32" };

// A Map, not an object: the key comes from the caller, and `"constructor"`
// must be an unknown alphabet rather than something off a prototype.
const _NAMED_ALPHABETS: ReadonlyMap<string, string> = /* @__PURE__ */ new Map([
  ["base32", "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"], // RFC 4648 §6
  ["base32hex", "0123456789ABCDEFGHIJKLMNOPQRSTUV"], // RFC 4648 §7
  ["crockford", "0123456789ABCDEFGHJKMNPQRSTVWXYZ"], // excludes I, L, O, U
]);

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

/**
 * Resolve a named variant, or check that a custom alphabet can actually name
 * 32 distinct symbols: ASCII only (the decode table is indexed by code unit),
 * no `=` (it would be indistinguishable from padding) and no whitespace (which
 * every codec here drops or rejects rather than decodes).
 */
/* @__NO_SIDE_EFFECTS__ */
function _resolveChars(alphabet: Base32Alphabet, label: string): string {
  const named = _NAMED_ALPHABETS.get(alphabet);
  if (named !== undefined) return named;
  if (alphabet.length !== 32) {
    throw _badOption(label, `alphabet must be exactly 32 characters (got ${alphabet.length}).`);
  }
  const seen = new Set<string>();
  for (let i = 0; i < 32; i++) {
    const char = alphabet[i]!;
    const code = alphabet.charCodeAt(i);
    if (code > 127) {
      throw _badOption(label, `alphabet character ${JSON.stringify(char)} is not ASCII.`);
    }
    if (code === 61) throw _badOption(label, `alphabet must not contain the padding "=".`);
    if (code === 32 || (code >= 9 && code <= 13)) {
      throw _badOption(label, `alphabet must not contain whitespace (at index ${i}).`);
    }
    if (seen.has(char)) throw _badOption(label, `alphabet repeats ${JSON.stringify(char)}.`);
    seen.add(char);
  }
  return alphabet;
}

// charCode → 5-bit value; `-1` marks invalid. Cached for the named variants
// only — a custom alphabet builds its table per call rather than growing an
// unbounded cache keyed by caller input.
const _tables: Map<string, Int16Array> = /* @__PURE__ */ new Map<string, Int16Array>();

/* @__NO_SIDE_EFFECTS__ */
function _buildTable(alphabet: Base32Alphabet, chars: string, loose: boolean): Int16Array {
  const table = new Int16Array(128).fill(-1);
  // Crockford's own spec decodes case-insensitively; the RFC alphabets are
  // uppercase and fold only under `loose`. A custom alphabet is taken
  // literally either way — its case may carry meaning.
  const fold = alphabet === "crockford" || (loose && _NAMED_ALPHABETS.has(alphabet));
  for (let i = 0; i < 32; i++) {
    table[chars.charCodeAt(i)] = i;
    if (fold) {
      table[chars[i]!.toLowerCase().charCodeAt(0)] = i;
      table[chars[i]!.toUpperCase().charCodeAt(0)] = i;
    }
  }
  if (alphabet === "crockford") {
    // Crockford decode aliases: O→0, I/L→1 (case-insensitive).
    table[79] = table[111] = 0;
    table[73] = table[105] = table[76] = table[108] = 1;
  }
  return table;
}

/* @__NO_SIDE_EFFECTS__ */
function _decodeTable(alphabet: Base32Alphabet, chars: string, loose: boolean): Int16Array {
  if (!_NAMED_ALPHABETS.has(alphabet)) return _buildTable(alphabet, chars, loose);
  const key = loose ? `${alphabet}/loose` : alphabet;
  let table = _tables.get(key);
  if (!table) {
    table = _buildTable(alphabet, chars, loose);
    _tables.set(key, table);
  }
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
  table: Int16Array,
  loose: boolean,
  label: string,
): Uint8Array<ArrayBuffer> {
  if (loose) {
    const values = _symbols(text, table);
    return _decodeSymbols(values, _looseCount(values.length, _B32_SHAPE), 5);
  }
  const body = _strictBody(text, table, _B32_SHAPE, label);
  return _decodeSymbols(_symbols(body, table), body.length, 5);
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
  const alphabet = options?.alphabet ?? "base32";
  const chars = _resolveChars(alphabet, "Base32.stringify");
  const padding = options?.padding ?? alphabet !== "crockford";
  return _encodeBase32(toBytes(data, "Base32.stringify"), chars, padding);
}

/**
 * Decode a base32 string. Strict by default: the text must be the canonical
 * encoding of some byte string — alphabet characters only (uppercase for the
 * RFC variants), no whitespace, padding either absent or exactly right, no set
 * bits past the final byte. `{ loose: true }` drops whatever it cannot use,
 * folding case for the named variants, instead of throwing.
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
  options?: Base32ParseOptions,
): string | Uint8Array {
  _assertData(input, "Base32.parse");
  const alphabet = options?.alphabet ?? "base32";
  const chars = _resolveChars(alphabet, "Base32.parse");
  const loose = options?.loose ?? false;
  const { text, wantString } = _parsePrep(input, options);
  if (!text) return wantString ? "" : new Uint8Array(0);
  const table = _decodeTable(alphabet, chars, loose);
  const bytes = _decodeBase32(text, table, loose, "Base32.parse");
  return _parseFinalize(bytes, wantString, !loose, "Base32.parse");
}

/**
 * Base32 codec: `Base32.stringify(bytes)` / `Base32.parse(text)`. Strict by default.
 * `alphabet` accepts `"base32"` | `"base32hex"` | `"crockford"` | a custom 32-char string.
 */
export const Base32: Base32Codec = /* @__PURE__ */ {
  stringify: base32Stringify,
  parse: base32Parse,
};
