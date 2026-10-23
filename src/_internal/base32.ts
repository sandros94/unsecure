import {
  type BlockShape,
  badOption,
  decodeSymbols,
  looseCount,
  strictBody,
  symbols,
} from "./codec.ts";

const _SHAPE: BlockShape = { bits: 5, group: 8, name: "base32" };

// A Map, not an object: the key comes from the caller, and `"constructor"`
// must be an unknown alphabet rather than something off a prototype.
const _NAMED: ReadonlyMap<string, string> = /* @__PURE__ */ new Map([
  ["base32", "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"],
  ["base32hex", "0123456789ABCDEFGHIJKLMNOPQRSTUV"],
  ["crockford", "0123456789ABCDEFGHJKMNPQRSTVWXYZ"],
]);

/** A named variant, or a custom 32-character alphabet string. */
// oxlint-disable-next-line typescript/no-redundant-type-constituents
export type Base32Alphabet = "base32" | "base32hex" | "crockford" | (string & {});

/**
 * Resolve a named variant, or check that a custom alphabet can actually name
 * 32 distinct symbols: ASCII only (the decode table is indexed by code unit),
 * no `=` (it would be indistinguishable from padding) and no whitespace (which
 * every codec here drops or rejects rather than decodes).
 */
/* @__NO_SIDE_EFFECTS__ */
export function base32Chars(alphabet: Base32Alphabet, source: string): string {
  const named = _NAMED.get(alphabet);
  if (named !== undefined) return named;
  if (alphabet.length !== 32) {
    throw badOption(`alphabet must be exactly 32 characters (got ${alphabet.length}).`, source);
  }
  const seen = new Set<string>();
  for (let i = 0; i < 32; i++) {
    const char = alphabet[i]!;
    const code = alphabet.charCodeAt(i);
    if (code > 127) {
      throw badOption(`alphabet character ${JSON.stringify(char)} is not ASCII.`, source);
    }
    if (code === 61) throw badOption(`alphabet must not contain the padding "=".`, source);
    if (code === 32 || (code >= 9 && code <= 13)) {
      throw badOption(`alphabet must not contain whitespace (at index ${i}).`, source);
    }
    if (seen.has(char)) throw badOption(`alphabet repeats ${JSON.stringify(char)}.`, source);
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
  const fold = alphabet === "crockford" || (loose && _NAMED.has(alphabet));
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
  if (!_NAMED.has(alphabet)) return _buildTable(alphabet, chars, loose);
  const key = loose ? `${alphabet}/loose` : alphabet;
  let table = _tables.get(key);
  if (!table) {
    table = _buildTable(alphabet, chars, loose);
    _tables.set(key, table);
  }
  return table;
}

/** Base32 text of `bytes`; `padding` defaults to on except for `crockford`. */
/* @__NO_SIDE_EFFECTS__ */
export function base32StringifyBytes(
  bytes: Uint8Array,
  source: string,
  options: { alphabet?: Base32Alphabet; padding?: boolean } = {},
): string {
  const alphabet = options.alphabet ?? "base32";
  const chars = base32Chars(alphabet, source);
  const padding = options.padding ?? alphabet !== "crockford";
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

/**
 * Bytes of base32 `text`. Strict unless `loose`: the canonical encoding of
 * some byte string in the named alphabet, padding pinned by `padding` or
 * accepted either way. `loose` folds case for the named variants and drops
 * what it cannot use.
 */
/* @__NO_SIDE_EFFECTS__ */
export function base32ParseText(
  text: string,
  source: string,
  options: { alphabet?: Base32Alphabet; loose?: boolean; padding?: boolean } = {},
): Uint8Array<ArrayBuffer> {
  const alphabet = options.alphabet ?? "base32";
  const loose = options.loose ?? false;
  const table = _decodeTable(alphabet, base32Chars(alphabet, source), loose);
  if (loose) {
    const values = symbols(text, table);
    return decodeSymbols(values, looseCount(values.length, _SHAPE), 5);
  }
  const body = strictBody(text, table, _SHAPE, source, options.padding);
  return decodeSymbols(symbols(body, table), body.length, 5);
}
