import { _Buffer, _hasBuffer, _toBuffer } from "./_buffer.ts";
import {
  type _BlockShape,
  type BytesSource,
  type DecodeOptions,
  type DecodeReturnAs,
  _assertData,
  _decodeSymbols,
  _looseCount,
  _parseFinalize,
  _parsePrep,
  _strictBody,
  _symbols,
  toBytes,
} from "./_codec.ts";

interface _ToBase64 {
  toBase64(options?: { alphabet?: string; omitPadding?: boolean }): string;
}
interface _FromBase64 {
  fromBase64(
    input: string,
    options?: { alphabet?: string; lastChunkHandling?: string },
  ): Uint8Array<ArrayBuffer>;
}

const _nativeToBase64: boolean = /* @__PURE__ */ (() =>
  typeof (Uint8Array.prototype as Partial<_ToBase64>).toBase64 === "function")();
const _nativeFromBase64: boolean = /* @__PURE__ */ (() =>
  typeof (Uint8Array as Partial<_FromBase64>).fromBase64 === "function")();

/** Standard (`+/`) or URL-safe (`-_`) alphabet. */
export type Base64Alphabet = "base64" | "base64url";

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

export interface Base64ParseOptions extends DecodeOptions {
  /**
   * Alphabet to enforce in strict mode. `loose` accepts either alphabet and
   * ignores this.
   * @default "base64"
   */
  alphabet?: Base64Alphabet;
}

const _B64_SHAPE: _BlockShape = { bits: 6, group: 4, name: "base64" };

const _B64_DIGITS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

/** charCode → 6-bit value, `-1` for anything the alphabet does not carry. */
/* @__NO_SIDE_EFFECTS__ */
function _b64Table(pairs: string): Int16Array {
  const t = new Int16Array(128).fill(-1);
  for (let i = 0; i < 62; i++) t[_B64_DIGITS.charCodeAt(i)] = i;
  for (let i = 0; i < pairs.length; i += 2) {
    t[pairs.charCodeAt(i)] = 62;
    t[pairs.charCodeAt(i + 1)] = 63;
  }
  return t;
}

const _B64_TABLE_STD: Int16Array = /* @__PURE__ */ _b64Table("+/");
const _B64_TABLE_URL: Int16Array = /* @__PURE__ */ _b64Table("-_");

/* @__NO_SIDE_EFFECTS__ */
function _unpad(s: string): string {
  let end = s.length;
  while (end > 0 && s.charCodeAt(end - 1) === 61) end--;
  return end === s.length ? s : s.slice(0, end);
}

/* @__NO_SIDE_EFFECTS__ */
function _padTo4(s: string): string {
  const rem = s.length % 4;
  return rem === 0 ? s : s + "=".repeat(4 - rem);
}

/* @__NO_SIDE_EFFECTS__ */
function _encodeBase64(bytes: Uint8Array, alphabet: Base64Alphabet, padding: boolean): string {
  const url = alphabet === "base64url";
  if (_hasBuffer) {
    // Node emits padded "base64" and unpadded "base64url".
    const s = _toBuffer(bytes).toString(url ? "base64url" : "base64");
    if (url) return padding ? _padTo4(s) : s;
    return padding ? s : _unpad(s);
  }
  if (_nativeToBase64) {
    return (bytes as unknown as _ToBase64).toBase64({ alphabet, omitPadding: !padding });
  }
  let binary = "";
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]!);
  }
  let s = btoa(binary);
  if (url) s = s.replace(/\+/g, "-").replace(/\//g, "_");
  return padding ? s : _unpad(s);
}

/**
 * Bulk-decode canonical, fully padded, standard-alphabet base64. Every backend
 * agrees on that input, which is why the contract is settled in JS before any
 * of them runs: native `fromBase64`'s own strict mode enforces a *different*
 * contract (padding mandatory, whitespace fatal), so it is never asked to
 * validate — only to decode.
 */
/* @__NO_SIDE_EFFECTS__ */
function _decodeCanonical(padded: string, symbols: number): Uint8Array<ArrayBuffer> {
  if (_hasBuffer) return new Uint8Array(_Buffer!.from(padded, "base64"));
  if (_nativeFromBase64) return (Uint8Array as unknown as _FromBase64).fromBase64(padded);
  return _decodeSymbols(_symbols(padded, _B64_TABLE_STD), symbols, 6);
}

/* @__NO_SIDE_EFFECTS__ */
function _decodeBase64(
  text: string,
  alphabet: Base64Alphabet,
  loose: boolean,
  label: string,
): Uint8Array<ArrayBuffer> {
  const url = alphabet === "base64url";
  let body: string;
  if (loose) {
    // Either alphabet is accepted; `-_` fold onto `+/` before the junk goes.
    const clean = text
      .replace(/-/g, "+")
      .replace(/_/g, "/")
      .replace(/[^A-Za-z0-9+/]/g, "");
    body = clean.slice(0, _looseCount(clean.length, _B64_SHAPE));
  } else {
    const strict = _strictBody(text, url ? _B64_TABLE_URL : _B64_TABLE_STD, _B64_SHAPE, label);
    body = url ? strict.replace(/-/g, "+").replace(/_/g, "/") : strict;
  }
  const rem = body.length % 4;
  return _decodeCanonical(rem === 0 ? body : body + (rem === 2 ? "==" : "="), body.length);
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
 * @throws {TypeError} if `data` is not a string, `ArrayBuffer` or view over one
 * @example
 * base64Stringify(bytes, { alphabet: "base64url" });
 */
/* @__NO_SIDE_EFFECTS__ */
export function base64Stringify(
  data: string | BytesSource,
  options?: Base64StringifyOptions,
): string {
  const alphabet = options?.alphabet ?? "base64";
  const padding = options?.padding ?? alphabet !== "base64url";
  return _encodeBase64(toBytes(data, "Base64.stringify"), alphabet, padding);
}

/**
 * Decode a base64 string. Strict by default: the text must be the canonical
 * encoding of some byte string — alphabet characters only, no whitespace,
 * padding either absent or exactly right, no set bits past the final byte.
 * `{ loose: true }` drops whatever it cannot use instead of throwing.
 *
 * @param input - base64 text, or its ASCII bytes
 * @param options - see {@link Base64ParseOptions}
 * @returns decoded bytes, or a UTF-8 `string` when `returnAs` is `"string"`
 * @throws {SyntaxError} on anything but a canonical encoding, unless `loose`
 * @throws {TypeError} if `input` is nullish
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
  _assertData(input, "Base64.parse");
  const { text, wantString } = _parsePrep(input, options);
  if (!text) return wantString ? "" : new Uint8Array(0);
  const alphabet = options?.alphabet ?? "base64";
  const loose = options?.loose ?? false;
  const bytes = _decodeBase64(text, alphabet, loose, "Base64.parse");
  return _parseFinalize(bytes, wantString, !loose, "Base64.parse");
}

/**
 * Base64 codec: `Base64.stringify(bytes)` / `Base64.parse(text)`. Strict decode
 * by default. Pass `{ alphabet: "base64url" }` for URL-safe (unpadded by default).
 */
export const Base64: Base64Codec = /* @__PURE__ */ {
  stringify: base64Stringify,
  parse: base64Parse,
};
