import { _Buffer, _hasBuffer, _toBuffer } from "./_buffer.ts";
import {
  type DecodeOptions,
  type DecodeReturnAs,
  _assertData,
  _malformed,
  _parseFinalize,
  _parsePrep,
  _toBytes,
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

const _nativeToBase64 = typeof (Uint8Array.prototype as Partial<_ToBase64>).toBase64 === "function";
const _nativeFromBase64 = typeof (Uint8Array as Partial<_FromBase64>).fromBase64 === "function";

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
   * Alphabet to enforce in strict mode.
   * @default "base64"
   */
  alphabet?: Base64Alphabet;
}

const _B64_STD_RE = /^[A-Za-z0-9+/]*={0,2}$/;
const _B64_URL_RE = /^[A-Za-z0-9\-_]*={0,2}$/;

// charCode → 6-bit value; accepts both alphabets (single table serves `+/` and `-_`).
const _B64_TABLE: Int16Array = /* @__PURE__ */ (() => {
  const t = new Int16Array(128).fill(-1);
  const std = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  for (let i = 0; i < 64; i++) t[std.charCodeAt(i)] = i;
  t[45] = 62;
  t[95] = 63;
  return t;
})();

function _unpad(s: string): string {
  let end = s.length;
  while (end > 0 && s.charCodeAt(end - 1) === 61) end--;
  return end === s.length ? s : s.slice(0, end);
}

function _padTo4(s: string): string {
  const rem = s.length % 4;
  return rem === 0 ? s : s + "=".repeat(4 - rem);
}

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

function _base64Manual(text: string, loose: boolean, label: string): Uint8Array<ArrayBuffer> {
  const out = new Uint8Array(Math.ceil((text.length * 3) / 4));
  let bits = 0;
  let value = 0;
  let index = 0;
  for (let i = 0; i < text.length; i++) {
    const c = text.charCodeAt(i);
    if (c === 61) continue;
    const v = c < 128 ? _B64_TABLE[c]! : -1;
    if (v === -1) {
      if (loose) continue;
      throw _malformed(label, "invalid base64 input.");
    }
    value = (value << 6) | v;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out[index++] = (value >>> bits) & 0xff;
    }
  }
  return out.subarray(0, index);
}

function _decodeBase64(
  text: string,
  alphabet: Base64Alphabet,
  loose: boolean,
  label: string,
): Uint8Array<ArrayBuffer> {
  if (loose) {
    if (_hasBuffer) {
      return new Uint8Array(_Buffer!.from(text.replace(/-/g, "+").replace(/_/g, "/"), "base64"));
    }
    if (_nativeFromBase64) {
      return (Uint8Array as unknown as _FromBase64).fromBase64(
        _padTo4(text.replace(/-/g, "+").replace(/_/g, "/")),
        { lastChunkHandling: "loose" },
      );
    }
    return _base64Manual(text, true, label);
  }
  if (_nativeFromBase64) {
    return (Uint8Array as unknown as _FromBase64).fromBase64(text, {
      alphabet,
      lastChunkHandling: "strict",
    });
  }
  // Fallback strict. Strip ASCII whitespace to match native fromBase64, which
  // ignores it. Then validate the alphabet with a regex (Buffer decodes `-_`
  // and `+/` interchangeably, so it can't enforce the alphabet itself).
  const clean = text.replace(/[\t\n\f\r ]+/g, "");
  const re = alphabet === "base64url" ? _B64_URL_RE : _B64_STD_RE;
  if (!re.test(clean)) throw _malformed(label, "invalid base64 input.");
  let padLen = 0;
  for (let i = clean.length - 1; i >= 0 && clean.charCodeAt(i) === 61; i--) padLen++;
  if ((clean.length - padLen) % 4 === 1) throw _malformed(label, "invalid base64 input.");
  if (_hasBuffer) {
    const std = alphabet === "base64url" ? clean.replace(/-/g, "+").replace(/_/g, "/") : clean;
    return new Uint8Array(_Buffer!.from(std, "base64"));
  }
  return _base64Manual(clean, false, label);
}

export interface Base64Codec {
  /**
   * Encode bytes to base64.
   *
   * @param data - raw bytes, or a `string` (UTF-8 encoded first)
   * @param options - see {@link Base64StringifyOptions}
   * @returns the base64 string
   * @throws {TypeError} if `data` is nullish
   * @example
   * Base64.stringify(bytes, { alphabet: "base64url" });
   */
  stringify(data: Uint8Array | string, options?: Base64StringifyOptions): string;
  /**
   * Decode a base64 string. Strict by default; ASCII whitespace is ignored
   * (matching native `fromBase64`).
   *
   * @param input - base64 text, or its ASCII bytes
   * @param options - see {@link Base64ParseOptions}
   * @returns decoded bytes, or a UTF-8 `string` when `returnAs` is `"string"`
   * @throws {SyntaxError} on characters outside the `alphabet`, unless `loose`
   * @throws {TypeError} if `input` is nullish
   * @example
   * Base64.parse(token, { alphabet: "base64url", returnAs: "bytes" });
   */
  parse<T extends DecodeReturnAs>(
    input: string | Uint8Array,
    options: Base64ParseOptions & { returnAs: T },
  ): T extends "string" ? string : Uint8Array<ArrayBuffer>;
  /** Decode a base64 `string` to a UTF-8 string (strict; see {@link Base64ParseOptions}). */
  parse(input: string, options?: Base64ParseOptions): string;
  /** Decode base64-as-bytes to bytes (strict; see {@link Base64ParseOptions}). */
  parse(input: Uint8Array, options?: Base64ParseOptions): Uint8Array<ArrayBuffer>;
}

function base64Stringify(data: Uint8Array | string, options?: Base64StringifyOptions): string {
  _assertData(data, "Base64.stringify");
  const alphabet = options?.alphabet ?? "base64";
  const padding = options?.padding ?? alphabet !== "base64url";
  return _encodeBase64(_toBytes(data), alphabet, padding);
}

function base64Parse<T extends DecodeReturnAs>(
  input: string | Uint8Array,
  options: Base64ParseOptions & { returnAs: T },
): T extends "string" ? string : Uint8Array<ArrayBuffer>;
function base64Parse(input: string, options?: Base64ParseOptions): string;
function base64Parse(input: Uint8Array, options?: Base64ParseOptions): Uint8Array<ArrayBuffer>;
function base64Parse(
  input: string | Uint8Array,
  options?: Base64ParseOptions,
): string | Uint8Array {
  _assertData(input, "Base64.parse");
  const { text, wantString } = _parsePrep(input, options);
  if (!text) return wantString ? "" : new Uint8Array(0);
  const alphabet = options?.alphabet ?? "base64";
  const bytes = _decodeBase64(text, alphabet, options?.loose ?? false, "Base64.parse");
  return _parseFinalize(bytes, wantString);
}

/**
 * Base64 codec: `Base64.stringify(bytes)` / `Base64.parse(text)`. Strict decode
 * by default. Pass `{ alphabet: "base64url" }` for URL-safe (unpadded by default).
 */
export const Base64: Base64Codec = { stringify: base64Stringify, parse: base64Parse };

/** @deprecated Use `Base64.stringify`. */
export function base64Encode(data: Uint8Array | string): string {
  return base64Stringify(data);
}

/** @deprecated Use `Base64.stringify(data, { alphabet: "base64url" })`. */
export function base64UrlEncode(data: Uint8Array | string): string {
  return base64Stringify(data, { alphabet: "base64url", padding: false });
}

/** @deprecated Use `Base64.parse` (note: `Base64.parse` is strict by default). */
export function base64Decode<T extends DecodeReturnAs>(
  data: string | Uint8Array,
  options: { returnAs: T },
): T extends "string" ? string : Uint8Array<ArrayBuffer>;
export function base64Decode(data: string): string;
export function base64Decode(data: Uint8Array): Uint8Array<ArrayBuffer>;
export function base64Decode(
  data: string | Uint8Array,
  options?: { returnAs?: DecodeReturnAs },
): Uint8Array<ArrayBuffer> | string {
  return base64Parse(data as string, { returnAs: options?.returnAs, loose: true });
}

/** @deprecated Use `Base64.parse(data, { alphabet: "base64url" })` (strict by default). */
export function base64UrlDecode<T extends DecodeReturnAs>(
  data: string | Uint8Array,
  options: { returnAs: T },
): T extends "string" ? string : Uint8Array<ArrayBuffer>;
export function base64UrlDecode(data: string): string;
export function base64UrlDecode(data: Uint8Array): Uint8Array<ArrayBuffer>;
export function base64UrlDecode(
  data: string | Uint8Array,
  options?: { returnAs?: DecodeReturnAs },
): Uint8Array<ArrayBuffer> | string {
  return base64Parse(data as string, {
    alphabet: "base64url",
    returnAs: options?.returnAs,
    loose: true,
  });
}
