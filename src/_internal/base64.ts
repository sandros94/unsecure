import { NO_OPTIONS } from "./options.ts";
import { nodeBuffer, preferBuffer, toBuffer } from "./buffer.ts";
import {
  type BlockShape,
  decodeSymbols,
  honoursViews,
  looseCount,
  strictBody,
  symbols,
  wholeBuffer,
} from "./codec.ts";

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
/** Whether `toBase64` honours a view; a runtime without it never reaches it. */
const _base64Views: boolean = /* @__PURE__ */ (() =>
  !_nativeToBase64 || honoursViews((view) => (view as unknown as _ToBase64).toBase64(), "AQI="))();

/** Standard (`+/`) or URL-safe (`-_`) alphabet. */
export type Base64Alphabet = "base64" | "base64url";

const _SHAPE: BlockShape = { bits: 6, group: 4, name: "base64" };

const _DIGITS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

/** charCode → 6-bit value, `-1` for anything the alphabet does not carry. */
/* @__NO_SIDE_EFFECTS__ */
function _table(pairs: string): Int16Array {
  const t = new Int16Array(128).fill(-1);
  for (let i = 0; i < 62; i++) t[_DIGITS.charCodeAt(i)] = i;
  for (let i = 0; i < pairs.length; i += 2) {
    t[pairs.charCodeAt(i)] = 62;
    t[pairs.charCodeAt(i + 1)] = 63;
  }
  return t;
}

const _TABLE_STD: Int16Array = /* @__PURE__ */ _table("+/");
const _TABLE_URL: Int16Array = /* @__PURE__ */ _table("-_");

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

/** Base64 text of `bytes`; `padding` defaults to on for `base64`, off for `base64url`. */
/* @__NO_SIDE_EFFECTS__ */
export function base64StringifyBytes(
  bytes: Uint8Array,
  options: { alphabet?: Base64Alphabet; padding?: boolean } = NO_OPTIONS,
): string {
  const alphabet = options.alphabet ?? "base64";
  const padding = options.padding ?? alphabet !== "base64url";
  const url = alphabet === "base64url";
  if (preferBuffer(bytes.length, _nativeToBase64)) {
    // Node emits padded "base64" and unpadded "base64url".
    const s = toBuffer(bytes).toString(url ? "base64url" : "base64");
    if (url) return padding ? _padTo4(s) : s;
    return padding ? s : _unpad(s);
  }
  if (_nativeToBase64) {
    return (wholeBuffer(bytes, _base64Views) as unknown as _ToBase64).toBase64({
      alphabet,
      omitPadding: !padding,
    });
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
 * Bytes of base64 `text`. Strict unless `loose`: the canonical encoding of
 * some byte string in the named alphabet, padding pinned by `padding` or
 * accepted either way. `loose` takes either alphabet and drops what it cannot use.
 */
/* @__NO_SIDE_EFFECTS__ */
export function base64ParseText(
  text: string,
  source: string,
  options: { alphabet?: Base64Alphabet; loose?: boolean; padding?: boolean } = NO_OPTIONS,
): Uint8Array<ArrayBuffer> {
  const url = (options.alphabet ?? "base64") === "base64url";
  let body: string;
  if (options.loose) {
    // Either alphabet is accepted; `-_` fold onto `+/` before the junk goes.
    const clean = text
      .replace(/-/g, "+")
      .replace(/_/g, "/")
      .replace(/[^A-Za-z0-9+/]/g, "");
    body = clean.slice(0, looseCount(clean.length, _SHAPE));
  } else {
    const strict = strictBody(text, url ? _TABLE_URL : _TABLE_STD, _SHAPE, source, options.padding);
    body = url ? strict.replace(/-/g, "+").replace(/_/g, "/") : strict;
  }
  const rem = body.length % 4;
  return _bulk(rem === 0 ? body : body + (rem === 2 ? "==" : "="), body.length);
}

/**
 * Bulk-decode canonical, fully padded, standard-alphabet base64. Every backend
 * agrees on that input, which is why the contract is settled in JS before any
 * of them runs: native `fromBase64`'s own strict mode enforces a *different*
 * contract (padding mandatory, whitespace fatal), so it is never asked to
 * validate — only to decode.
 */
/* @__NO_SIDE_EFFECTS__ */
function _bulk(padded: string, count: number): Uint8Array<ArrayBuffer> {
  if (preferBuffer((count * 6) >>> 3, _nativeFromBase64)) {
    return new Uint8Array(nodeBuffer!.from(padded, "base64"));
  }
  if (_nativeFromBase64) return (Uint8Array as unknown as _FromBase64).fromBase64(padded);
  return decodeSymbols(symbols(padded, _TABLE_STD), count, 6);
}
