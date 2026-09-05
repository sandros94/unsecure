import { _Buffer, _hasBuffer, _toBuffer } from "./_buffer.ts";
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

interface _ToHex {
  toHex(): string;
}
interface _FromHex {
  fromHex(input: string): Uint8Array<ArrayBuffer>;
}

const _nativeToHex: boolean = /* @__PURE__ */ (() =>
  typeof (Uint8Array.prototype as Partial<_ToHex>).toHex === "function")();
const _nativeFromHex: boolean = /* @__PURE__ */ (() =>
  typeof (Uint8Array as Partial<_FromHex>).fromHex === "function")();

/* @__NO_SIDE_EFFECTS__ */
function _encodeHex(bytes: Uint8Array): string {
  if (_hasBuffer) return _toBuffer(bytes).toString("hex");
  if (_nativeToHex) return (bytes as unknown as _ToHex).toHex();
  let out = "";
  for (let i = 0; i < bytes.length; i++) {
    out += bytes[i]!.toString(16).padStart(2, "0");
  }
  return out;
}

/* @__NO_SIDE_EFFECTS__ */
function _hexManual(text: string, strict: boolean, label: string): Uint8Array<ArrayBuffer> {
  const len = text.length >>> 1;
  const bytes = new Uint8Array(len);
  let j = 0;
  for (let i = 0; i < len; i++) {
    const hi = Number.parseInt(text[i * 2]!, 16);
    const lo = Number.parseInt(text[i * 2 + 1]!, 16);
    if (Number.isNaN(hi) || Number.isNaN(lo)) {
      if (strict) throw _malformed(label, "invalid hexadecimal input.");
      break;
    }
    bytes[j++] = (hi << 4) | lo;
  }
  return j === len ? bytes : bytes.slice(0, j);
}

/* @__NO_SIDE_EFFECTS__ */
function _decodeHex(text: string, loose: boolean, label: string): Uint8Array<ArrayBuffer> {
  if (loose) {
    if (_hasBuffer) return new Uint8Array(_Buffer!.from(text, "hex"));
    return _hexManual(text, false, label);
  }
  if (_nativeFromHex) return (Uint8Array as unknown as _FromHex).fromHex(text);
  if (text.length % 2 !== 0) throw _malformed(label, "invalid hexadecimal input.");
  if (_hasBuffer) {
    // Buffer.from(hex) stops at the first invalid char; a short result flags it.
    const buf = _Buffer!.from(text, "hex");
    if (buf.length * 2 !== text.length) throw _malformed(label, "invalid hexadecimal input.");
    return new Uint8Array(buf);
  }
  return _hexManual(text, true, label);
}

export interface HexCodec {
  /** See {@link hexStringify}. */
  stringify: typeof hexStringify;
  /** See {@link hexParse}. */
  parse: typeof hexParse;
}

/**
 * Encode bytes to a lowercase hex string.
 *
 * @param data - raw bytes (any `BytesSource`), or a `string` (UTF-8 encoded first)
 * @returns the hex-encoded string
 * @throws {TypeError} if `data` is not a string, `ArrayBuffer` or view over one
 * @example
 * hexStringify(new Uint8Array([0xde, 0xad])); // "dead"
 */
/* @__NO_SIDE_EFFECTS__ */
export function hexStringify(data: string | BytesSource): string {
  return _encodeHex(toBytes(data, "Hex.stringify"));
}

/**
 * Decode a hex string. Strict by default.
 *
 * @param input - hex text, or its ASCII bytes
 * @param options - see {@link DecodeOptions}
 * @returns decoded bytes, or a UTF-8 `string` when `returnAs` is `"string"`
 * @throws {SyntaxError} on non-hex characters or odd length, unless `loose`
 * @throws {TypeError} if `input` is nullish
 * @example
 * hexParse("dead", { returnAs: "bytes" }); // Uint8Array [0xde, 0xad]
 */
export function hexParse<T extends DecodeReturnAs>(
  input: string | Uint8Array,
  options: DecodeOptions & { returnAs: T },
): T extends "string" ? string : Uint8Array<ArrayBuffer>;
export function hexParse(input: string, options?: DecodeOptions): string;
export function hexParse(input: Uint8Array, options?: DecodeOptions): Uint8Array<ArrayBuffer>;
/* @__NO_SIDE_EFFECTS__ */
export function hexParse(input: string | Uint8Array, options?: DecodeOptions): string | Uint8Array {
  _assertData(input, "Hex.parse");
  const { text, wantString } = _parsePrep(input, options);
  if (!text) return wantString ? "" : new Uint8Array(0);
  return _parseFinalize(_decodeHex(text, options?.loose ?? false, "Hex.parse"), wantString);
}

/** Hex codec: `Hex.stringify(bytes)` / `Hex.parse(text)`. Strict decode by default. */
export const Hex: HexCodec = /* @__PURE__ */ { stringify: hexStringify, parse: hexParse };
