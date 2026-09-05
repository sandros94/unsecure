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

/**
 * Validate hex text and return the part that encodes whole bytes: `[0-9a-fA-F]`
 * only, even length. Loose drops every other character — whitespace, `0x`,
 * separators — and then the odd nibble, if one is left over.
 */
/* @__NO_SIDE_EFFECTS__ */
function _hexBody(text: string, loose: boolean, label: string): string {
  if (loose) {
    const clean = text.replace(/[^\dA-Fa-f]/g, "");
    return clean.length % 2 === 0 ? clean : clean.slice(0, -1);
  }
  for (let i = 0; i < text.length; i++) {
    const c = text.charCodeAt(i);
    if (!((c >= 48 && c <= 57) || (c >= 65 && c <= 70) || (c >= 97 && c <= 102))) {
      throw _malformed(
        label,
        `invalid hexadecimal character ${JSON.stringify(text[i])} at index ${i}.`,
      );
    }
  }
  if (text.length % 2 !== 0) {
    throw _malformed(label, `${text.length} hexadecimal characters cannot encode whole bytes.`);
  }
  return text;
}

/** charCode → nibble; `& 0xdf` folds a letter to uppercase. Digits only. */
/* @__NO_SIDE_EFFECTS__ */
function _nibble(code: number): number {
  return code <= 57 ? code - 48 : (code & 0xdf) - 55;
}

/* @__NO_SIDE_EFFECTS__ */
function _hexManual(text: string): Uint8Array<ArrayBuffer> {
  const bytes = new Uint8Array(text.length >>> 1);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = (_nibble(text.charCodeAt(i * 2)) << 4) | _nibble(text.charCodeAt(i * 2 + 1));
  }
  return bytes;
}

/**
 * Bulk-decode validated, even-length hex. The backends disagree about what is
 * malformed and phrase their complaints differently, so none of them is ever
 * asked to validate — only to decode text that is already known good.
 */
/* @__NO_SIDE_EFFECTS__ */
function _decodeHex(text: string): Uint8Array<ArrayBuffer> {
  if (_hasBuffer) return new Uint8Array(_Buffer!.from(text, "hex"));
  if (_nativeFromHex) return (Uint8Array as unknown as _FromHex).fromHex(text);
  return _hexManual(text);
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
 * Decode a hex string. Strict by default: `[0-9a-fA-F]` only — whitespace
 * included in the rejection — and an even length. `{ loose: true }` drops
 * every other character, and the odd nibble left over, instead of throwing.
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
  const loose = options?.loose ?? false;
  const body = _hexBody(text, loose, "Hex.parse");
  return _parseFinalize(_decodeHex(body), wantString, !loose, "Hex.parse");
}

/** Hex codec: `Hex.stringify(bytes)` / `Hex.parse(text)`. Strict decode by default. */
export const Hex: HexCodec = /* @__PURE__ */ { stringify: hexStringify, parse: hexParse };
