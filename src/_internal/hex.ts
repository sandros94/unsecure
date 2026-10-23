import { nodeBuffer, preferBuffer, toBuffer } from "./buffer.ts";
import { honoursViews, malformed, wholeBuffer } from "./codec.ts";

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
/** Whether `toHex` honours a view; a runtime without it never reaches it. */
const _hexViews: boolean = /* @__PURE__ */ (() =>
  !_nativeToHex || honoursViews((view) => (view as unknown as _ToHex).toHex(), "0102"))();

/** Lowercase hex of `bytes`. */
/* @__NO_SIDE_EFFECTS__ */
export function hexStringifyBytes(bytes: Uint8Array): string {
  if (preferBuffer(bytes.length, _nativeToHex)) return toBuffer(bytes).toString("hex");
  if (_nativeToHex) return (wholeBuffer(bytes, _hexViews) as unknown as _ToHex).toHex();
  let out = "";
  for (let i = 0; i < bytes.length; i++) {
    out += bytes[i]!.toString(16).padStart(2, "0");
  }
  return out;
}

/**
 * Bytes of hex `text`: `[0-9a-fA-F]` only and an even length, or with `loose`
 * whatever of it decodes — every other character dropped, then the odd nibble.
 */
/* @__NO_SIDE_EFFECTS__ */
export function hexParseText(
  text: string,
  source: string,
  options: { loose?: boolean } = {},
): Uint8Array<ArrayBuffer> {
  return _bulk(_body(text, options.loose ?? false, source));
}

/** Validate hex text and return the part that encodes whole bytes. */
/* @__NO_SIDE_EFFECTS__ */
function _body(text: string, loose: boolean, source: string): string {
  if (loose) {
    const clean = text.replace(/[^\dA-Fa-f]/g, "");
    return clean.length % 2 === 0 ? clean : clean.slice(0, -1);
  }
  for (let i = 0; i < text.length; i++) {
    const c = text.charCodeAt(i);
    if (!((c >= 48 && c <= 57) || (c >= 65 && c <= 70) || (c >= 97 && c <= 102))) {
      throw malformed(
        `invalid hexadecimal character ${JSON.stringify(text[i])} at index ${i}.`,
        source,
      );
    }
  }
  if (text.length % 2 !== 0) {
    throw malformed(`${text.length} hexadecimal characters cannot encode whole bytes.`, source);
  }
  return text;
}

/** charCode → nibble; `& 0xdf` folds a letter to uppercase. Digits only. */
/* @__NO_SIDE_EFFECTS__ */
function _nibble(code: number): number {
  return code <= 57 ? code - 48 : (code & 0xdf) - 55;
}

/* @__NO_SIDE_EFFECTS__ */
function _manual(text: string): Uint8Array<ArrayBuffer> {
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
function _bulk(text: string): Uint8Array<ArrayBuffer> {
  if (preferBuffer(text.length >>> 1, _nativeFromHex)) {
    return new Uint8Array(nodeBuffer!.from(text, "hex"));
  }
  if (_nativeFromHex) return (Uint8Array as unknown as _FromHex).fromHex(text);
  return _manual(text);
}
