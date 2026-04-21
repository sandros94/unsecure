import { type DecodeReturnAs, textEncoder, textDecoder } from "./index.ts";
import { _Buffer, _hasBuffer, _toBuffer } from "./_buffer.ts";

// #region Internal utilities

const _hasToHex = !_hasBuffer && typeof (Uint8Array.prototype as any).toHex === "function";
const _hasFromHex = !_hasBuffer && typeof (Uint8Array as any).fromHex === "function";

// #region Public API

/**
 * Hex encoding. Accepts `string` or raw bytes; throws `TypeError` on
 * `null`/`undefined`. Empty strings and empty `Uint8Array` return `""`.
 */
export function hexEncode(data: Uint8Array | string): string {
  if (data == null) {
    throw new TypeError("hexEncode: data must be a string or Uint8Array.");
  }
  if (_hasBuffer) {
    return _toBuffer(data).toString("hex");
  }
  const encodedData = data instanceof Uint8Array ? data : textEncoder.encode(data);
  if (_hasToHex) {
    return (encodedData as any).toHex();
  }
  return Array.prototype.map
    .call(encodedData, (x: number) => ("00" + x.toString(16)).slice(-2))
    .join("");
}

/* Hex decoding function */
export function hexDecode<T extends DecodeReturnAs>(
  data: string | Uint8Array,
  options: { returnAs: T },
): T extends "string" ? string : Uint8Array<ArrayBuffer>;
export function hexDecode(data: string): string;
export function hexDecode(data: Uint8Array): Uint8Array<ArrayBuffer>;
export function hexDecode(
  data: string | Uint8Array,
  options?: { returnAs?: DecodeReturnAs },
): Uint8Array<ArrayBuffer> | string {
  if (data == null) {
    throw new TypeError("hexDecode: data must be a string or Uint8Array.");
  }
  const isBufferInput = data instanceof Uint8Array;
  const str = isBufferInput ? textDecoder.decode(data) : data;
  const effectiveReturnAs = options?.returnAs ?? (isBufferInput ? "uint8array" : "string");
  const decodeToString = effectiveReturnAs === "string";

  if (!str) {
    return decodeToString ? "" : new Uint8Array(0);
  }

  if (_hasBuffer) {
    const buf = _Buffer!.from(str, "hex");
    return decodeToString ? buf.toString("utf8") : new Uint8Array(buf);
  }

  const decoded: Uint8Array<ArrayBuffer> = _hasFromHex
    ? (Uint8Array as any).fromHex(str)
    : fromHexString(str);

  return decodeToString ? textDecoder.decode(decoded) : decoded;
}

function fromHexString(hexString: string) {
  // Only parse complete byte pairs; ignore trailing nibble and invalid chars (matches Buffer behavior)
  const len = hexString.length >>> 1;
  if (len === 0) return new Uint8Array(0);
  const bytes = new Uint8Array(len);
  let j = 0;
  for (let i = 0; i < len; i++) {
    const hi = Number.parseInt(hexString[i * 2], 16);
    const lo = Number.parseInt(hexString[i * 2 + 1], 16);
    if (Number.isNaN(hi) || Number.isNaN(lo)) break;
    bytes[j++] = (hi << 4) | lo;
  }
  return j === len ? bytes : bytes.slice(0, j);
}
