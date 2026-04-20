import { type DecodeReturnAs, textEncoder, textDecoder } from "./index.ts";
import { _Buffer, _hasBuffer, _toBuffer } from "./_buffer.ts";

// Re-export so existing deep imports keep resolving; the public
// `unsecure/utils` surface also re-exports this type via `src/utils.ts`.
export type { DecodeReturnAs };

// #region Internal utilities

const _hasToBase64 = !_hasBuffer && typeof (Uint8Array.prototype as any).toBase64 === "function";
const _hasFromBase64 = !_hasBuffer && typeof (Uint8Array as any).fromBase64 === "function";
const _b64UrlEncOpts = /* @__PURE__ */ Object.freeze({ alphabet: "base64url", omitPadding: true });
const _b64UrlDecOpts = /* @__PURE__ */ Object.freeze({ alphabet: "base64url" });

// #region Public API

/**
 * Base64 encoding. Accepts `string` or raw bytes; throws `TypeError` on
 * `null`/`undefined`. Empty strings and empty `Uint8Array` return `""`.
 */
export function base64Encode(data: Uint8Array<ArrayBuffer> | string): string {
  if (data == null) {
    throw new TypeError("base64Encode: data must be a string or Uint8Array.");
  }
  if (_hasBuffer) {
    return _toBuffer(data).toString("base64");
  }
  const encodedData = data instanceof Uint8Array ? data : textEncoder.encode(data);
  if (_hasToBase64) {
    return (encodedData as any).toBase64();
  }
  return btoa(String.fromCodePoint(...encodedData));
}

/**
 * Base64 URL-safe encoding (no padding). Accepts `string` or raw bytes;
 * throws `TypeError` on `null`/`undefined`. Empty inputs return `""`.
 */
export function base64UrlEncode(data: Uint8Array<ArrayBuffer> | string): string {
  if (data == null) {
    throw new TypeError("base64UrlEncode: data must be a string or Uint8Array.");
  }
  if (_hasBuffer) {
    return _toBuffer(data).toString("base64url");
  }
  const encodedData = data instanceof Uint8Array ? data : textEncoder.encode(data);
  if (_hasToBase64) {
    return (encodedData as any).toBase64(_b64UrlEncOpts);
  }
  return btoa(String.fromCodePoint(...encodedData))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=/g, "");
}

/* Base64 decoding function */
export function base64Decode<T extends DecodeReturnAs>(
  data: string | Uint8Array<ArrayBuffer>,
  options: { returnAs: T },
): T extends "string" ? string : Uint8Array<ArrayBuffer>;
export function base64Decode(data: string): string;
export function base64Decode(data: Uint8Array<ArrayBuffer>): Uint8Array<ArrayBuffer>;
export function base64Decode(
  data: string | Uint8Array<ArrayBuffer>,
  options?: { returnAs?: DecodeReturnAs },
): Uint8Array<ArrayBuffer> | string {
  if (data == null) {
    throw new TypeError("base64Decode: data must be a string or Uint8Array.");
  }
  const isBufferInput = data instanceof Uint8Array;
  const str = isBufferInput ? textDecoder.decode(data) : data;
  const effectiveReturnAs = options?.returnAs ?? (isBufferInput ? "uint8array" : "string");
  const decodeToString = effectiveReturnAs === "string";

  if (!str) {
    return decodeToString ? "" : new Uint8Array(0);
  }

  if (_hasBuffer) {
    const buf = _Buffer!.from(str, "base64");
    return decodeToString
      ? buf.toString("utf8")
      : new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength);
  }

  const decoded: Uint8Array<ArrayBuffer> = _hasFromBase64
    ? (Uint8Array as any).fromBase64(str)
    : Uint8Array.from(atob(str), (b) => b.codePointAt(0)!);

  return decodeToString ? textDecoder.decode(decoded) : decoded;
}

/* Base64 URL decoding function */
export function base64UrlDecode<T extends DecodeReturnAs>(
  data: string | Uint8Array<ArrayBuffer>,
  options: { returnAs: T },
): T extends "string" ? string : Uint8Array<ArrayBuffer>;
export function base64UrlDecode(data: string): string;
export function base64UrlDecode(data: Uint8Array<ArrayBuffer>): Uint8Array<ArrayBuffer>;
export function base64UrlDecode(
  data: string | Uint8Array<ArrayBuffer>,
  options?: { returnAs?: DecodeReturnAs },
): Uint8Array<ArrayBuffer> | string {
  if (data == null) {
    throw new TypeError("base64UrlDecode: data must be a string or Uint8Array.");
  }
  const isBufferInput = data instanceof Uint8Array;
  let str = isBufferInput ? textDecoder.decode(data) : data;
  const effectiveReturnAs = options?.returnAs ?? (isBufferInput ? "uint8array" : "string");
  const decodeToString = effectiveReturnAs === "string";

  if (!str) {
    return decodeToString ? "" : new Uint8Array(0);
  }

  if (_hasBuffer) {
    const buf = _Buffer!.from(str, "base64url");
    return decodeToString
      ? buf.toString("utf8")
      : new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength);
  }

  let decoded: Uint8Array<ArrayBuffer>;

  if (_hasFromBase64) {
    decoded = (Uint8Array as any).fromBase64(str, _b64UrlDecOpts);
  } else {
    str = str.replace(/-/g, "+").replace(/_/g, "/");
    while (str.length % 4) str += "=";
    decoded = Uint8Array.from(atob(str), (b) => b.codePointAt(0)!);
  }

  return decodeToString ? textDecoder.decode(decoded) : decoded;
}
