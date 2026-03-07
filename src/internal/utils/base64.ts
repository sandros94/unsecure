import { textEncoder, textDecoder } from "../../utils.ts";
import { _Buffer, _hasBuffer, _toBuffer } from "./_buffer.ts";

// #region Internal utilities

const _hasToBase64 = !_hasBuffer && typeof (Uint8Array.prototype as any).toBase64 === "function";
const _hasFromBase64 = !_hasBuffer && typeof (Uint8Array as any).fromBase64 === "function";
const _b64UrlEncOpts = /* @__PURE__ */ Object.freeze({ alphabet: "base64url", omitPadding: true });
const _b64UrlDecOpts = /* @__PURE__ */ Object.freeze({ alphabet: "base64url" });

// #region Public API

/* Base64 encoding function */
export function base64Encode(data: Uint8Array<ArrayBuffer> | string): string {
  if (_hasBuffer) {
    return _toBuffer(data).toString("base64");
  }
  const encodedData = data instanceof Uint8Array ? data : textEncoder.encode(data);
  if (_hasToBase64) {
    return (encodedData as any).toBase64();
  }
  return btoa(String.fromCodePoint(...encodedData));
}

/* Base64 URL encoding function */
export function base64UrlEncode(data: Uint8Array<ArrayBuffer> | string): string {
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
export function base64Decode(str: string | undefined): string;
export function base64Decode<T extends boolean | undefined>(
  str?: string | undefined,
  toString?: T,
): T extends false ? Uint8Array<ArrayBuffer> : string;
export function base64Decode(
  str?: string | undefined,
  toString?: boolean | undefined,
): Uint8Array<ArrayBuffer> | string {
  const decodeToString = toString !== false;

  if (!str) {
    return decodeToString ? "" : new Uint8Array(0);
  }

  if (_hasBuffer) {
    const buf = _Buffer!.from(str, "base64");
    return decodeToString
      ? buf.toString("utf8")
      : new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength);
  }

  const data: Uint8Array<ArrayBuffer> = _hasFromBase64
    ? (Uint8Array as any).fromBase64(str)
    : Uint8Array.from(atob(str), (b) => b.codePointAt(0)!);

  return decodeToString ? textDecoder.decode(data) : data;
}

/* Base64 URL decoding function */
export function base64UrlDecode(str: string | undefined): string;
export function base64UrlDecode<T extends boolean | undefined>(
  str?: string | undefined,
  toString?: T,
): T extends false ? Uint8Array<ArrayBuffer> : string;
export function base64UrlDecode(
  str?: string | undefined,
  toString?: boolean | undefined,
): Uint8Array<ArrayBuffer> | string {
  const decodeToString = toString !== false;

  if (!str) {
    return decodeToString ? "" : new Uint8Array(0);
  }

  if (_hasBuffer) {
    const buf = _Buffer!.from(str, "base64url");
    return decodeToString
      ? buf.toString("utf8")
      : new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength);
  }

  let data: Uint8Array<ArrayBuffer>;

  if (_hasFromBase64) {
    data = (Uint8Array as any).fromBase64(str, _b64UrlDecOpts);
  } else {
    str = str.replace(/-/g, "+").replace(/_/g, "/");
    while (str.length % 4) str += "=";
    data = Uint8Array.from(atob(str), (b) => b.codePointAt(0)!);
  }

  return decodeToString ? textDecoder.decode(data) : data;
}
