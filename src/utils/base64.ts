import { textEncoder, textDecoder } from './'

/* Base64 URL encoding function */
export function base64Encode(data: Uint8Array | string): string {
  const encodedData =
    data instanceof Uint8Array ? data : textEncoder.encode(data);

  // @ts-expect-error check if toBase64 is available
  if (Uint8Array.prototype.toBase64) {
    // @ts-expect-error
    return encodedData.toBase64();
  }

  return btoa(String.fromCodePoint(...encodedData));
}

/* Base64 URL encoding function */
export function base64UrlEncode(data: Uint8Array | string): string {
  const encodedData =
    data instanceof Uint8Array ? data : textEncoder.encode(data);

  // @ts-expect-error check if toBase64 is available
  if (Uint8Array.prototype.toBase64) {
    // @ts-expect-error
    return encodedData.toBase64({ alphabet: "base64url", omitPadding: true });
  }

  return btoa(String.fromCodePoint(...encodedData))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=/g, "");
}

/* Base64 URL decoding function */
export function base64Decode(str: string | undefined): string;
export function base64Decode<T extends boolean | undefined>(
  str?: string | undefined,
  toString?: T,
): T extends false ? Uint8Array : string;
export function base64Decode(
  str?: string | undefined,
  toString?: boolean | undefined,
): Uint8Array | string {
  const decodeToString = toString !== false;

  if (!str) {
    return decodeToString ? "" : new Uint8Array(0);
  }

  // @ts-expect-error check if fromBase64 is available
  const data: Uint8Array = Uint8Array.fromBase64
    ? // @ts-expect-error
      Uint8Array.fromBase64(str)
    : Uint8Array.from(atob(str), (b) => b.codePointAt(0)!);

  return decodeToString ? textDecoder.decode(data) : data;
}

/* Base64 URL decoding function */
export function base64UrlDecode(str: string | undefined): string;
export function base64UrlDecode<T extends boolean | undefined>(
  str?: string | undefined,
  toString?: T,
): T extends false ? Uint8Array : string;
export function base64UrlDecode(
  str?: string | undefined,
  toString?: boolean | undefined,
): Uint8Array | string {
  const decodeToString = toString !== false;

  if (!str) {
    return decodeToString ? "" : new Uint8Array(0);
  }

  let data: Uint8Array;

  // @ts-expect-error check if fromBase64 is available
  if (Uint8Array.fromBase64) {
    // @ts-expect-error
    data = Uint8Array.fromBase64(str, { alphabet: "base64url" });
  } else {
    str = str.replace(/-/g, "+").replace(/_/g, "/");
    while (str.length % 4) str += "=";
    data = Uint8Array.from(atob(str), (b) => b.codePointAt(0)!);
  }

  return decodeToString ? textDecoder.decode(data) : data;
}
