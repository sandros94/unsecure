import { textDecoder, textEncoder } from "../../utils.ts";
import type { DecodeReturnAs } from "./types.ts";

const BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/**
 * Encode binary data to a Base32 string (RFC 4648).
 *
 * Accepts `string` or raw bytes. `undefined` and empty input return `""`.
 *
 * @param data Raw bytes or a string to encode.
 * @returns A padded Base32-encoded string.
 */
export function base32Encode(data?: Uint8Array<ArrayBuffer> | string): string {
  if (!data) return "";
  const bytes = typeof data === "string" ? textEncoder.encode(data) : data;
  if (bytes.length === 0) return "";

  let result = "";
  let bits = 0;
  let value = 0;

  for (const byte of bytes) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      result += BASE32_ALPHABET[(value >>> bits) & 0x1f];
    }
  }

  if (bits > 0) {
    result += BASE32_ALPHABET[(value << (5 - bits)) & 0x1f];
  }

  while (result.length % 8) {
    result += "=";
  }

  return result;
}

/**
 * Decode a Base32 string (RFC 4648). Handles padded or unpadded input,
 * case-insensitively, and silently skips whitespace and invalid characters.
 *
 * When `returnAs` is not specified, the return type mirrors the input:
 * - `string` input → decoded bytes interpreted as UTF-8 (`string`)
 * - `Uint8Array` input → raw decoded bytes (`Uint8Array`)
 *
 * Pass `{ returnAs: "uint8array" }` (or `"bytes"`) to always get bytes,
 * or `{ returnAs: "string" }` to always get a UTF-8 string.
 */
export function base32Decode<T extends DecodeReturnAs>(
  data: string | Uint8Array<ArrayBuffer>,
  options: { returnAs: T },
): T extends "string" ? string : Uint8Array<ArrayBuffer>;
export function base32Decode(data?: string | undefined): string;
export function base32Decode(data: Uint8Array<ArrayBuffer> | undefined): Uint8Array<ArrayBuffer>;
export function base32Decode(
  data?: string | Uint8Array<ArrayBuffer> | undefined,
  options?: { returnAs?: DecodeReturnAs },
): Uint8Array<ArrayBuffer> | string {
  const isBufferInput = data instanceof Uint8Array;
  const str = isBufferInput ? textDecoder.decode(data) : data;
  const effectiveReturnAs = options?.returnAs ?? (isBufferInput ? "uint8array" : "string");
  const decodeToString = effectiveReturnAs === "string";

  if (!str) {
    return decodeToString ? "" : new Uint8Array(0);
  }

  const bytes = _base32DecodeToBytes(str);
  return decodeToString ? textDecoder.decode(bytes) : bytes;
}

function _base32DecodeToBytes(data: string): Uint8Array<ArrayBuffer> {
  const output = new Uint8Array(Math.floor((data.length * 5) / 8));
  let bits = 0;
  let value = 0;
  let index = 0;

  for (let i = 0; i < data.length; i++) {
    const c = data.charCodeAt(i);
    let v: number;
    if (c >= 65 && c <= 90)
      v = c - 65; // A-Z → 0-25
    else if (c >= 97 && c <= 122)
      v = c - 97; // a-z → 0-25
    else if (c >= 50 && c <= 55)
      v = c - 24; // 2-7 → 26-31
    else continue; // skip padding, whitespace, invalid

    value = (value << 5) | v;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      output[index++] = (value >>> bits) & 0xff;
    }
  }

  return output.subarray(0, index);
}
