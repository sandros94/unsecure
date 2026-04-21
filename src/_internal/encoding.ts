import { base64Encode, base64UrlEncode, hexEncode } from "../utils/index.ts";
import type { DigestReturnAs } from "../hash.ts";

/**
 * Encode raw bytes into the format requested by a `returnAs` option.
 *
 * Shared by `hash`, `hmac`, and `hkdf` so their `returnAs` handling stays
 * consistent by construction.
 *
 * @param bytes The raw output bytes to encode.
 * @param returnAs The requested output shape.
 * @param source A short label (e.g. `"hash"`, `"hmac"`, `"hkdf"`) used in
 *               the error message when `returnAs` is unsupported.
 * @throws {Error} If `returnAs` is not a recognized value.
 */
export function encodeBytes<T extends DigestReturnAs>(
  bytes: Uint8Array<ArrayBuffer>,
  returnAs: T,
  source: string,
): T extends "uint8array" | "bytes" ? Uint8Array<ArrayBuffer> : string;
export function encodeBytes(
  bytes: Uint8Array<ArrayBuffer>,
  returnAs: DigestReturnAs,
  source: string,
): Uint8Array<ArrayBuffer> | string {
  switch (returnAs) {
    case "bytes":
    case "uint8array": {
      return bytes;
    }
    case "hex": {
      return hexEncode(bytes);
    }
    case "b64":
    case "base64": {
      return base64Encode(bytes);
    }
    case "b64url":
    case "base64url": {
      return base64UrlEncode(bytes);
    }
    default: {
      throw new Error(`Unsupported ${source} "returnAs" option: ${returnAs}`);
    }
  }
}
