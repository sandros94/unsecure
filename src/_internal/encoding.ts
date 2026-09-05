import { Base64, Hex, base64Parse, hexParse } from "../utils/index.ts";
import type { DigestReturnAs } from "../hash.ts";

/** Encode raw bytes into the format requested by a `returnAs` option. */
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
      return Hex.stringify(bytes);
    }
    case "b64":
    case "base64": {
      return Base64.stringify(bytes);
    }
    case "b64url":
    case "base64url": {
      return Base64.stringify(bytes, { alphabet: "base64url" });
    }
    default: {
      throw new Error(`Unsupported ${source} "returnAs" option: ${String(returnAs)}`);
    }
  }
}

/**
 * Read back the text form {@link encodeBytes} produces. Decoding is strict: a
 * signature or digest that is not the canonical encoding of some byte string
 * cannot be one this library printed, so tolerating it would only widen what
 * counts as a match. `returnAs` values that name raw bytes have no text form of
 * their own — hex is how the library prints bytes, so that is how text is read.
 */
export function decodeBytes(
  text: string,
  returnAs: DigestReturnAs | undefined,
  source: string,
): Uint8Array<ArrayBuffer> {
  switch (returnAs) {
    case undefined:
    case "bytes":
    case "uint8array":
    case "hex": {
      return hexParse(text, { returnAs: "bytes" });
    }
    case "b64":
    case "base64": {
      return base64Parse(text, { returnAs: "bytes" });
    }
    case "b64url":
    case "base64url": {
      return base64Parse(text, { alphabet: "base64url", returnAs: "bytes" });
    }
    default: {
      throw new Error(`Unsupported ${source} "returnAs" option: ${String(returnAs)}`);
    }
  }
}
