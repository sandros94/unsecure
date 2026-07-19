import { Base64, Hex } from "../utils/index.ts";
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
