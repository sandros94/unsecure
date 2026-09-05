import { Base64, Hex, base64Parse, hexParse } from "../utils/index.ts";
import type { DigestReturnAs } from "../hash.ts";

/** The text form a `returnAs` names; `"raw"` is bytes, which have none. */
type _Form = "hex" | "base64" | "base64url" | "raw";

/**
 * Every `returnAs` the library accepts, and the form it names. One table
 * rather than three switches: the accepted set, how bytes are written and how
 * text is read all have to agree, and a `Map` cannot be reached through a
 * caller-supplied key like `"constructor"`.
 */
const _FORMS: ReadonlyMap<string, _Form> = /* @__PURE__ */ new Map<DigestReturnAs, _Form>([
  ["hex", "hex"],
  ["base64", "base64"],
  ["b64", "base64"],
  ["base64url", "base64url"],
  ["b64url", "base64url"],
  ["uint8array", "raw"],
  ["bytes", "raw"],
]);

/** The one place an unknown `returnAs` is refused. */
function _formOf(returnAs: DigestReturnAs, source: string): _Form {
  const form = _FORMS.get(returnAs);
  if (form === undefined) {
    throw new Error(`Unsupported ${source} "returnAs" option: ${String(returnAs)}`);
  }
  return form;
}

/**
 * Reject a `returnAs` the library does not know, before anything is computed.
 * An unsupported option is a caller mistake whichever path would consume it,
 * so it must not depend on the shape of the other arguments.
 */
export function assertReturnAs(returnAs: DigestReturnAs | undefined, source: string): void {
  if (returnAs !== undefined) _formOf(returnAs, source);
}

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
  switch (_formOf(returnAs, source)) {
    case "raw": {
      return bytes;
    }
    case "hex": {
      return Hex.stringify(bytes);
    }
    case "base64": {
      return Base64.stringify(bytes);
    }
    case "base64url": {
      return Base64.stringify(bytes, { alphabet: "base64url" });
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
  switch (returnAs === undefined ? "hex" : _formOf(returnAs, source)) {
    case "raw":
    case "hex": {
      return hexParse(text, { returnAs: "bytes" });
    }
    case "base64": {
      return base64Parse(text, { returnAs: "bytes" });
    }
    case "base64url": {
      return base64Parse(text, { alphabet: "base64url", returnAs: "bytes" });
    }
  }
}
