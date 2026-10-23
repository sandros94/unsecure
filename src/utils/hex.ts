import { type BytesSource, toBytes } from "../_internal/bytes.ts";
import {
  type DecodeOptions,
  type DecodeReturnAs,
  assertData,
  parseFinalize,
  parsePrep,
} from "../_internal/codec.ts";
import { hexParseText, hexStringifyBytes } from "../_internal/hex.ts";

export interface HexCodec {
  /** See {@link hexStringify}. */
  stringify: typeof hexStringify;
  /** See {@link hexParse}. */
  parse: typeof hexParse;
}

/**
 * Encode bytes to a lowercase hex string.
 *
 * @param data - raw bytes (any `BytesSource`), or a `string` (UTF-8 encoded first)
 * @returns the hex-encoded string
 * @throws {UnsecureError} `INVALID_TYPE` if `data` is not a string, `ArrayBuffer` or view over one
 * @example
 * hexStringify(new Uint8Array([0xde, 0xad])); // "dead"
 */
/* @__NO_SIDE_EFFECTS__ */
export function hexStringify(data: string | BytesSource): string {
  return hexStringifyBytes(toBytes(data, "Hex.stringify"));
}

/**
 * Decode a hex string. Strict by default: `[0-9a-fA-F]` only — whitespace
 * included in the rejection — and an even length. `{ loose: true }` drops
 * every other character, and the odd nibble left over, instead of throwing.
 *
 * @param input - hex text, or its ASCII bytes
 * @param options - see {@link DecodeOptions}
 * @returns decoded bytes, or a UTF-8 `string` when `returnAs` is `"string"`
 * @throws {UnsecureError} `MALFORMED` on non-hex characters or odd length, unless `loose`
 * @throws {UnsecureError} `INVALID_TYPE` if `input` is nullish
 * @example
 * hexParse("dead", { returnAs: "bytes" }); // Uint8Array [0xde, 0xad]
 */
export function hexParse<T extends DecodeReturnAs>(
  input: string | Uint8Array,
  options: DecodeOptions & { returnAs: T },
): T extends "string" ? string : Uint8Array<ArrayBuffer>;
export function hexParse(input: string, options?: DecodeOptions): string;
export function hexParse(input: Uint8Array, options?: DecodeOptions): Uint8Array<ArrayBuffer>;
/* @__NO_SIDE_EFFECTS__ */
export function hexParse(input: string | Uint8Array, options?: DecodeOptions): string | Uint8Array {
  assertData(input, "Hex.parse");
  const { text, wantString } = parsePrep(input, options);
  if (!text) return wantString ? "" : new Uint8Array(0);
  const loose = options?.loose ?? false;
  return parseFinalize(hexParseText(text, "Hex.parse", { loose }), wantString, !loose, "Hex.parse");
}

/** Hex codec: `Hex.stringify(bytes)` / `Hex.parse(text)`. Strict decode by default. */
export const Hex: HexCodec = { stringify: hexStringify, parse: hexParse };
