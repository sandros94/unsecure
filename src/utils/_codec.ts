/** Shared UTF-8 `TextEncoder` instance. */
export const textEncoder: TextEncoder = /* @__PURE__ */ new TextEncoder();
/** Shared UTF-8 `TextDecoder` instance. */
export const textDecoder: TextDecoder = /* @__PURE__ */ new TextDecoder();

/**
 * Decoder output shape. Omit to mirror the input (`string` in → `string` out,
 * `Uint8Array` in → `Uint8Array` out). `"bytes"` aliases `"uint8array"`.
 */
export type DecodeReturnAs = "string" | "uint8array" | "bytes";

/** Shared `parse` options. */
export interface DecodeOptions {
  /** Output shape. Mirrors the input type when omitted. */
  returnAs?: DecodeReturnAs;
  /**
   * Tolerate malformed input (skip/normalize) instead of throwing.
   * @default false
   */
  loose?: boolean;
}

export function _assertData(data: unknown, label: string): void {
  if (data == null) {
    throw new TypeError(`${label}: data must be a string or Uint8Array.`);
  }
}

export function _toBytes(data: Uint8Array | string): Uint8Array {
  return typeof data === "string" ? textEncoder.encode(data) : data;
}

/** `Uint8Array` input is treated as the ASCII bytes of the encoded text. */
export function _parsePrep(
  input: string | Uint8Array,
  options: DecodeOptions | undefined,
): { text: string; wantString: boolean } {
  const isBytes = input instanceof Uint8Array;
  const returnAs = options?.returnAs ?? (isBytes ? "uint8array" : "string");
  return {
    text: isBytes ? textDecoder.decode(input) : input,
    wantString: returnAs === "string",
  };
}

export function _parseFinalize(bytes: Uint8Array, wantString: boolean): string | Uint8Array {
  return wantString ? textDecoder.decode(bytes) : bytes;
}

export function _malformed(label: string, detail: string): SyntaxError {
  return new SyntaxError(`${label}: ${detail}`);
}
