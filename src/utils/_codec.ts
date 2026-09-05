import { describeValue } from "../_internal/bytes.ts";

export { type BytesSource, toBytes } from "../_internal/bytes.ts";

/** Shared UTF-8 `TextEncoder` instance. */
export { textEncoder } from "../_internal/bytes.ts";

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

/**
 * `parse` reads encoded text: a `string`, or the ASCII bytes of one. Anything
 * else — a number, a plain object, an `ArrayBuffer` — is a caller mistake, not
 * something to coerce into text and then complain about.
 */
export function _assertData(input: unknown, label: string): asserts input is string | Uint8Array {
  if (typeof input !== "string" && !(input instanceof Uint8Array)) {
    throw new TypeError(`${label}: expected a string or Uint8Array, got ${describeValue(input)}.`);
  }
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

/**
 * Geometry of a padded block codec: `bits` carried by one symbol, `group`
 * symbols per whole block, and the codec name used in error text.
 */
export interface _BlockShape {
  bits: number;
  group: number;
  name: string;
}

/**
 * Unused low bits carried by the final symbol of a body that ends `rem`
 * symbols past the last whole block, or `-1` when no byte string can produce
 * that remainder — those symbols would waste a whole symbol's worth of bits.
 */
/* @__NO_SIDE_EFFECTS__ */
export function _tailBits(rem: number, bits: number): number {
  if (rem === 0) return 0;
  const leftover = (rem * bits) % 8;
  return leftover >= bits ? -1 : leftover;
}

/**
 * Validate one encoded body and return it stripped of trailing padding.
 *
 * Canonical means exactly one text per byte string: alphabet characters only
 * (whitespace included in the rejection), `=` only as a trailing run and only
 * in the count the body length calls for — or absent, since padding tells a
 * decoder nothing the length does not — and no set bits past the last byte.
 */
export function _strictBody(
  text: string,
  table: Int16Array,
  shape: _BlockShape,
  label: string,
): string {
  let end = text.length;
  while (end > 0 && text.charCodeAt(end - 1) === 61) end--;
  const padFound = text.length - end;

  for (let i = 0; i < end; i++) {
    const c = text.charCodeAt(i);
    if ((c < 128 ? table[c]! : -1) < 0) {
      throw _malformed(
        label,
        `invalid ${shape.name} character ${JSON.stringify(text[i])} at index ${i}.`,
      );
    }
  }

  const rem = end % shape.group;
  const tail = _tailBits(rem, shape.bits);
  if (tail < 0) {
    throw _malformed(label, `${end} ${shape.name} symbols cannot encode whole bytes.`);
  }

  const padNeeded = rem === 0 ? 0 : shape.group - rem;
  if (padFound > 0) {
    if (padNeeded === 0) throw _malformed(label, `unexpected "=" padding.`);
    if (padFound !== padNeeded) {
      throw _malformed(label, `expected ${padNeeded} "=" padding characters, found ${padFound}.`);
    }
  }

  if (tail > 0 && (table[text.charCodeAt(end - 1)]! & ((1 << tail) - 1)) !== 0) {
    throw _malformed(label, `the last ${shape.name} symbol sets bits past the final byte.`);
  }

  return end === text.length ? text : text.slice(0, end);
}

/** Symbol values read out of `text`; anything outside `table` is dropped. */
/* @__NO_SIDE_EFFECTS__ */
export function _symbols(text: string, table: Int16Array): Uint8Array {
  const values = new Uint8Array(text.length);
  let n = 0;
  for (let i = 0; i < text.length; i++) {
    const c = text.charCodeAt(i);
    const v = c < 128 ? table[c]! : -1;
    if (v >= 0) values[n++] = v;
  }
  return n === values.length ? values : values.subarray(0, n);
}

/** Longest prefix of `n` symbols that still encodes whole bytes. */
/* @__NO_SIDE_EFFECTS__ */
export function _looseCount(n: number, shape: _BlockShape): number {
  let count = n;
  while (count > 0 && _tailBits(count % shape.group, shape.bits) < 0) count--;
  return count;
}

/**
 * Pack the first `count` symbols into bytes, dropping the bits that fall past
 * the last whole byte. The result owns its buffer at exactly its own length.
 */
/* @__NO_SIDE_EFFECTS__ */
export function _decodeSymbols(
  values: Uint8Array,
  count: number,
  bits: number,
): Uint8Array<ArrayBuffer> {
  const out = new Uint8Array((count * bits) >>> 3);
  let acc = 0;
  let held = 0;
  let j = 0;
  for (let i = 0; i < count; i++) {
    acc = (acc << bits) | values[i]!;
    held += bits;
    if (held >= 8) {
      held -= 8;
      out[j++] = (acc >>> held) & 0xff;
    }
  }
  return out;
}
