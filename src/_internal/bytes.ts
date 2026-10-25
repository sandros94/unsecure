import { UnsecureError } from "../errors.ts";

/**
 * Shared UTF-8 `TextEncoder`. Encoding holds no state between calls, so a
 * single instance serves every caller.
 */
export const textEncoder: TextEncoder = /* @__PURE__ */ new TextEncoder();

/**
 * Any byte container the library accepts: an `ArrayBuffer` — shared or not —
 * or a view over one. Wider than the DOM `BufferSource`, which excludes
 * `SharedArrayBuffer`-backed views.
 */
export type BytesSource = ArrayBufferLike | ArrayBufferView<ArrayBufferLike>;

/**
 * Name what the caller actually passed, so the message says something. The
 * constructor name is taken only when it is one: the value may come off the
 * wire, and a `constructor` key it carries is data, not a type.
 */
/* @__NO_SIDE_EFFECTS__ */
export function describeValue(value: unknown): string {
  if (value === null) return "null";
  if (typeof value !== "object") return typeof value;
  const name = (value as { constructor?: { name?: unknown } }).constructor?.name;
  return typeof name === "string" && /^[A-Za-z_$][\w$]{0,63}$/.test(name) ? name : "object";
}

/**
 * Coerce a caller value to bytes.
 *
 * Views and buffers are wrapped over the *same* memory rather than copied, so
 * the result aliases whatever the caller still holds — never hand it to code
 * that writes. Anything that is not text or bytes is rejected here rather
 * than coerced: `new Uint8Array(123)` is 123 zero bytes, which would turn a
 * caller's mistake into a plausible-looking result.
 */
/* @__NO_SIDE_EFFECTS__ */
export function toBytes(value: string | BytesSource, label: string): Uint8Array {
  if (typeof value === "string") return textEncoder.encode(value);
  // `isView` first: `instanceof` only says what a value inherits from, so an
  // object created on `Uint8Array.prototype` passes it while carrying none of
  // the internal slots the typed-array methods read.
  if (ArrayBuffer.isView(value)) {
    return value instanceof Uint8Array
      ? value
      : new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
  }
  if (
    value instanceof ArrayBuffer ||
    (typeof SharedArrayBuffer !== "undefined" && value instanceof SharedArrayBuffer)
  ) {
    return new Uint8Array(value);
  }
  throw new UnsecureError(
    "INVALID_TYPE",
    `${label}: expected a string, ArrayBuffer or ArrayBuffer view, got ${describeValue(value)}.`,
  );
}

/**
 * Like {@link toBytes}, but the result is never a view onto shared memory:
 * Web Crypto rejects `SharedArrayBuffer`-backed views outright, so those are
 * copied into a private buffer. The narrower return type is what lets the
 * result be handed straight to `crypto.subtle`.
 */
/* @__NO_SIDE_EFFECTS__ */
export function toCryptoBytes(value: string | BytesSource, label: string): Uint8Array<ArrayBuffer> {
  const bytes = toBytes(value, label);
  return typeof SharedArrayBuffer !== "undefined" && bytes.buffer instanceof SharedArrayBuffer
    ? new Uint8Array(bytes)
    : (bytes as Uint8Array<ArrayBuffer>);
}
