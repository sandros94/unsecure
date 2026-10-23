// Which bulk backend serves a codec call: Node's `Buffer` or the TC39 `Uint8Array` methods.

/** Minimal shape of the Node.js `Buffer` instance we rely on. */
interface _BufferLike extends Uint8Array {
  toString(): string;
  toString(encoding: "hex" | "base64" | "base64url" | "utf8"): string;
}

/** Minimal shape of the Node.js `Buffer` constructor we rely on. */
interface _BufferCtor {
  from(str: string): _BufferLike;
  from(str: string, encoding: "hex" | "base64" | "base64url" | "utf8"): _BufferLike;
  from(array: Uint8Array): _BufferLike;
  from(array: ArrayBufferLike, byteOffset?: number, length?: number): _BufferLike;
}

/**
 * V8 keeps typed arrays this small on-heap; wrapping one as a `Buffer` view
 * forces it off-heap at several times the cost of a copy. Above it a view is free.
 */
const _ON_HEAP_MAX = 64;

export const nodeBuffer: _BufferCtor | undefined = /* @__PURE__ */ (() => {
  try {
    return (globalThis as { Buffer?: _BufferCtor }).Buffer;
  } catch {
    return undefined;
  }
})();

export const hasBuffer: boolean = /* @__PURE__ */ (() => typeof nodeBuffer?.from === "function")();

/* @__NO_SIDE_EFFECTS__ */
export function toBuffer(bytes: Uint8Array): _BufferLike {
  return bytes.byteLength <= _ON_HEAP_MAX
    ? nodeBuffer!.from(bytes)
    : nodeBuffer!.from(bytes.buffer, bytes.byteOffset, bytes.byteLength);
}

/**
 * `Buffer` does the bulk work where it exists, except for inputs of up to
 * `_ON_HEAP_MAX` bytes when the TC39 method exists too: that one reads an
 * on-heap array in place where `Buffer` would copy it first.
 */
/* @__NO_SIDE_EFFECTS__ */
export function preferBuffer(byteLength: number, native: boolean): boolean {
  return hasBuffer && !(native && byteLength <= _ON_HEAP_MAX);
}
