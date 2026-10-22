// Which bulk backend serves a codec call: Node's `Buffer`, when the runtime
// has it, measured against the TC39 `Uint8Array` methods by input size.

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

export const _Buffer: _BufferCtor | undefined = /* @__PURE__ */ (() => {
  try {
    return (globalThis as { Buffer?: _BufferCtor }).Buffer;
  } catch {
    return undefined;
  }
})();

export const _hasBuffer: boolean = /* @__PURE__ */ (() => typeof _Buffer?.from === "function")();

/* @__NO_SIDE_EFFECTS__ */
export function _toBuffer(bytes: Uint8Array): _BufferLike {
  return bytes.byteLength <= _ON_HEAP_MAX
    ? _Buffer!.from(bytes)
    : _Buffer!.from(bytes.buffer, bytes.byteOffset, bytes.byteLength);
}

/**
 * Whether `Buffer` should do the bulk work for `byteLength` bytes, given
 * whether the runtime also has the TC39 `Uint8Array` method for the job.
 *
 * Where both exist the size decides: the native method reads an on-heap array
 * in place, while `Buffer` has to copy it first, so up to `_ON_HEAP_MAX`
 * bytes it is the faster of the two by a wide margin. Above that the array is
 * off-heap either way and `Buffer` keeps the edge in bulk work. Where only
 * one exists it serves every size, and the manual loop is the last resort.
 */
/* @__NO_SIDE_EFFECTS__ */
export function _preferBuffer(byteLength: number, native: boolean): boolean {
  return _hasBuffer && !(native && byteLength <= _ON_HEAP_MAX);
}
