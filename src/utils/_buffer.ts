// Shared Buffer detection for various utilities.
// Prefer Node.js Buffer (fastest) when available.

/** Minimal shape of the Node.js `Buffer` instance we rely on. */
interface _BufferLike extends Uint8Array {
  toString(): string;
  toString(encoding: "hex" | "base64" | "base64url" | "utf8"): string;
}

/** Minimal shape of the Node.js `Buffer` constructor we rely on. */
interface _BufferCtor {
  from(str: string): _BufferLike;
  from(str: string, encoding: "hex" | "base64" | "base64url" | "utf8"): _BufferLike;
  from(array: ArrayBufferLike, byteOffset?: number, length?: number): _BufferLike;
}

export const _Buffer: _BufferCtor | undefined = /* @__PURE__ */ (() => {
  try {
    return (globalThis as { Buffer?: _BufferCtor }).Buffer;
  } catch {
    return undefined;
  }
})();

export const _hasBuffer: boolean = typeof _Buffer?.from === "function";

export function _toBuffer(bytes: Uint8Array): _BufferLike {
  return _Buffer!.from(bytes.buffer, bytes.byteOffset, bytes.byteLength);
}
