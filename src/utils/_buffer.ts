// @ts-nocheck
// Shared Buffer detection for base64 and hex utilities.
// Prefer Node.js Buffer (fastest) when available.

export const _Buffer: BufferConstructor | undefined = /* @__PURE__ */ (() => {
  try {
    return globalThis.Buffer;
  } catch {
    return undefined;
  }
})();

export const _hasBuffer: boolean = typeof _Buffer?.from === "function";

export function _toBuffer(data: Uint8Array | string): InstanceType<typeof Buffer> {
  return data instanceof Uint8Array
    ? _Buffer!.from(data.buffer, data.byteOffset, data.byteLength)
    : _Buffer!.from(data);
}
