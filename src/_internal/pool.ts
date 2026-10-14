/**
 * The library's one buffered source of entropy. `crypto.getRandomValues`
 * costs the call, not the bytes, so every small draw (a UUID, a salt, a random
 * integer) is served from a pool filled in one call. The pool is never handed
 * out: `fill` copies into the caller's memory and zeroes the slot, nothing is
 * allocated before the first draw, and every draw is synchronous.
 */

/** Bytes per refill of the process-wide pool: one `getRandomValues` per 256 UUIDs. */
export const SHARED_POOL_BYTES = 4096;

/** A `fill` longer than this goes straight to `crypto.getRandomValues`. */
export const POOL_DIRECT_ABOVE = 64;

/** `crypto.getRandomValues` refuses more than this many bytes in one call. */
const _MAX_FILL = 65536;

export interface EntropyPool {
  /** One uniformly random unsigned 32-bit integer. */
  nextUint32(): number;
  /** Overwrite every byte of `target` with random bytes. Returns `target`. */
  fill<T extends Uint8Array<ArrayBuffer>>(target: T): T;
  /** Wipe and release the buffer. The next draw refills, or `now` does. */
  reset(now?: boolean): void;
}

/** A pool of `size` bytes (a multiple of 4, at most 65536), empty until the first draw. */
/* @__NO_SIDE_EFFECTS__ */
export function createEntropyPool(size: number): EntropyPool {
  let bytes: Uint8Array<ArrayBuffer> | undefined;
  let words: Uint32Array<ArrayBuffer> | undefined;
  let offset = size;

  function refill(): void {
    if (bytes === undefined) {
      const buffer = new ArrayBuffer(size);
      bytes = new Uint8Array(buffer);
      words = new Uint32Array(buffer);
    }
    crypto.getRandomValues(bytes);
    offset = 0;
  }

  function nextUint32(): number {
    // Realign after byte draws; discards at most 3 bytes.
    offset = (offset + 3) & ~3;
    if (offset >= size) refill();
    const value = words![offset >>> 2]!;
    offset += 4;
    return value;
  }

  function fill<T extends Uint8Array<ArrayBuffer>>(target: T): T {
    const length = target.length;
    if (length === 0) return target;
    if (length > POOL_DIRECT_ABOVE) {
      if (length <= _MAX_FILL) {
        crypto.getRandomValues(target);
      } else {
        for (let start = 0; start < length; start += _MAX_FILL) {
          crypto.getRandomValues(target.subarray(start, Math.min(start + _MAX_FILL, length)));
        }
      }
      return target;
    }
    if (offset + length > size) refill();
    const slot = bytes!.subarray(offset, offset + length);
    target.set(slot);
    slot.fill(0);
    offset += length;
    return target;
  }

  function reset(now = false): void {
    bytes?.fill(0);
    bytes = words = undefined;
    offset = size;
    if (now) refill();
  }

  _onSnapshotRestore(reset);
  return { nextUint32, fill, reset };
}

/** The pool behind every one-shot draw in the library. */
export const sharedPool: EntropyPool = /* @__PURE__ */ createEntropyPool(SHARED_POOL_BYTES);

interface _StartupSnapshot {
  isBuildingSnapshot(): boolean;
  addDeserializeCallback(callback: () => void): void;
}

/**
 * While Node builds a startup snapshot, run `callback` on restore so no two
 * restored processes replay the same pool. A lookup, not an import, so the
 * module stays runtime-agnostic; a no-op everywhere else.
 */
function _onSnapshotRestore(callback: () => void): void {
  try {
    const proc = (globalThis as { process?: { getBuiltinModule?: (id: string) => unknown } })
      .process;
    if (typeof proc?.getBuiltinModule !== "function") return;
    const snapshot = (proc.getBuiltinModule("node:v8") as { startupSnapshot?: _StartupSnapshot })
      ?.startupSnapshot;
    if (snapshot?.isBuildingSnapshot()) snapshot.addDeserializeCallback(callback);
  } catch {
    // A `process` without the module: nothing to register.
  }
}
