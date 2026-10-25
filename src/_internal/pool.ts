import { UnsecureError } from "../errors.ts";

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

/**
 * The one call to the platform's generator. A refusal — a missing or
 * disabled `crypto`, a view it will not fill — is the runtime declining,
 * which is what `PLATFORM` names; nothing a caller controls reaches here.
 */
function _random<T extends ArrayBufferView<ArrayBuffer>>(target: T): T {
  try {
    return crypto.getRandomValues(target);
  } catch (error) {
    throw new UnsecureError("PLATFORM", "the runtime's crypto.getRandomValues refused.", {
      cause: error,
    });
  }
}

/** Random bytes straight from the platform, in the chunks it accepts. */
function _direct(target: Uint8Array<ArrayBuffer>): void {
  const length = target.length;
  if (length <= _MAX_FILL) {
    _random(target);
    return;
  }
  for (let start = 0; start < length; start += _MAX_FILL) {
    _random(target.subarray(start, Math.min(start + _MAX_FILL, length)));
  }
}

interface _StartupSnapshot {
  /** Node answers `1` / `0`, not a boolean: read it for truth, never `=== true`. */
  isBuildingSnapshot(): boolean | number;
  addDeserializeCallback(callback: () => void): void;
}

/**
 * Node's startup-snapshot API, looked up once. A lookup, not an import, so the
 * module stays runtime-agnostic; `undefined` everywhere else.
 */
/* @__NO_SIDE_EFFECTS__ */
function _startupSnapshot(): _StartupSnapshot | undefined {
  try {
    const proc = (globalThis as { process?: { getBuiltinModule?: (id: string) => unknown } })
      .process;
    if (typeof proc?.getBuiltinModule !== "function") return undefined;
    return (proc.getBuiltinModule("node:v8") as { startupSnapshot?: _StartupSnapshot })
      ?.startupSnapshot;
  } catch {
    // A `process` without the module: nothing to consult.
    return undefined;
  }
}

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
  // Looked up when the pool is made: a pool created after a restore is in a
  // process that is not building, whatever the one that built the blob was.
  const snapshot = _startupSnapshot();

  function refill(): void {
    if (bytes === undefined) {
      const buffer = new ArrayBuffer(size);
      bytes = new Uint8Array(buffer);
      words = new Uint32Array(buffer);
    }
    _random(bytes);
    offset = 0;
  }

  function nextUint32(): number {
    // While a startup snapshot is being built nothing may be buffered: a word
    // left in the pool would be serialized and served after every restore.
    if (snapshot?.isBuildingSnapshot()) return _random(new Uint32Array(1))[0]!;
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
    if (length > POOL_DIRECT_ABOVE || snapshot?.isBuildingSnapshot()) {
      _direct(target);
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

  // While Node builds a startup snapshot the pool buffers nothing (above), so
  // the blob never carries bytes to replay. The restore callback is a second
  // layer behind that: it wipes whatever a pool holds, for every pool created
  // while building, whatever order other callbacks were registered in.
  if (snapshot?.isBuildingSnapshot()) snapshot.addDeserializeCallback(() => reset());
  return { nextUint32, fill, reset };
}

/** The pool behind every one-shot draw in the library. */
export const sharedPool: EntropyPool = /* @__PURE__ */ createEntropyPool(SHARED_POOL_BYTES);
