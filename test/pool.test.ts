import { describe, it, expect, vi, afterEach } from "vitest";
import {
  POOL_DIRECT_ABOVE,
  SHARED_POOL_BYTES,
  createEntropyPool,
  sharedPool,
} from "../src/_internal/pool.ts";
import { secureRandomBytes, secureRandomNumber } from "../src/random.ts";
import { uuidv4, uuidv7 } from "../src/uuid.ts";

afterEach(() => {
  vi.restoreAllMocks();
});

describe("createEntropyPool", () => {
  it("is empty until the first draw, then refills in one call", () => {
    const spy = vi.spyOn(crypto, "getRandomValues");
    const pool = createEntropyPool(64);
    expect(spy).not.toHaveBeenCalled();
    pool.nextUint32();
    expect(spy).toHaveBeenCalledTimes(1);
    expect(spy.mock.calls[0]![0]).toHaveLength(64);
  });

  it("serves `size` bytes of draws per refill", () => {
    const spy = vi.spyOn(crypto, "getRandomValues");
    const pool = createEntropyPool(64);
    for (let i = 0; i < 16; i++) pool.nextUint32();
    expect(spy).toHaveBeenCalledTimes(1);
    pool.nextUint32();
    expect(spy).toHaveBeenCalledTimes(2);
  });

  it("realigns a word draw after an odd byte draw instead of reading across a boundary", () => {
    const pool = createEntropyPool(16);
    pool.fill(new Uint8Array(3));
    // Offsets 3..7 would be a misaligned word; the draw skips to 4 and the
    // pool has 8 bytes left, i.e. exactly two more words before a refill.
    const spy = vi.spyOn(crypto, "getRandomValues");
    pool.nextUint32();
    pool.nextUint32();
    pool.nextUint32();
    expect(spy).not.toHaveBeenCalled();
    pool.nextUint32();
    expect(spy).toHaveBeenCalledTimes(1);
  });

  it("copies into the caller's memory and never hands out the pool", () => {
    const pool = createEntropyPool(64);
    const a = pool.fill(new Uint8Array(16));
    const b = pool.fill(new Uint8Array(16));
    expect(a.buffer).not.toBe(b.buffer);
    expect(a.byteLength).toBe(16);
    expect(a).not.toEqual(b);
  });

  it("fills a view in place and returns it", () => {
    const pool = createEntropyPool(64);
    const bytes = new Uint8Array(16);
    const view = bytes.subarray(6);
    expect(pool.fill(view)).toBe(view);
    expect(bytes.subarray(0, 6)).toEqual(new Uint8Array(6));
    expect(view.some((b) => b !== 0)).toBe(true);
  });

  it("discards a tail too short for the draw and refills", () => {
    const pool = createEntropyPool(16);
    pool.fill(new Uint8Array(12));
    const spy = vi.spyOn(crypto, "getRandomValues");
    pool.fill(new Uint8Array(8));
    expect(spy).toHaveBeenCalledTimes(1);
    expect(spy.mock.calls[0]![0]).toHaveLength(16);
  });

  it("sends a fill longer than the direct threshold straight to getRandomValues", () => {
    const pool = createEntropyPool(16);
    const spy = vi.spyOn(crypto, "getRandomValues");
    const target = new Uint8Array(POOL_DIRECT_ABOVE + 1);
    pool.fill(target);
    expect(spy).toHaveBeenCalledTimes(1);
    expect(spy.mock.calls[0]![0]).toBe(target);
    expect(target.some((b) => b !== 0)).toBe(true);
  });

  it("chunks a direct fill under the 65536-byte limit", () => {
    const pool = createEntropyPool(16);
    const spy = vi.spyOn(crypto, "getRandomValues");
    pool.fill(new Uint8Array(65536 * 2 + 1));
    expect(spy).toHaveBeenCalledTimes(3);
    expect(spy.mock.calls.map((c) => (c[0] as Uint8Array).length)).toEqual([65536, 65536, 1]);
  });

  it("keeps no copy of what it handed out: the slot is zeroed", () => {
    const spy = vi.spyOn(crypto, "getRandomValues");
    const pool = createEntropyPool(64);
    const out = pool.fill(new Uint8Array(16));
    const inner = spy.mock.calls[0]![0] as Uint8Array;
    expect(out.some((b) => b !== 0)).toBe(true);
    expect(inner.subarray(0, 16)).toEqual(new Uint8Array(16));
    expect(inner.subarray(16).some((b) => b !== 0)).toBe(true);
  });

  it("allocates nothing until the first draw and releases on reset", () => {
    const spy = vi.spyOn(crypto, "getRandomValues");
    const pool = createEntropyPool(64);
    pool.nextUint32();
    const first = spy.mock.calls[0]![0] as Uint8Array;
    pool.reset();
    expect(first.every((b) => b === 0)).toBe(true);
    pool.nextUint32();
    expect(spy).toHaveBeenCalledTimes(2);
    expect(spy.mock.calls[1]![0]).not.toBe(first);
  });

  it("reset(true) refills at once, reset() on the next draw", () => {
    const spy = vi.spyOn(crypto, "getRandomValues");
    const pool = createEntropyPool(64);
    pool.reset();
    expect(spy).not.toHaveBeenCalled();
    pool.reset(true);
    expect(spy).toHaveBeenCalledTimes(1);
    pool.nextUint32();
    expect(spy).toHaveBeenCalledTimes(1);
  });

  it("handles an empty fill without touching the pool", () => {
    const pool = createEntropyPool(16);
    const spy = vi.spyOn(crypto, "getRandomValues");
    expect(pool.fill(new Uint8Array(0))).toHaveLength(0);
    expect(spy).not.toHaveBeenCalled();
  });
});

describe("startup-snapshot hook", () => {
  type Hook = () => void;
  function fakeNode(building: boolean, hooks: Hook[]) {
    const v8 = {
      startupSnapshot: {
        isBuildingSnapshot: () => building,
        addDeserializeCallback: (cb: Hook) => {
          hooks.push(cb);
        },
      },
    };
    return vi
      .spyOn(process, "getBuiltinModule")
      .mockImplementation(((id: string) => (id === "node:v8" ? v8 : undefined)) as never);
  }

  it("registers a reset while a snapshot is being built, and the restore refills", () => {
    const hooks: Hook[] = [];
    fakeNode(true, hooks);
    const pool = createEntropyPool(16);
    expect(hooks).toHaveLength(1);
    const spy = vi.spyOn(crypto, "getRandomValues");
    pool.nextUint32();
    hooks[0]!();
    pool.nextUint32();
    expect(spy).toHaveBeenCalledTimes(2);
  });

  it("registers nothing outside a snapshot build", () => {
    const hooks: Hook[] = [];
    fakeNode(false, hooks);
    createEntropyPool(16);
    expect(hooks).toHaveLength(0);
  });

  it("survives a runtime whose process has no getBuiltinModule", () => {
    vi.spyOn(process, "getBuiltinModule").mockImplementation((() => {
      throw new Error("not here");
    }) as never);
    expect(() => createEntropyPool(16).nextUint32()).not.toThrow();
  });
});

describe("sharedPool", () => {
  it(`is ${SHARED_POOL_BYTES} bytes per refill`, () => {
    sharedPool.nextUint32();
    const spy = vi.spyOn(crypto, "getRandomValues");
    for (let i = 0; i < SHARED_POOL_BYTES / 4 + 1; i++) sharedPool.nextUint32();
    expect(spy).toHaveBeenCalledTimes(1);
    expect(spy.mock.calls[0]![0]).toHaveLength(SHARED_POOL_BYTES);
  });

  it("serves 256 uuidv4() per getRandomValues call", () => {
    uuidv4();
    const spy = vi.spyOn(crypto, "getRandomValues");
    for (let i = 0; i < 256; i++) uuidv4();
    expect(spy).toHaveBeenCalledTimes(1);
  });

  it("is shared by uuid, random bytes and random numbers", () => {
    uuidv4();
    const spy = vi.spyOn(crypto, "getRandomValues");
    // 16 + 10 + 32 + 4 = 62 bytes, comfortably one refill.
    uuidv4();
    uuidv7();
    secureRandomBytes(32);
    secureRandomNumber(10);
    expect(spy.mock.calls.length).toBeLessThanOrEqual(1);
  });

  it("keeps secureRandomBytes past the threshold on the direct path", () => {
    const spy = vi.spyOn(crypto, "getRandomValues");
    const bytes = secureRandomBytes(POOL_DIRECT_ABOVE + 1);
    expect(spy).toHaveBeenCalledTimes(1);
    expect(spy.mock.calls[0]![0]).toBe(bytes);
  });

  it("yields unique UUIDs across many refills", () => {
    const seen = new Set<string>();
    for (let i = 0; i < 5000; i++) seen.add(uuidv4());
    expect(seen.size).toBe(5000);
  });
});
