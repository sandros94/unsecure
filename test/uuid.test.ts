import { afterEach, describe, expect, it, vi } from "vitest";
import {
  createUUIDv7Generator,
  isUUIDv4,
  isUUIDv7,
  secureUUID,
  uuidv4,
  uuidv7,
  uuidv7Timestamp,
} from "../src/uuid.ts";

const CANONICAL = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

// Helper: verify version and variant nibble positions in the canonical string.
function versionNibble(uuid: string): string {
  return uuid[14]!;
}
function variantNibble(uuid: string): string {
  return uuid[19]!;
}

afterEach(() => {
  vi.restoreAllMocks();
});

describe.concurrent("uuidv4", () => {
  it("produces canonical lowercase format", () => {
    const u = uuidv4();
    expect(u).toMatch(CANONICAL);
  });

  it("sets version 4", () => {
    for (let i = 0; i < 50; i++) {
      expect(versionNibble(uuidv4())).toBe("4");
    }
  });

  it("sets RFC variant (8, 9, a, or b)", () => {
    for (let i = 0; i < 50; i++) {
      expect(["8", "9", "a", "b"]).toContain(variantNibble(uuidv4()));
    }
  });

  it("produces unique values", () => {
    const seen = new Set<string>();
    for (let i = 0; i < 1000; i++) seen.add(uuidv4());
    expect(seen.size).toBe(1000);
  });
});

describe.concurrent("uuidv7", () => {
  it("produces canonical lowercase format", () => {
    expect(uuidv7()).toMatch(CANONICAL);
  });

  it("sets version 7", () => {
    for (let i = 0; i < 50; i++) {
      expect(versionNibble(uuidv7())).toBe("7");
    }
  });

  it("sets RFC variant", () => {
    for (let i = 0; i < 50; i++) {
      expect(["8", "9", "a", "b"]).toContain(variantNibble(uuidv7()));
    }
  });

  it("embeds the current Unix-ms timestamp", () => {
    const before = Date.now();
    const u = uuidv7();
    const after = Date.now();
    const ts = uuidv7Timestamp(u);
    expect(ts).toBeGreaterThanOrEqual(before);
    expect(ts).toBeLessThanOrEqual(after);
  });

  it("round-trips a mocked timestamp exactly", () => {
    const fixed = 1_742_195_712_345;
    vi.spyOn(Date, "now").mockReturnValue(fixed);
    expect(uuidv7Timestamp(uuidv7())).toBe(fixed);
  });

  it("sorts older-before-newer across millisecond boundaries", () => {
    const spy = vi.spyOn(Date, "now");
    spy.mockReturnValue(1_000_000_000_000);
    const older = uuidv7();
    spy.mockReturnValue(1_000_000_000_001);
    const newer = uuidv7();
    expect(older < newer).toBe(true);
  });

  it("produces unique values under rapid calls", () => {
    const seen = new Set<string>();
    for (let i = 0; i < 1000; i++) seen.add(uuidv7());
    expect(seen.size).toBe(1000);
  });

  it("accepts a Date argument", () => {
    const d = new Date("2020-01-01T00:00:00.000Z");
    expect(uuidv7Timestamp(uuidv7(d))).toBe(d.getTime());
  });

  it("accepts a numeric ms argument", () => {
    const ms = 1_234_567_890_123;
    expect(uuidv7Timestamp(uuidv7(ms))).toBe(ms);
  });

  it("floors fractional numeric timestamps", () => {
    expect(uuidv7Timestamp(uuidv7(1_000.9))).toBe(1_000);
  });

  it("supports the max 48-bit timestamp", () => {
    expect(uuidv7Timestamp(uuidv7(0xffffffffffff))).toBe(0xffffffffffff);
  });

  it("accepts timestamp 0 (Unix epoch)", () => {
    expect(uuidv7Timestamp(uuidv7(0))).toBe(0);
  });

  it("throws RangeError on negative, NaN, Infinity, or out-of-range ms", () => {
    expect(() => uuidv7(-1)).toThrow(RangeError);
    expect(() => uuidv7(Number.NaN)).toThrow(RangeError);
    expect(() => uuidv7(Number.POSITIVE_INFINITY)).toThrow(RangeError);
    expect(() => uuidv7(0xffffffffffff + 1)).toThrow(RangeError);
  });

  it("throws RangeError on an Invalid Date", () => {
    expect(() => uuidv7(new Date("totally invalid"))).toThrow(RangeError);
  });

  it("throws TypeError on non-Date / non-number arguments", () => {
    expect(() => uuidv7("2020-01-01" as any)).toThrow(TypeError);
    expect(() => uuidv7({} as any)).toThrow(TypeError);
    expect(() => uuidv7(null as any)).toThrow(TypeError);
  });
});

describe.concurrent("secureUUID", () => {
  it("is an alias of uuidv7", () => {
    expect(secureUUID).toBe(uuidv7);
    expect(versionNibble(secureUUID())).toBe("7");
  });
});

describe("createUUIDv7Generator", () => {
  it("next() returns canonical v7 UUIDs", () => {
    const gen = createUUIDv7Generator();
    for (let i = 0; i < 20; i++) {
      const u = gen.next();
      expect(u).toMatch(CANONICAL);
      expect(versionNibble(u)).toBe("7");
      expect(["8", "9", "a", "b"]).toContain(variantNibble(u));
    }
  });

  it("is strictly monotonic within the same millisecond", () => {
    vi.spyOn(Date, "now").mockReturnValue(1_000_000_000_000);
    const gen = createUUIDv7Generator();
    const ids: string[] = [];
    for (let i = 0; i < 1000; i++) ids.push(gen.next());
    // Lexicographic comparison on canonical hex reflects numeric byte order.
    for (let i = 1; i < ids.length; i++) {
      expect(ids[i]! > ids[i - 1]!).toBe(true);
    }
  });

  it("is strictly monotonic across a clock regression", () => {
    const spy = vi.spyOn(Date, "now");
    spy.mockReturnValue(1_000_000_000_100);
    const gen = createUUIDv7Generator();
    const a = gen.next();
    // Clock moves backward (NTP jump).
    spy.mockReturnValue(1_000_000_000_050);
    const b = gen.next();
    const c = gen.next();
    expect(b > a).toBe(true);
    expect(c > b).toBe(true);
  });

  it("advances the timestamp by 1 ms when the counter overflows", () => {
    vi.spyOn(Date, "now").mockReturnValue(1_000_000_000_000);
    const gen = createUUIDv7Generator();
    // Generate enough IDs to be sure the 12-bit counter (seeded in [0, 0x7ff])
    // overflows — 4096 calls is always more than enough.
    const ids: string[] = [];
    for (let i = 0; i < 4096; i++) ids.push(gen.next());

    // All IDs must be strictly monotonic even after overflow.
    for (let i = 1; i < ids.length; i++) {
      expect(ids[i]! > ids[i - 1]!).toBe(true);
    }

    // After overflow the stored timestamp has advanced past the mocked clock,
    // so the last UUID's embedded ts is >= the mock + 1 (at least one overflow).
    const last = uuidv7Timestamp(ids[ids.length - 1]!);
    expect(last).toBeGreaterThanOrEqual(1_000_000_000_001);
  });

  it("accepts a Date or number argument and embeds it verbatim", () => {
    const gen = createUUIDv7Generator();
    const d = new Date("2020-01-01T00:00:00.000Z");
    const u1 = gen.next(d);
    expect(uuidv7Timestamp(u1)).toBe(d.getTime());
    const u2 = gen.next(d.getTime() + 5);
    expect(uuidv7Timestamp(u2)).toBe(d.getTime() + 5);
  });

  it("honors past timestamps verbatim (dual-clock: user ts does not drive counter state)", () => {
    vi.spyOn(Date, "now").mockReturnValue(1_000_000_000_000);
    const gen = createUUIDv7Generator();
    const a = gen.next(1_000_000_000_100);
    const b = gen.next(1_000_000_000_050); // supplied ts is in the past

    // Embedded ts reflects caller intent, not the previous UUID's ts.
    expect(uuidv7Timestamp(a)).toBe(1_000_000_000_100);
    expect(uuidv7Timestamp(b)).toBe(1_000_000_000_050);

    // UUIDs are unique, and within the same Date.now() ms the counter
    // progresses sequentially regardless of the supplied timestamps.
    expect(a).not.toBe(b);
    const counterA = Number.parseInt(a.slice(15, 18), 16);
    const counterB = Number.parseInt(b.slice(15, 18), 16);
    expect(counterB).toBe(counterA + 1);
  });

  it("keeps counter monotonic when no-arg and user-ts calls are interleaved", () => {
    vi.spyOn(Date, "now").mockReturnValue(1_000_000_000_000);
    const gen = createUUIDv7Generator();
    const counters: number[] = [];
    counters.push(Number.parseInt(gen.next().slice(15, 18), 16));
    counters.push(Number.parseInt(gen.next(1_000_000_000_050).slice(15, 18), 16));
    counters.push(Number.parseInt(gen.next().slice(15, 18), 16));
    counters.push(Number.parseInt(gen.next(2_000_000_000_000).slice(15, 18), 16));
    // Each subsequent call in the same Date.now() ms has counter + 1.
    for (let i = 1; i < counters.length; i++) {
      expect(counters[i]).toBe(counters[i - 1]! + 1);
    }
  });

  it("validates the timestamp argument like uuidv7()", () => {
    const gen = createUUIDv7Generator();
    expect(() => gen.next(-1)).toThrow(RangeError);
    expect(() => gen.next(Number.NaN)).toThrow(RangeError);
    expect(() => gen.next(new Date("invalid"))).toThrow(RangeError);
    expect(() => gen.next("now" as any)).toThrow(TypeError);
  });

  it("does not consume counter state when .next() throws on invalid input", () => {
    vi.spyOn(Date, "now").mockReturnValue(1_000_000_000_000);
    const gen = createUUIDv7Generator();
    const before = gen.next();
    const beforeCounter = Number.parseInt(before.slice(15, 18), 16);

    expect(() => gen.next(-1)).toThrow(RangeError);
    expect(() => gen.next(Number.NaN)).toThrow(RangeError);
    expect(() => gen.next("oops" as any)).toThrow(TypeError);

    const after = gen.next();
    const afterCounter = Number.parseInt(after.slice(15, 18), 16);
    // Only two successful calls happened, so the counter advanced exactly
    // once between them — not once per failed call in between.
    expect(afterCounter).toBe(beforeCounter + 1);
  });

  it("reseeds the counter on a fresh millisecond", () => {
    // Two generators sampled at the same clock tick should not always land
    // on identical rand_a (counter) nibbles, because the seed is random.
    // Probability two random seeds collide across 2048 values is ~1/2048,
    // so across 10 generator pairs it's effectively zero.
    vi.spyOn(Date, "now").mockReturnValue(1_000_000_000_000);
    const seeds = new Set<string>();
    for (let i = 0; i < 10; i++) {
      seeds.add(createUUIDv7Generator().next().slice(14, 18));
    }
    expect(seeds.size).toBeGreaterThan(1);
  });
});

describe.concurrent("uuidv7Timestamp", () => {
  it("extracts a known 48-bit timestamp", () => {
    // Hand-crafted UUID: ts = 0x00000000ffff → 65535
    const uuid = "00000000-ffff-7000-8000-000000000000";
    expect(uuidv7Timestamp(uuid)).toBe(0xffff);
  });

  it("supports max-representable 48-bit timestamp", () => {
    const uuid = "ffffffff-ffff-7000-8000-000000000000";
    expect(uuidv7Timestamp(uuid)).toBe(0xffffffffffff);
  });

  it("is case-insensitive on the hex alphabet", () => {
    const uuid = "00000000-FFFF-7000-8000-000000000000";
    expect(uuidv7Timestamp(uuid)).toBe(0xffff);
  });

  it("throws TypeError for non-v7 UUIDs", () => {
    expect(() => uuidv7Timestamp(uuidv4())).toThrow(TypeError);
  });

  it("throws TypeError for malformed input", () => {
    expect(() => uuidv7Timestamp("not-a-uuid")).toThrow(TypeError);
    expect(() => uuidv7Timestamp("")).toThrow(TypeError);
    expect(() => uuidv7Timestamp(undefined as any)).toThrow(TypeError);
  });
});

describe.concurrent("isUUIDv4", () => {
  it("accepts valid UUIDv4", () => {
    expect(isUUIDv4(uuidv4())).toBe(true);
    expect(isUUIDv4("00000000-0000-4000-8000-000000000000")).toBe(true);
    expect(isUUIDv4("00000000-0000-4000-b000-000000000000")).toBe(true);
  });

  it("accepts uppercase canonical form", () => {
    expect(isUUIDv4(uuidv4().toUpperCase())).toBe(true);
  });

  it("rejects UUIDv7", () => {
    expect(isUUIDv4(uuidv7())).toBe(false);
  });

  it("rejects wrong variant", () => {
    expect(isUUIDv4("00000000-0000-4000-0000-000000000000")).toBe(false);
    expect(isUUIDv4("00000000-0000-4000-4000-000000000000")).toBe(false);
    expect(isUUIDv4("00000000-0000-4000-c000-000000000000")).toBe(false);
    expect(isUUIDv4("00000000-0000-4000-f000-000000000000")).toBe(false);
  });

  it("rejects malformed strings", () => {
    expect(isUUIDv4("")).toBe(false);
    expect(isUUIDv4("not-a-uuid")).toBe(false);
    expect(isUUIDv4("00000000-0000-4000-8000-00000000000")).toBe(false);
    expect(isUUIDv4("gggggggg-0000-4000-8000-000000000000")).toBe(false);
  });

  it("rejects non-string values", () => {
    expect(isUUIDv4(123)).toBe(false);
    expect(isUUIDv4(null)).toBe(false);
    expect(isUUIDv4(undefined)).toBe(false);
    expect(isUUIDv4({})).toBe(false);
  });
});

describe.concurrent("isUUIDv7", () => {
  it("accepts valid UUIDv7", () => {
    expect(isUUIDv7(uuidv7())).toBe(true);
    expect(isUUIDv7("00000000-0000-7000-8000-000000000000")).toBe(true);
    expect(isUUIDv7("00000000-0000-7000-b000-000000000000")).toBe(true);
  });

  it("accepts uppercase canonical form", () => {
    const u = uuidv7().toUpperCase();
    expect(isUUIDv7(u)).toBe(true);
  });

  it("rejects UUIDv4", () => {
    expect(isUUIDv7(uuidv4())).toBe(false);
  });

  it("rejects wrong variant", () => {
    // Variant nibble 0 / 4 / c / f all violate the 10xx pattern.
    expect(isUUIDv7("00000000-0000-7000-0000-000000000000")).toBe(false);
    expect(isUUIDv7("00000000-0000-7000-4000-000000000000")).toBe(false);
    expect(isUUIDv7("00000000-0000-7000-c000-000000000000")).toBe(false);
    expect(isUUIDv7("00000000-0000-7000-f000-000000000000")).toBe(false);
  });

  it("rejects malformed strings", () => {
    expect(isUUIDv7("")).toBe(false);
    expect(isUUIDv7("not-a-uuid")).toBe(false);
    expect(isUUIDv7("00000000-0000-7000-8000-00000000000")).toBe(false); // too short
    expect(isUUIDv7("00000000-0000-7000-8000-0000000000000")).toBe(false); // too long
    expect(isUUIDv7("gggggggg-0000-7000-8000-000000000000")).toBe(false); // non-hex
  });

  it("rejects non-string values", () => {
    expect(isUUIDv7(123)).toBe(false);
    expect(isUUIDv7(null)).toBe(false);
    expect(isUUIDv7(undefined)).toBe(false);
    expect(isUUIDv7({})).toBe(false);
  });
});
