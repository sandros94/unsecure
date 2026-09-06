import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { expectUnsecureError } from "./_helpers.ts";
import {
  createSecureRandomGenerator,
  secureRandomBytes,
  secureRandomNumber,
  secureShuffle,
  randomJitter,
} from "../src/random.ts";

describe.concurrent("Random-based Functions", () => {
  describe("secureRandomNumber(max)", () => {
    it("should return a number within the range [0, max) and be an integer", () => {
      const max = 100;
      const iterations = 1000; // Run multiple times to increase confidence

      for (let i = 0; i < iterations; i++) {
        const num = secureRandomNumber(max);
        expect(num).toBeTypeOf("number");
        expect(num).toBeGreaterThanOrEqual(0);
        expect(num).toBeLessThan(max);
        expect(Number.isInteger(num)).toBe(true);
      }
    });

    it("should return 0 when max is 1", () => {
      expect(secureRandomNumber(1)).toBe(0);
    });

    it("should handle max values up to 2**32", () => {
      const max = 2 ** 32; // 4294967296
      const iterations = 100; // Fewer iterations due to large max

      // This will generate numbers in [0, 2**32 - 1]
      for (let i = 0; i < iterations; i++) {
        const num = secureRandomNumber(max);
        expect(num).toBeGreaterThanOrEqual(0);
        expect(num).toBeLessThan(max);
        expect(Number.isInteger(num)).toBe(true);
      }
    });

    it("should exhibit a reasonable distribution (spot check)", () => {
      const max = 10;
      const iterations = 1000;
      const counts: Record<number, number> = {};
      for (let i = 0; i < max; i++) {
        counts[i] = 0;
      }

      for (let i = 0; i < iterations; i++) {
        const num = secureRandomNumber(max);
        if (num >= 0 && num < max && Number.isInteger(num)) {
          counts[num]!++;
        } else {
          // Fail test if number is out of expected range/type for this specific distribution test
          throw new Error(`Generated number ${num} is invalid for max=${max}`);
        }
      }

      // Check if all numbers in the range [0, max-1] were generated at least once
      for (let i = 0; i < max; i++) {
        expect(counts[i]).toBeGreaterThan(0);
      }
    });

    it("should throw RangeError when max is 0 or negative", () => {
      expect(() => secureRandomNumber(0)).toThrow(RangeError);
      expect(() => secureRandomNumber(0)).toThrow(
        "SecureRandomGenerator.next: max must be greater than min.",
      );
      expect(() => secureRandomNumber(-5)).toThrow(RangeError);
    });

    it("should throw RangeError when max is not an integer", () => {
      const max = 3.14;
      expect(() => secureRandomNumber(max)).toThrow(RangeError);
      expect(() => secureRandomNumber(max)).toThrow(
        "SecureRandomGenerator.next: min and max must be integers.",
      );
    });

    it("should throw RangeError when range is greater than 2**32", () => {
      const max = 2 ** 32 + 1;
      expect(() => secureRandomNumber(max)).toThrow(RangeError);
      expect(() => secureRandomNumber(max)).toThrow(
        "SecureRandomGenerator.next: range must be less than or equal to 2^32.",
      );
    });
  });

  describe("secureRandomNumber(min, max)", () => {
    it("should return a number within the range [min, max) and be an integer", () => {
      const min = 50;
      const max = 150;
      const iterations = 1000;

      for (let i = 0; i < iterations; i++) {
        const num = secureRandomNumber(min, max);
        expect(num).toBeTypeOf("number");
        expect(num).toBeGreaterThanOrEqual(min);
        expect(num).toBeLessThan(max);
        expect(Number.isInteger(num)).toBe(true);
      }
    });

    it("should return min when range is 1", () => {
      expect(secureRandomNumber(5, 6)).toBe(5);
    });

    it("should handle negative ranges", () => {
      const min = -100;
      const max = -50;
      const iterations = 100;

      for (let i = 0; i < iterations; i++) {
        const num = secureRandomNumber(min, max);
        expect(num).toBeGreaterThanOrEqual(min);
        expect(num).toBeLessThan(max);
        expect(Number.isInteger(num)).toBe(true);
      }
    });

    it("should handle ranges spanning zero", () => {
      const min = -50;
      const max = 50;
      const iterations = 1000;

      for (let i = 0; i < iterations; i++) {
        const num = secureRandomNumber(min, max);
        expect(num).toBeGreaterThanOrEqual(min);
        expect(num).toBeLessThan(max);
        expect(Number.isInteger(num)).toBe(true);
      }
    });

    it("should throw RangeError when max <= min", () => {
      expect(() => secureRandomNumber(10, 10)).toThrow(RangeError);
      expect(() => secureRandomNumber(10, 10)).toThrow(
        "SecureRandomGenerator.next: max must be greater than min.",
      );
      expect(() => secureRandomNumber(10, 5)).toThrow(RangeError);
    });

    it("should throw RangeError when min or max are not integers", () => {
      expect(() => secureRandomNumber(1.5, 10)).toThrow(RangeError);
      expect(() => secureRandomNumber(1, 10.5)).toThrow(RangeError);
      expect(() => secureRandomNumber(1.5, 10.5)).toThrow(
        "SecureRandomGenerator.next: min and max must be integers.",
      );
    });

    it("should throw RangeError when range exceeds 2**32", () => {
      const min = 0;
      const max = 2 ** 32 + 1;
      expect(() => secureRandomNumber(min, max)).toThrow(RangeError);
      expect(() => secureRandomNumber(min, max)).toThrow(
        "SecureRandomGenerator.next: range must be less than or equal to 2^32.",
      );
    });
  });

  describe("secureRandomNumber with ignore parameter", () => {
    it("should exclude values in ignore array", () => {
      const iterations = 100;
      const ignore = [5, 7, 9];

      for (let i = 0; i < iterations; i++) {
        const num = secureRandomNumber(10, ignore);
        expect(ignore).not.toContain(num);
        expect(num).toBeGreaterThanOrEqual(0);
        expect(num).toBeLessThan(10);
      }
    });

    it("should exclude values in ignore Set", () => {
      const iterations = 100;
      const ignore = new Set([5, 7, 9]);

      for (let i = 0; i < iterations; i++) {
        const num = secureRandomNumber(10, ignore);
        expect(ignore.has(num)).toBe(false);
        expect(num).toBeGreaterThanOrEqual(0);
        expect(num).toBeLessThan(10);
      }
    });

    it("should work with min/max and ignore array", () => {
      const iterations = 100;
      const ignore = [55, 57, 59];

      for (let i = 0; i < iterations; i++) {
        const num = secureRandomNumber(50, 60, ignore);
        expect(ignore).not.toContain(num);
        expect(num).toBeGreaterThanOrEqual(50);
        expect(num).toBeLessThan(60);
      }
    });

    it("should throw RangeError when ignore excludes all values in range", () => {
      const ignore = [0, 1, 2, 3, 4];
      expect(() => secureRandomNumber(5, ignore)).toThrow(RangeError);
      expect(() => secureRandomNumber(5, ignore)).toThrow(
        "SecureRandomGenerator.next: ignore set excludes all possible values in the range.",
      );
    });

    it("should throw TypeError for invalid ignore parameter", () => {
      expect(() => secureRandomNumber(10, "invalid" as any)).toThrow(TypeError);
      expect(() => secureRandomNumber(10, "invalid" as any)).toThrow(
        "SecureRandomGenerator.next: ignore must be an iterable of numbers or a Set<number>.",
      );
    });

    it("should ignore non-integer values in ignore set", () => {
      const iterations = 100;
      const ignore = new Set([1.5, 2.7, 3]);

      for (let i = 0; i < iterations; i++) {
        const num = secureRandomNumber(10, ignore);
        // Only integer 3 should be excluded
        expect(num).not.toBe(3);
        expect(num).toBeGreaterThanOrEqual(0);
        expect(num).toBeLessThan(10);
        expect(Number.isInteger(num)).toBe(true);
      }
    });
  });

  describe("createSecureRandomGenerator", () => {
    it("should generate numbers in range [0, max) using next(max)", () => {
      const gen = createSecureRandomGenerator();
      const max = 100;
      const iterations = 1000;

      for (let i = 0; i < iterations; i++) {
        const num = gen.next(max);
        expect(num).toBeGreaterThanOrEqual(0);
        expect(num).toBeLessThan(max);
        expect(Number.isInteger(num)).toBe(true);
      }
    });

    it("should generate numbers in range [min, max) using next(min, max)", () => {
      const gen = createSecureRandomGenerator();
      const min = 50;
      const max = 150;
      const iterations = 1000;

      for (let i = 0; i < iterations; i++) {
        const num = gen.next(min, max);
        expect(num).toBeGreaterThanOrEqual(min);
        expect(num).toBeLessThan(max);
        expect(Number.isInteger(num)).toBe(true);
      }
    });

    it("should respect ignore parameter with next(max, ignore)", () => {
      const gen = createSecureRandomGenerator();
      const ignore = new Set([3, 5, 7]);
      const iterations = 100;

      for (let i = 0; i < iterations; i++) {
        const num = gen.next(10, ignore);
        expect(ignore.has(num)).toBe(false);
        expect(num).toBeGreaterThanOrEqual(0);
        expect(num).toBeLessThan(10);
      }
    });

    it("should respect ignore parameter with next(min, max, ignore)", () => {
      const gen = createSecureRandomGenerator();
      const ignore = [53, 55, 57];
      const iterations = 100;

      for (let i = 0; i < iterations; i++) {
        const num = gen.next(50, 60, ignore);
        expect(ignore).not.toContain(num);
        expect(num).toBeGreaterThanOrEqual(50);
        expect(num).toBeLessThan(60);
      }
    });

    it("should throw RangeError when max <= min", () => {
      const gen = createSecureRandomGenerator();
      expect(() => gen.next(10, 10)).toThrow(RangeError);
      expect(() => gen.next(10, 5)).toThrow(
        "SecureRandomGenerator.next: max must be greater than min.",
      );
    });

    it("should throw RangeError when ignore excludes all values", () => {
      const gen = createSecureRandomGenerator();
      const ignore = new Set([0, 1, 2, 3, 4]);
      expect(() => gen.next(5, ignore)).toThrow(RangeError);
      expect(() => gen.next(5, ignore)).toThrow(
        "SecureRandomGenerator.next: ignore set excludes all possible values in the range.",
      );
    });

    it("should throw RangeError when min or max are not integers", () => {
      const gen = createSecureRandomGenerator();
      expect(() => gen.next(1.5, 10)).toThrow(RangeError);
      expect(() => gen.next(1.5, 10)).toThrow(
        "SecureRandomGenerator.next: min and max must be integers.",
      );
    });

    it("should throw RangeError when range exceeds 2**32", () => {
      const gen = createSecureRandomGenerator();
      expect(() => gen.next(0, 2 ** 32 + 1)).toThrow(RangeError);
      expect(() => gen.next(0, 2 ** 32 + 1)).toThrow(
        "SecureRandomGenerator.next: range must be less than or equal to 2^32.",
      );
    });

    it("should throw TypeError for invalid ignore parameter", () => {
      const gen = createSecureRandomGenerator();
      expect(() => gen.next(10, "invalid" as any)).toThrow(TypeError);
      expect(() => gen.next(10, "invalid" as any)).toThrow(
        "SecureRandomGenerator.next: ignore must be an iterable of numbers or a Set<number>.",
      );
    });

    it("should reuse buffer efficiently for multiple calls", () => {
      const gen = createSecureRandomGenerator();
      const results = [];
      // Generate more than buffer size (256) to ensure refill happens
      for (let i = 0; i < 500; i++) {
        results.push(gen.next(1000));
      }
      expect(results.length).toBe(500);
      // All should be valid numbers
      for (const num of results) {
        expect(num).toBeGreaterThanOrEqual(0);
        expect(num).toBeLessThan(1000);
      }
    });
  });

  describe("secureRandomBytes(length)", () => {
    it("should return a Uint8Array of the requested length", () => {
      const bytes = secureRandomBytes(32);
      expect(bytes).toBeInstanceOf(Uint8Array);
      expect(bytes.length).toBe(32);
    });

    it("should return an ArrayBuffer-backed Uint8Array", () => {
      const bytes = secureRandomBytes(32);
      expect(bytes.buffer).toBeInstanceOf(ArrayBuffer);
    });

    it("should return an empty Uint8Array for length 0", () => {
      const bytes = secureRandomBytes(0);
      expect(bytes).toBeInstanceOf(Uint8Array);
      expect(bytes.length).toBe(0);
    });

    it("should produce different output on successive calls", () => {
      const a = secureRandomBytes(32);
      const b = secureRandomBytes(32);
      // Extremely unlikely to be equal
      expect(a).not.toEqual(b);
    });

    it("should handle lengths larger than the 65536-byte getRandomValues limit", () => {
      // Every chunk is checked over a wide slice: a one-byte tail is all-zero
      // once in 256 draws, which would make this test fail at random rather
      // than when a chunk is genuinely left unfilled.
      const length = 3 * 65_536 + 5000;
      const bytes = secureRandomBytes(length);
      expect(bytes.length).toBe(length);
      for (let offset = 0; offset < length; offset += 65_536) {
        const chunk = bytes.subarray(offset, Math.min(offset + 65_536, length));
        expect(chunk.some((b) => b !== 0)).toBe(true);
      }
    });

    it("should throw RangeError for negative length", () => {
      expectUnsecureError(() => secureRandomBytes(-1), "OUT_OF_RANGE");
      expect(() => secureRandomBytes(-1)).toThrow(
        "secureRandomBytes: length must be an integer between 0 and 2147483647, got -1.",
      );
    });

    it("should throw RangeError for non-integer length", () => {
      expectUnsecureError(() => secureRandomBytes(3.14), "OUT_OF_RANGE");
      expect(() => secureRandomBytes(3.14)).toThrow(
        "secureRandomBytes: length must be an integer between 0 and 2147483647, got 3.14.",
      );
    });

    it("should throw RangeError above the 2**31 - 1 ceiling", () => {
      expectUnsecureError(() => secureRandomBytes(2 ** 31), "OUT_OF_RANGE");
      expect(() => secureRandomBytes(2 ** 31)).toThrow(
        "secureRandomBytes: length must be an integer between 0 and 2147483647, got 2147483648.",
      );
    });
  });

  describe("secureShuffle(array)", () => {
    it("should return the same array instance (in-place shuffle)", () => {
      const array = [1, 2, 3];
      expect(secureShuffle(array)).toBe(array);
    });

    it("should preserve array length and all original elements", () => {
      const originalArray = [5, 1, 4, 2, 3, 3, "a", { id: 1 }];
      const arrayCopy = [...originalArray];
      secureShuffle(arrayCopy);

      expect(arrayCopy.length).toBe(originalArray.length);

      // Check element counts for comparison.
      // eslint-disable-next-line unicorn/no-array-reduce
      const originalCounts = originalArray.reduce(
        (acc, val) => {
          acc[JSON.stringify(val)] = (acc[JSON.stringify(val)] || 0) + 1;
          return acc;
        },
        {} as Record<string, number>,
      );
      // eslint-disable-next-line unicorn/no-array-reduce
      const shuffledCounts = arrayCopy.reduce(
        (acc, val) => {
          acc[JSON.stringify(val)] = (acc[JSON.stringify(val)] || 0) + 1;
          return acc;
        },
        {} as Record<string, number>,
      );
      expect(shuffledCounts).toEqual(originalCounts);
    });

    it("should handle an empty array", () => {
      const emptyArray: unknown[] = [];
      secureShuffle(emptyArray);
      expect(emptyArray).toEqual([]);
    });

    it("should handle an array with a single element", () => {
      const singleElementArray = [{ id: "test" }];
      secureShuffle(singleElementArray);
      expect(singleElementArray).toEqual([{ id: "test" }]);
    });

    it("should correctly shuffle arrays with various data types and duplicates", () => {
      const originalArray = [1, "a", { id: 1 }, "a", 2, 1, { id: 2 }, { id: 1 }];
      const arrayCopy = [...originalArray];
      secureShuffle(arrayCopy);

      expect(arrayCopy.length).toBe(originalArray.length);
      // Verify all original elements are present in the shuffled array
      for (const item of originalArray) expect(arrayCopy).toContain(item);
      // Verify all shuffled elements were in the original array
      for (const item of arrayCopy) expect(originalArray).toContain(item);
    });
  });
});

describe("randomJitter", () => {
  /** Capture the delays a run of calls hands to `setTimeout`. */
  function delaysOf(call: () => void, runs: number): number[] {
    const delays: number[] = [];
    const spy = vi.spyOn(globalThis, "setTimeout").mockImplementation(((
      _fn: () => void,
      ms?: number,
    ) => {
      delays.push(ms as number);
      return 0 as unknown as ReturnType<typeof setTimeout>;
    }) as typeof setTimeout);
    try {
      for (let i = 0; i < runs; i++) call();
    } finally {
      spy.mockRestore();
    }
    return delays;
  }

  /** Every captured delay sits in `[min, max)`, and the draw actually varies. */
  function assertDrawnWithin(delays: number[], min: number, max: number): void {
    expect(delays.every((ms) => Number.isInteger(ms))).toBe(true);
    expect(Math.min(...delays)).toBeGreaterThanOrEqual(min);
    expect(Math.max(...delays)).toBeLessThan(max);
    // A constant delay would satisfy the bounds; the draw must actually vary.
    expect(new Set(delays).size).toBeGreaterThan(1);
  }

  it("defaults to [0, 100)", () => {
    const delays = delaysOf(() => void randomJitter(), 500);
    expect(delays).toHaveLength(500);
    assertDrawnWithin(delays, 0, 100);
  });

  it("uses [0, maxMs) for the one-argument form", () => {
    const delays = delaysOf(() => void randomJitter(50), 500);
    expect(delays).toHaveLength(500);
    assertDrawnWithin(delays, 0, 50);
  });

  it("uses [minMs, maxMs) for the two-argument form", () => {
    const delays = delaysOf(() => void randomJitter(50, 100), 500);
    expect(delays).toHaveLength(500);
    assertDrawnWithin(delays, 50, 100);
  });

  it("reads an undefined minMs as no lower bound, not as the one-argument form", () => {
    const delays = delaysOf(() => void randomJitter(undefined, 50), 500);
    expect(delays).toHaveLength(500);
    assertDrawnWithin(delays, 0, 50);
  });

  it("returns minMs exactly when maxMs equals minMs", () => {
    expect(delaysOf(() => void randomJitter(42, 42), 3)).toEqual([42, 42, 42]);
  });

  it("returns 0 when maxMs is 1", () => {
    expect(delaysOf(() => void randomJitter(1), 3)).toEqual([0, 0, 0]);
  });

  describe("timing", () => {
    beforeEach(() => {
      vi.useFakeTimers();
    });
    afterEach(() => {
      vi.useRealTimers();
    });

    it("resolves only after the delay has elapsed", async () => {
      const promise = randomJitter(42, 42);
      vi.advanceTimersByTime(41);
      await expect(Promise.race([promise, Promise.resolve("pending")])).resolves.toBe("pending");
      vi.advanceTimersByTime(1);
      await expect(promise).resolves.toBeUndefined();
    });

    it("draws no randomness when the range is empty", async () => {
      const spy = vi.spyOn(crypto, "getRandomValues");
      const promise = randomJitter(30, 30);
      vi.advanceTimersByTime(30);
      await expect(promise).resolves.toBeUndefined();
      expect(spy).not.toHaveBeenCalled();
      spy.mockRestore();
    });
  });

  describe("input validation", () => {
    it("throws RangeError when maxMs < minMs", () => {
      expect(() => randomJitter(100, 50)).toThrow(RangeError);
      expect(() => randomJitter(100, 50)).toThrow(
        "randomJitter: maxMs must be an integer >= minMs (100), got 50.",
      );
    });

    it("throws RangeError when minMs is negative", () => {
      expect(() => randomJitter(-1, 10)).toThrow(
        "randomJitter: minMs must be an integer >= 0, got -1.",
      );
      expectUnsecureError(() => randomJitter(-1), "OUT_OF_RANGE");
    });

    it("throws RangeError when maxMs is negative (single-arg form)", () => {
      expect(() => randomJitter(-5)).toThrow(
        "randomJitter: maxMs must be an integer >= 0, got -5.",
      );
    });

    it("throws RangeError for a null bound instead of taking the default", () => {
      expect(() => randomJitter(null as any)).toThrow(
        "randomJitter: maxMs must be an integer >= 0, got null.",
      );
      expect(() => randomJitter(null as any, 50)).toThrow(
        "randomJitter: minMs must be an integer >= 0, got null.",
      );
      expect(() => randomJitter(0, null as any)).toThrow(
        "randomJitter: maxMs must be an integer >= 0, got null.",
      );
    });

    it("throws RangeError when minMs or maxMs is non-finite", () => {
      expectUnsecureError(() => randomJitter(Number.NaN), "OUT_OF_RANGE");
      expectUnsecureError(() => randomJitter(Number.POSITIVE_INFINITY), "OUT_OF_RANGE");
      expectUnsecureError(() => randomJitter(0, Number.NaN), "OUT_OF_RANGE");
      expectUnsecureError(() => randomJitter(0, Number.POSITIVE_INFINITY), "OUT_OF_RANGE");
    });

    it("throws RangeError on fractional milliseconds", () => {
      // setTimeout truncates, so a fractional bound never described the delay.
      expect(() => randomJitter(1.5)).toThrow(
        "randomJitter: maxMs must be an integer >= 0, got 1.5.",
      );
      expect(() => randomJitter(0.5, 10)).toThrow(
        "randomJitter: minMs must be an integer >= 0, got 0.5.",
      );
    });
  });
});

describe("secureRandomNumber uniformity", () => {
  it("stays uniform across 300 000 draws over 3 buckets", () => {
    const draws = 300_000;
    const counts = [0, 0, 0];
    for (let i = 0; i < draws; i++) counts[secureRandomNumber(3)]!++;

    expect(counts[0]! + counts[1]! + counts[2]!).toBe(draws);
    // Expected 100 000 each; sigma is ~258, so 2000 is ~7.7 sigma.
    for (const count of counts) {
      expect(Math.abs(count - draws / 3)).toBeLessThan(2000);
    }
  });
});
