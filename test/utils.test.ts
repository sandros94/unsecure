import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import {
  createSecureRandomGenerator,
  secureRandomNumber,
  secureShuffle,
  base64Decode,
  base64Encode,
  base64UrlDecode,
  base64UrlEncode,
  hexDecode,
  hexEncode,
  randomJitter,
} from "../src/utils.ts";

describe.concurrent("Utility Functions", () => {
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
      expect(() => secureRandomNumber(0)).toThrow("max must be greater than min.");
      expect(() => secureRandomNumber(-5)).toThrow(RangeError);
    });

    it("should throw RangeError when max is not an integer", () => {
      const max = 3.14;
      expect(() => secureRandomNumber(max)).toThrow(RangeError);
      expect(() => secureRandomNumber(max)).toThrow("min and max must be integers.");
    });

    it("should throw RangeError when range is greater than 2**32", () => {
      const max = 2 ** 32 + 1;
      expect(() => secureRandomNumber(max)).toThrow(RangeError);
      expect(() => secureRandomNumber(max)).toThrow("range must be less than or equal to 2^32.");
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
      expect(() => secureRandomNumber(10, 10)).toThrow("max must be greater than min.");
      expect(() => secureRandomNumber(10, 5)).toThrow(RangeError);
    });

    it("should throw RangeError when min or max are not integers", () => {
      expect(() => secureRandomNumber(1.5, 10)).toThrow(RangeError);
      expect(() => secureRandomNumber(1, 10.5)).toThrow(RangeError);
      expect(() => secureRandomNumber(1.5, 10.5)).toThrow("min and max must be integers.");
    });

    it("should throw RangeError when range exceeds 2**32", () => {
      const min = 0;
      const max = 2 ** 32 + 1;
      expect(() => secureRandomNumber(min, max)).toThrow(RangeError);
      expect(() => secureRandomNumber(min, max)).toThrow(
        "range must be less than or equal to 2^32.",
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
        "Ignore set excludes all possible values in the range.",
      );
    });

    it("should throw TypeError for invalid ignore parameter", () => {
      expect(() => secureRandomNumber(10, "invalid" as any)).toThrow(TypeError);
      expect(() => secureRandomNumber(10, "invalid" as any)).toThrow(
        "ignore must be an iterable of numbers or a Set<number>.",
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
      expect(() => gen.next(10, 5)).toThrow("max must be greater than min.");
    });

    it("should throw RangeError when ignore excludes all values", () => {
      const gen = createSecureRandomGenerator();
      const ignore = new Set([0, 1, 2, 3, 4]);
      expect(() => gen.next(5, ignore)).toThrow(RangeError);
      expect(() => gen.next(5, ignore)).toThrow(
        "Ignore set excludes all possible values in the range.",
      );
    });

    it("should throw RangeError when min or max are not integers", () => {
      const gen = createSecureRandomGenerator();
      expect(() => gen.next(1.5, 10)).toThrow(RangeError);
      expect(() => gen.next(1.5, 10)).toThrow("min and max must be integers.");
    });

    it("should throw RangeError when range exceeds 2**32", () => {
      const gen = createSecureRandomGenerator();
      expect(() => gen.next(0, 2 ** 32 + 1)).toThrow(RangeError);
      expect(() => gen.next(0, 2 ** 32 + 1)).toThrow("range must be less than or equal to 2^32.");
    });

    it("should throw TypeError for invalid ignore parameter", () => {
      const gen = createSecureRandomGenerator();
      expect(() => gen.next(10, "invalid" as any)).toThrow(TypeError);
      expect(() => gen.next(10, "invalid" as any)).toThrow(
        "ignore must be an iterable of numbers or a Set<number>.",
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
          acc[String(val)] = (acc[String(val)] || 0) + 1;
          return acc;
        },
        {} as Record<string, number>,
      );
      // eslint-disable-next-line unicorn/no-array-reduce
      const shuffledCounts = arrayCopy.reduce(
        (acc, val) => {
          acc[String(val)] = (acc[String(val)] || 0) + 1;
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

  describe("Base64 Encoding/Decoding", () => {
    const testString =
      "Hello, Vitest! 👋 This is a test string with some special characters: Ā 𐀀 文 +/=";
    const testUint8Array = new TextEncoder().encode(testString);

    describe("base64Encode(data)", () => {
      it("should encode a string to standard Base64", () => {
        const encoded = base64Encode(testString);
        expect(encoded).toBe(b64Encode(testString));
      });

      it("should encode a Uint8Array to standard Base64", () => {
        const encoded = base64Encode(testUint8Array);
        expect(encoded).toBe(b64Encode(testUint8Array));
      });

      it("should handle empty string", () => {
        expect(base64Encode("")).toBe("");
      });
    });

    describe("base64UrlEncode(data)", () => {
      it("should encode a string to Base64 URL-safe", () => {
        const encoded = base64UrlEncode(testString);
        const expected = b64Encode(testString)
          .replace(/\+/g, "-")
          .replace(/\//g, "_")
          .replace(/=/g, "");
        expect(encoded).toBe(expected);
      });

      it("should encode a Uint8Array to Base64 URL-safe", () => {
        const encoded = base64UrlEncode(testUint8Array);
        const expected = b64Encode(testUint8Array)
          .replace(/\+/g, "-")
          .replace(/\//g, "_")
          .replace(/=/g, "");
        expect(encoded).toBe(expected);
      });

      it("should handle empty string", () => {
        expect(base64UrlEncode("")).toBe("");
      });
    });

    describe("base64Decode(data, options)", () => {
      const encodedString = b64Encode(testString);
      const encodedUint8Array = new TextEncoder().encode(encodedString);

      it("should decode a Base64 string to string by default", () => {
        const decoded = base64Decode(encodedString);
        expect(decoded).toBe(testString);
      });

      it("should decode a Base64 string to string with returnAs 'string'", () => {
        const decoded = base64Decode(encodedString, { returnAs: "string" });
        expect(decoded).toBe(testString);
      });

      it("should decode a Base64 string to Uint8Array with returnAs 'uint8array'", () => {
        const decoded = base64Decode(encodedString, { returnAs: "uint8array" });
        expect(decoded).toEqual(testUint8Array);
      });

      it("should decode a Base64 string to Uint8Array with returnAs 'bytes' alias", () => {
        const decoded = base64Decode(encodedString, { returnAs: "bytes" });
        expect(decoded).toEqual(testUint8Array);
      });

      it("should mirror input type: Uint8Array in → Uint8Array out", () => {
        const decoded = base64Decode(encodedUint8Array);
        expect(decoded).toBeInstanceOf(Uint8Array);
        expect(decoded).toEqual(testUint8Array);
      });

      it("should override mirroring with explicit returnAs", () => {
        const decoded = base64Decode(encodedUint8Array, { returnAs: "string" });
        expect(decoded).toBe(testString);
      });

      it("should handle empty string input", () => {
        expect(base64Decode("")).toBe("");
        expect(base64Decode("", { returnAs: "uint8array" })).toEqual(new Uint8Array(0));
      });

      it("should handle undefined input", () => {
        expect(base64Decode(undefined)).toBe("");
      });
    });

    describe("base64UrlDecode(data, options)", () => {
      const originalBase64 = b64Encode(testString);
      const encodedUrlSafeString = originalBase64
        .replace(/\+/g, "-")
        .replace(/\//g, "_")
        .replace(/=/g, "");
      const encodedUrlSafeUint8Array = new TextEncoder().encode(encodedUrlSafeString);

      it("should decode a Base64 URL-safe string to string by default", () => {
        const decoded = base64UrlDecode(encodedUrlSafeString);
        expect(decoded).toBe(testString);
      });

      it("should decode a Base64 URL-safe string to string with returnAs 'string'", () => {
        const decoded = base64UrlDecode(encodedUrlSafeString, { returnAs: "string" });
        expect(decoded).toBe(testString);
      });

      it("should decode a Base64 URL-safe string to Uint8Array with returnAs 'uint8array'", () => {
        const decoded = base64UrlDecode(encodedUrlSafeString, { returnAs: "uint8array" });
        expect(decoded).toEqual(testUint8Array);
      });

      it("should decode a Base64 URL-safe string to Uint8Array with returnAs 'bytes' alias", () => {
        const decoded = base64UrlDecode(encodedUrlSafeString, { returnAs: "bytes" });
        expect(decoded).toEqual(testUint8Array);
      });

      it("should mirror input type: Uint8Array in → Uint8Array out", () => {
        const decoded = base64UrlDecode(encodedUrlSafeUint8Array);
        expect(decoded).toBeInstanceOf(Uint8Array);
        expect(decoded).toEqual(testUint8Array);
      });

      it("should override mirroring with explicit returnAs", () => {
        const decoded = base64UrlDecode(encodedUrlSafeUint8Array, { returnAs: "string" });
        expect(decoded).toBe(testString);
      });

      it("should handle empty string input", () => {
        expect(base64UrlDecode("")).toBe("");
        expect(base64UrlDecode("", { returnAs: "uint8array" })).toEqual(new Uint8Array(0));
      });

      it("should handle undefined input", () => {
        expect(base64UrlDecode(undefined)).toBe("");
      });

      it("should correctly pad and decode URL-safe strings without padding", () => {
        expect(base64UrlDecode("")).toBe("");
        expect(base64UrlDecode("Zg")).toBe("f");
        expect(base64UrlDecode("Zm8")).toBe("fo");
        expect(base64UrlDecode("Zm9v")).toBe("foo");
        expect(base64UrlDecode("Zm9vYg")).toBe("foob");
        expect(base64UrlDecode("Zm9vYmE")).toBe("fooba");
        expect(base64UrlDecode("Zm9vYmFy")).toBe("foobar");
      });
    });
  });

  describe("Hex Encoding/Decoding", () => {
    const testString =
      "Hello, Vitest! 👋 This is a test string with some special characters: Ā 𐀀 文 +/=";
    const testUint8Array = new TextEncoder().encode(testString);
    const expectedHex = [...testUint8Array].map((x) => x.toString(16).padStart(2, "0")).join("");

    describe("hexEncode(data)", () => {
      it("should encode a string to hex", () => {
        const encoded = hexEncode(testString);
        expect(encoded).toBe(expectedHex);
      });

      it("should encode a Uint8Array to hex", () => {
        const encoded = hexEncode(testUint8Array);
        expect(encoded).toBe(expectedHex);
      });

      it("should handle empty string", () => {
        expect(hexEncode("")).toBe("");
      });
    });

    describe("hexDecode(data, options)", () => {
      const encodedHexUint8Array = new TextEncoder().encode(expectedHex);

      it("should decode a hex string to string by default", () => {
        const decoded = hexDecode(expectedHex);
        expect(decoded).toBe(testString);
      });

      it("should decode a hex string to string with returnAs 'string'", () => {
        const decoded = hexDecode(expectedHex, { returnAs: "string" });
        expect(decoded).toBe(testString);
      });

      it("should decode a hex string to Uint8Array with returnAs 'uint8array'", () => {
        const decoded = hexDecode(expectedHex, { returnAs: "uint8array" });
        expect(decoded).toEqual(testUint8Array);
      });

      it("should decode a hex string to Uint8Array with returnAs 'bytes' alias", () => {
        const decoded = hexDecode(expectedHex, { returnAs: "bytes" });
        expect(decoded).toEqual(testUint8Array);
      });

      it("should mirror input type: Uint8Array in → Uint8Array out", () => {
        const decoded = hexDecode(encodedHexUint8Array);
        expect(decoded).toBeInstanceOf(Uint8Array);
        expect(decoded).toEqual(testUint8Array);
      });

      it("should override mirroring with explicit returnAs", () => {
        const decoded = hexDecode(encodedHexUint8Array, { returnAs: "string" });
        expect(decoded).toBe(testString);
      });

      it("should handle empty string input", () => {
        expect(hexDecode("")).toBe("");
        expect(hexDecode("", { returnAs: "uint8array" })).toEqual(new Uint8Array(0));
      });

      it("should handle undefined input", () => {
        expect(hexDecode(undefined)).toBe("");
      });

      it("should decode hex strings with mixed case characters", () => {
        const mixedCaseHex = "48656c6c6f"; // "Hello"
        const expected = "Hello";
        expect(hexDecode(mixedCaseHex)).toBe(expected);
        expect(hexDecode(mixedCaseHex.toUpperCase())).toBe(expected);
      });

      it("should handle odd length hex strings gracefully", () => {
        // Only complete byte pairs are decoded; trailing nibble is ignored.
        const decoded = hexDecode("abc", { returnAs: "uint8array" });
        expect(decoded).toEqual(Uint8Array.from([0xab]));
      });

      it("should handle invalid hex characters gracefully", () => {
        // Invalid hex characters result in an empty buffer.
        const decoded = hexDecode("zz", { returnAs: "uint8array" });
        expect(decoded).toEqual(new Uint8Array(0));
      });
    });
  });
});

describe("randomJitter", () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });
  afterEach(() => {
    vi.useRealTimers();
  });

  it("should resolve after a random delay within default range", async () => {
    const spy = vi.spyOn(crypto, "getRandomValues").mockImplementation((arr) => {
      (arr as Uint32Array)[0] = 42;
      return arr;
    });

    const promise = randomJitter();
    // 42 % 100 = 42ms
    vi.advanceTimersByTime(41);
    await expect(Promise.race([promise, Promise.resolve("pending")])).resolves.toBe("pending");
    vi.advanceTimersByTime(1);
    await expect(promise).resolves.toBeUndefined();

    spy.mockRestore();
  });

  it("should respect custom maxMs", async () => {
    const spy = vi.spyOn(crypto, "getRandomValues").mockImplementation((arr) => {
      (arr as Uint32Array)[0] = 250;
      return arr;
    });

    const promise = randomJitter(50);
    // 250 % 50 = 0ms
    vi.advanceTimersByTime(0);
    await expect(promise).resolves.toBeUndefined();

    spy.mockRestore();
  });

  it("should handle maxMs of 1 (always 0ms delay)", async () => {
    const promise = randomJitter(1);
    vi.advanceTimersByTime(0);
    await expect(promise).resolves.toBeUndefined();
  });

  it("should respect minMs and maxMs range", async () => {
    const spy = vi.spyOn(crypto, "getRandomValues").mockImplementation((arr) => {
      (arr as Uint32Array)[0] = 7;
      return arr;
    });

    const promise = randomJitter(50, 100);
    // min=50, range=50, 7 % 50 = 7, delay = 50 + 7 = 57ms
    vi.advanceTimersByTime(56);
    await expect(Promise.race([promise, Promise.resolve("pending")])).resolves.toBe("pending");
    vi.advanceTimersByTime(1);
    await expect(promise).resolves.toBeUndefined();

    spy.mockRestore();
  });

  it("should resolve with minMs delay when range is 1", async () => {
    const promise = randomJitter(30, 31);
    // range=1, any value % 1 = 0, delay = 30 + 0 = 30ms
    vi.advanceTimersByTime(29);
    await expect(Promise.race([promise, Promise.resolve("pending")])).resolves.toBe("pending");
    vi.advanceTimersByTime(1);
    await expect(promise).resolves.toBeUndefined();
  });
});

function b64Encode(data: string | Uint8Array): string {
  return Buffer.from(data).toString("base64");
}
