import { describe, it, expect } from "vitest";
import {
  secureRandomNumber,
  secureShuffle,
  base64Decode,
  base64Encode,
  base64UrlDecode,
  base64UrlEncode,
  hexDecode,
  hexEncode,
} from "../src/utils";

describe.concurrent("Utility Functions", () => {
  describe("secureRandomNumber(max)", () => {
    it("should return a number within the range [0, max] and be an integer", () => {
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

    it("should throw RangeError when max is 0", () => {
      expect(() => secureRandomNumber(0)).toThrow(RangeError);
      expect(() => secureRandomNumber(0)).toThrow(
        "max must be a positive integer.",
      );
    });

    it("should throw RangeError when max is negative", () => {
      const max = -5;
      expect(() => secureRandomNumber(max)).toThrow(RangeError);
      expect(() => secureRandomNumber(max)).toThrow(
        "max must be a positive integer.",
      );
    });

    it("should throw RangeError when max is not an integer", () => {
      const max = 3.14;
      expect(() => secureRandomNumber(max)).toThrow(RangeError);
      expect(() => secureRandomNumber(max)).toThrow(
        "max must be a positive integer.",
      );
    });

    it("should throw RangeError when max is greater than 2**32", () => {
      const max = 2 ** 32 + 1;
      expect(() => secureRandomNumber(max)).toThrow(RangeError);
      expect(() => secureRandomNumber(max)).toThrow(
        "max must be less than or equal to 2^32.",
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
      const originalArray = [
        1,
        "a",
        { id: 1 },
        "a",
        2,
        1,
        { id: 2 },
        { id: 1 },
      ];
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

    describe("base64Decode(str, toString)", () => {
      const encodedString = b64Encode(testString);

      it("should decode a standard Base64 string to string by default", () => {
        const decoded = base64Decode(encodedString);
        expect(decoded).toBe(testString);
      });

      it("should decode a standard Base64 string to string when toString is true", () => {
        const decoded = base64Decode(encodedString, true);
        expect(decoded).toBe(testString);
      });

      it("should decode a standard Base64 string to Uint8Array when toString is false", () => {
        const decoded = base64Decode(encodedString, false);
        expect(decoded).toEqual(testUint8Array);
      });

      it("should handle empty string input", () => {
        expect(base64Decode("")).toBe("");
        expect(base64Decode("", false)).toEqual(new Uint8Array(0));
      });

      it("should handle undefined input", () => {
        expect(base64Decode(undefined)).toBe("");
        expect(base64Decode(undefined, false)).toEqual(new Uint8Array(0));
      });
    });

    describe("base64UrlDecode(str, toString)", () => {
      const originalBase64 = b64Encode(testString);
      const encodedUrlSafeString = originalBase64
        .replace(/\+/g, "-")
        .replace(/\//g, "_")
        .replace(/=/g, "");

      it("should decode a Base64 URL-safe string to string by default", () => {
        const decoded = base64UrlDecode(encodedUrlSafeString);
        expect(decoded).toBe(testString);
      });

      it("should decode a Base64 URL-safe string to string when toString is true", () => {
        const decoded = base64UrlDecode(encodedUrlSafeString, true);
        expect(decoded).toBe(testString);
      });

      it("should decode a Base64 URL-safe string to Uint8Array when toString is false", () => {
        const decoded = base64UrlDecode(encodedUrlSafeString, false);
        expect(decoded).toEqual(testUint8Array);
      });

      it("should handle empty string input", () => {
        expect(base64UrlDecode("")).toBe("");
        expect(base64UrlDecode("", false)).toEqual(new Uint8Array(0));
      });

      it("should handle undefined input", () => {
        expect(base64UrlDecode(undefined)).toBe("");
        expect(base64UrlDecode(undefined, false)).toEqual(new Uint8Array(0));
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
    const expectedHex = [...testUint8Array]
      .map((x) => x.toString(16).padStart(2, "0"))
      .join("");

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

    describe("hexDecode(str, toString)", () => {
      it("should decode a hex string to string by default", () => {
        const decoded = hexDecode(expectedHex);
        expect(decoded).toBe(testString);
      });

      it("should decode a hex string to string when toString is true", () => {
        const decoded = hexDecode(expectedHex, true);
        expect(decoded).toBe(testString);
      });

      it("should decode a hex string to Uint8Array when toString is false", () => {
        const decoded = hexDecode(expectedHex, false);
        expect(decoded).toEqual(testUint8Array);
      });

      it("should handle empty string input", () => {
        expect(hexDecode("")).toBe("");
        expect(hexDecode("", false)).toEqual(new Uint8Array(0));
      });

      it("should handle undefined input", () => {
        expect(hexDecode(undefined)).toBe("");
        expect(hexDecode(undefined, false)).toEqual(new Uint8Array(0));
      });

      it("should decode hex strings with mixed case characters", () => {
        const mixedCaseHex = "48656c6c6f"; // "Hello"
        const expected = "Hello";
        expect(hexDecode(mixedCaseHex)).toBe(expected);
        expect(hexDecode(mixedCaseHex.toUpperCase())).toBe(expected);
      });

      it("should handle odd length hex strings gracefully", () => {
        // "abc" is split into ["ab", "c"]. "ab" -> 0xab, "c" -> 0x0c.
        const decoded = hexDecode("abc", false);
        expect(decoded).toEqual(Uint8Array.from([0xab, 0x0c]));
      });

      it("should handle invalid hex characters gracefully (results in NaN)", () => {
        // "zz" -> Number.parseInt("zz", 16) is NaN.
        const decoded = hexDecode("zz", false);
        expect(decoded).toEqual(Uint8Array.from([Number.NaN]));
      });
    });
  });
});

function b64Encode(data: string | Uint8Array): string {
  return Buffer.from(data).toString("base64");
}
