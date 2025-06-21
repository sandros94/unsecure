import { describe, it, expect } from "vitest";
import { secureRandomNumber, secureShuffle } from "../src/utils";

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
});
