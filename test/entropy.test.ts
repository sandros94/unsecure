import { describe, it, expect } from "vitest";
import { entropy } from "../src/entropy.ts";

describe("entropy", () => {
  describe("edge cases", () => {
    it("should return all zeros for an empty string", () => {
      const result = entropy("");
      expect(result.bits).toBe(0);
      expect(result.bitsPerSymbol).toBe(0);
      expect(result.symbolCount).toBe(0);
      expect(result.uniqueSymbols).toBe(0);
      expect(result.maxBitsPerSymbol).toBe(0);
    });

    it("should return all zeros for an empty Uint8Array", () => {
      const result = entropy(new Uint8Array(0));
      expect(result.bits).toBe(0);
      expect(result.bitsPerSymbol).toBe(0);
      expect(result.symbolCount).toBe(0);
      expect(result.uniqueSymbols).toBe(0);
      expect(result.maxBitsPerSymbol).toBe(0);
    });

    it("should return 0 entropy for a single character", () => {
      const result = entropy("x");
      expect(result.bits).toBe(0);
      expect(result.bitsPerSymbol).toBe(0);
      expect(result.symbolCount).toBe(1);
      expect(result.uniqueSymbols).toBe(1);
      expect(result.maxBitsPerSymbol).toBe(0);
    });

    it("should return 0 entropy for a single byte", () => {
      const result = entropy(new Uint8Array([42]));
      expect(result.bits).toBe(0);
      expect(result.bitsPerSymbol).toBe(0);
      expect(result.symbolCount).toBe(1);
      expect(result.uniqueSymbols).toBe(1);
      expect(result.maxBitsPerSymbol).toBe(0);
    });
  });

  describe("string input", () => {
    it("should return 0 bits per symbol for a repeated character", () => {
      const result = entropy("aaaaaaa");
      expect(result.bitsPerSymbol).toBe(0);
      expect(result.bits).toBe(0);
      expect(result.symbolCount).toBe(7);
      expect(result.uniqueSymbols).toBe(1);
    });

    it("should return 1 bit per symbol for two equally distributed characters", () => {
      const result = entropy("abababab");
      expect(result.bitsPerSymbol).toBeCloseTo(1, 10);
      expect(result.bits).toBeCloseTo(8, 10);
      expect(result.symbolCount).toBe(8);
      expect(result.uniqueSymbols).toBe(2);
      expect(result.maxBitsPerSymbol).toBeCloseTo(1, 10);
    });

    it("should return log2(4) for four equally distributed characters", () => {
      const result = entropy("abcdabcdabcd");
      expect(result.bitsPerSymbol).toBeCloseTo(2, 10); // log2(4) = 2
      expect(result.bits).toBeCloseTo(24, 10);
      expect(result.uniqueSymbols).toBe(4);
      expect(result.maxBitsPerSymbol).toBeCloseTo(2, 10);
    });

    it("should have lower entropy when distribution is skewed", () => {
      // 'a' appears 7 times, 'b' appears 1 time → skewed
      const skewed = entropy("aaaaaaab");
      // Perfectly distributed ab would be 1 bit per symbol
      expect(skewed.bitsPerSymbol).toBeLessThan(1);
      expect(skewed.bitsPerSymbol).toBeGreaterThan(0);
      expect(skewed.uniqueSymbols).toBe(2);
    });

    it("should handle Unicode code points correctly", () => {
      // Each emoji is one code point, "ab" are two more
      const result = entropy("👋🎉ab");
      expect(result.symbolCount).toBe(4);
      expect(result.uniqueSymbols).toBe(4);
      expect(result.bitsPerSymbol).toBeCloseTo(2, 10); // log2(4)
    });

    it("should count surrogate pairs as single symbols", () => {
      // 𐀀 is U+10000, encoded as a surrogate pair in UTF-16 but one code point
      const result = entropy("𐀀𐀀𐀀");
      expect(result.symbolCount).toBe(3);
      expect(result.uniqueSymbols).toBe(1);
      expect(result.bitsPerSymbol).toBe(0);
    });

    it("should handle mixed ASCII and multi-byte characters", () => {
      const result = entropy("aAbBcC文字");
      expect(result.symbolCount).toBe(8);
      expect(result.uniqueSymbols).toBe(8);
      expect(result.bitsPerSymbol).toBeCloseTo(3, 10); // log2(8)
    });
  });

  describe("Uint8Array input", () => {
    it("should return 0 entropy for identical bytes", () => {
      const result = entropy(new Uint8Array([0xff, 0xff, 0xff, 0xff]));
      expect(result.bitsPerSymbol).toBe(0);
      expect(result.bits).toBe(0);
      expect(result.symbolCount).toBe(4);
      expect(result.uniqueSymbols).toBe(1);
    });

    it("should return 1 bit per symbol for two equally distributed byte values", () => {
      const result = entropy(new Uint8Array([0, 1, 0, 1, 0, 1]));
      expect(result.bitsPerSymbol).toBeCloseTo(1, 10);
      expect(result.bits).toBeCloseTo(6, 10);
      expect(result.symbolCount).toBe(6);
      expect(result.uniqueSymbols).toBe(2);
    });

    it("should approach 8 bits per symbol for uniformly distributed random bytes", () => {
      // Create a byte array with all 256 possible values equally represented
      const allBytes = new Uint8Array(256);
      for (let i = 0; i < 256; i++) allBytes[i] = i;
      const result = entropy(allBytes);
      expect(result.bitsPerSymbol).toBeCloseTo(8, 10); // log2(256) = 8
      expect(result.bits).toBeCloseTo(2048, 10); // 256 * 8
      expect(result.uniqueSymbols).toBe(256);
      expect(result.maxBitsPerSymbol).toBeCloseTo(8, 10);
    });

    it("should report lower entropy for skewed byte distribution", () => {
      // 15 zeros and 1 one
      const data = new Uint8Array(16);
      data[15] = 1;
      const result = entropy(data);
      expect(result.bitsPerSymbol).toBeLessThan(1);
      expect(result.bitsPerSymbol).toBeGreaterThan(0);
      expect(result.uniqueSymbols).toBe(2);
    });
  });

  describe("real-world scenarios", () => {
    it("should measure high entropy for crypto.getRandomValues output", () => {
      const bytes = new Uint8Array(1024);
      crypto.getRandomValues(bytes);
      const result = entropy(bytes);
      // Random bytes should have close to 8 bits per symbol
      expect(result.bitsPerSymbol).toBeGreaterThan(7.5);
      expect(result.uniqueSymbols).toBeGreaterThan(200);
    });

    it("should detect weak passwords", () => {
      const weak = entropy("password");
      const strong = entropy("p@$$w0rd!Xy7#q");
      // The more varied string should have higher entropy per symbol
      expect(strong.bitsPerSymbol).toBeGreaterThan(weak.bitsPerSymbol);
    });

    it("should differentiate repeated vs varied tokens", () => {
      const repeated = entropy("AAAAAAAAAAAAAAAA");
      const varied = entropy("A1b2C3d4E5f6G7h8");
      expect(repeated.bits).toBe(0);
      expect(varied.bits).toBeGreaterThan(50);
    });
  });
});
