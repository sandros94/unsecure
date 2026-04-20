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
      expect(result.bigramBits).toBe(0);
      expect(result.bigramBitsPerSymbol).toBe(0);
      expect(result.longestRun).toBe(0);
      expect(result.monotonicDirection).toBe("none");
    });

    it("should return all zeros for an empty Uint8Array", () => {
      const result = entropy(new Uint8Array(0));
      expect(result.bits).toBe(0);
      expect(result.bitsPerSymbol).toBe(0);
      expect(result.symbolCount).toBe(0);
      expect(result.uniqueSymbols).toBe(0);
      expect(result.maxBitsPerSymbol).toBe(0);
      expect(result.bigramBits).toBe(0);
      expect(result.bigramBitsPerSymbol).toBe(0);
      expect(result.longestRun).toBe(0);
      expect(result.monotonicDirection).toBe("none");
    });

    it("should return 0 entropy for a single character", () => {
      const result = entropy("x");
      expect(result.bits).toBe(0);
      expect(result.bitsPerSymbol).toBe(0);
      expect(result.symbolCount).toBe(1);
      expect(result.uniqueSymbols).toBe(1);
      expect(result.maxBitsPerSymbol).toBe(0);
      expect(result.bigramBits).toBe(0);
      expect(result.bigramBitsPerSymbol).toBe(0);
      expect(result.longestRun).toBe(1);
      expect(result.monotonicDirection).toBe("none");
    });

    it("should return 0 entropy for a single byte", () => {
      const result = entropy(new Uint8Array([42]));
      expect(result.bits).toBe(0);
      expect(result.bitsPerSymbol).toBe(0);
      expect(result.symbolCount).toBe(1);
      expect(result.uniqueSymbols).toBe(1);
      expect(result.maxBitsPerSymbol).toBe(0);
      expect(result.longestRun).toBe(1);
      expect(result.monotonicDirection).toBe("none");
    });

    it("should report longestRun=1 and direction=none for all-equal input", () => {
      const result = entropy("aaaa");
      expect(result.longestRun).toBe(1);
      expect(result.monotonicDirection).toBe("none");
      // All bigrams identical → zero bigram entropy.
      expect(result.bigramBits).toBe(0);
      expect(result.bigramBitsPerSymbol).toBe(0);
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

  describe("bigram entropy", () => {
    it("should equal 0 when every adjacent pair is identical", () => {
      const result = entropy("aaaaaa");
      expect(result.bigramBits).toBe(0);
      expect(result.bigramBitsPerSymbol).toBe(0);
    });

    it("should be well below 2 * bitsPerSymbol for sequential input", () => {
      const seq = entropy("abcdefgh");
      // Unigram: 8 unique, bitsPerSymbol = log2(8) = 3. For an independent
      // uniform source, bigramBitsPerSymbol would trend toward ~2 * 3 = 6.
      // Sequential input produces 7 unique single-occurrence bigrams:
      // bigramBitsPerSymbol ≈ log2(7) * 7 / 8 ≈ 2.46.
      expect(seq.bitsPerSymbol).toBeCloseTo(3, 10);
      expect(seq.bigramBitsPerSymbol).toBeCloseTo((Math.log2(7) * 7) / 8, 10);
      expect(seq.bigramBitsPerSymbol).toBeLessThan(2 * seq.bitsPerSymbol);
    });

    it("should match the unigram-derived expectation for perfectly alternating input", () => {
      const alt = entropy("abababab");
      // Bigrams: ab (×4), ba (×3). H_per_bigram = entropy of {4/7, 3/7}.
      const p1 = 4 / 7;
      const p2 = 3 / 7;
      const hPerBigram = -(p1 * Math.log2(p1)) - p2 * Math.log2(p2);
      expect(alt.bigramBits).toBeCloseTo(hPerBigram * 7, 10);
      expect(alt.bigramBitsPerSymbol).toBeCloseTo((hPerBigram * 7) / 8, 10);
    });

    it("should handle Uint8Array input the same way as strings", () => {
      // Sequential bytes.
      const seq = entropy(new Uint8Array([0, 1, 2, 3, 4, 5, 6, 7]));
      expect(seq.bigramBitsPerSymbol).toBeCloseTo((Math.log2(7) * 7) / 8, 10);
    });

    it("should approach its finite-sample ceiling for random input", () => {
      // 4KB of random bytes. With n=4096 samples over 256² = 65536 possible
      // bigrams, the per-bigram ceiling is log2(n-1) ≈ 12, not
      // 2 * bitsPerSymbol ≈ 16 (which would only apply for n >> 65536).
      const bytes = new Uint8Array(4096);
      crypto.getRandomValues(bytes);
      const result = entropy(bytes);
      const bigramCount = result.symbolCount - 1;
      const perBigram = result.bigramBits / bigramCount;
      const sampleCeiling = Math.log2(bigramCount);
      // Random input should land within ~1 bit of the finite-sample ceiling.
      expect(perBigram).toBeGreaterThan(sampleCeiling - 1);
      expect(perBigram).toBeLessThanOrEqual(sampleCeiling);
    });

    it("should be noticeably lower for repeating sequential input than random", () => {
      // When a sequential pattern repeats (n >> k), bigram entropy collapses
      // to log2(k) — only k distinct "next-char" transitions exist. Random
      // input over the same alphabet visits ~k² distinct bigrams and
      // reaches a much higher entropy.
      const alphabet = "abcdef"; // k=6, so sequential caps at log2(6) ≈ 2.58
      const seqStr = alphabet.repeat(100); // 600 chars, repeating sequential
      const randArr: string[] = [];
      const rnd = new Uint8Array(600);
      crypto.getRandomValues(rnd);
      for (let i = 0; i < 600; i++) randArr.push(alphabet[rnd[i]! % alphabet.length]!);
      const randStr = randArr.join("");

      const seq = entropy(seqStr);
      const rand = entropy(randStr);
      // Both have the same unigram entropy (≈ log2(6)); bigram entropy
      // should diverge by at least 1.5 bits per symbol.
      expect(rand.bigramBitsPerSymbol - seq.bigramBitsPerSymbol).toBeGreaterThan(1.5);
    });
  });

  describe("monotonic run detection", () => {
    it("should flag a strictly ascending alphabet", () => {
      const result = entropy("abcdefghijklmnop");
      expect(result.longestRun).toBe(16);
      expect(result.monotonicDirection).toBe("ascending");
      // Unigram entropy is maximum for its alphabet despite zero randomness.
      expect(result.bitsPerSymbol).toBeCloseTo(4, 10);
    });

    it("should flag a strictly descending alphabet", () => {
      const result = entropy("ponmlkjihgfedcba");
      expect(result.longestRun).toBe(16);
      expect(result.monotonicDirection).toBe("descending");
    });

    it("should report length 2 for a two-symbol ascending pair", () => {
      const result = entropy("ab");
      expect(result.longestRun).toBe(2);
      expect(result.monotonicDirection).toBe("ascending");
    });

    it("should report length 2 for a two-symbol descending pair", () => {
      const result = entropy("ba");
      expect(result.longestRun).toBe(2);
      expect(result.monotonicDirection).toBe("descending");
    });

    it("should report direction=none when ascending and descending runs tie", () => {
      // "abba": asc run of length 2 (ab), desc run of length 2 (ba).
      const result = entropy("abba");
      expect(result.longestRun).toBe(2);
      expect(result.monotonicDirection).toBe("none");
    });

    it("should reset the current run on an equal-pair", () => {
      // "aabbccdd": no strict run ever exceeds length 2.
      const result = entropy("aabbccdd");
      expect(result.longestRun).toBe(2);
    });

    it("should detect the longest run inside a mixed string", () => {
      // First 5 chars ascend strictly, then reset; longestRun should be 5.
      const result = entropy("abcde_zzzz");
      expect(result.longestRun).toBe(5);
      expect(result.monotonicDirection).toBe("ascending");
    });

    it("should work on Uint8Array input", () => {
      const asc = entropy(new Uint8Array([0, 1, 2, 3, 4, 5, 6, 7]));
      expect(asc.longestRun).toBe(8);
      expect(asc.monotonicDirection).toBe("ascending");

      const desc = entropy(new Uint8Array([7, 6, 5, 4, 3, 2, 1, 0]));
      expect(desc.longestRun).toBe(8);
      expect(desc.monotonicDirection).toBe("descending");
    });

    it("should handle multi-byte code points as whole symbols when ordering", () => {
      // 👋 (U+1F44B) > 🎉 (U+1F389) > 'b' (U+0062) > 'a' (U+0061) — strict descending.
      const result = entropy("👋🎉ba");
      expect(result.longestRun).toBe(4);
      expect(result.monotonicDirection).toBe("descending");
    });

    it("should stay small for well-shuffled random strings", () => {
      // Truly random 1024-byte buffer; longest monotonic run is almost
      // certainly short. Probability of a run of length ≥ 10 in a random
      // 256-alphabet sequence is astronomically low.
      const bytes = new Uint8Array(1024);
      crypto.getRandomValues(bytes);
      const result = entropy(bytes);
      expect(result.longestRun).toBeLessThan(10);
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
