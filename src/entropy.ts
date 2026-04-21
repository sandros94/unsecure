export interface EntropyResult {
  /**
   * Total Shannon (unigram) entropy of the input in bits.
   */
  bits: number;
  /**
   * Shannon (unigram) entropy per symbol — character for strings, byte for Uint8Array.
   */
  bitsPerSymbol: number;
  /**
   * Number of symbols analyzed.
   */
  symbolCount: number;
  /**
   * Number of unique symbols found.
   */
  uniqueSymbols: number;
  /**
   * Maximum possible bits per symbol for the observed alphabet size: `log2(uniqueSymbols)`.
   * Useful to compare against `bitsPerSymbol` to gauge distribution uniformity.
   */
  maxBitsPerSymbol: number;
  /**
   * Total Shannon entropy over adjacent-pair (bigram) frequencies, in bits.
   *
   * Equals `H_bigram * (symbolCount - 1)` where `H_bigram` is the per-bigram
   * Shannon entropy. Catches order structure that the unigram entropy misses
   * — a sorted string like `"abcdefgh"` has maximum `bitsPerSymbol` but low
   * `bigramBitsPerSymbol` compared to a truly random string of the same
   * alphabet.
   *
   * `0` when `symbolCount < 2`.
   */
  bigramBits: number;
  /**
   * `bigramBits / symbolCount`. Units match `bitsPerSymbol` for easy
   * side-by-side reads.
   *
   * Interpretation is length-sensitive. The per-bigram entropy is bounded
   * above by `log2(min(symbolCount - 1, k²))` where `k = uniqueSymbols`:
   *
   * - Short / moderate inputs (`symbolCount - 1 < k²`) are sample-limited:
   *   the ceiling is `log2(symbolCount - 1)`, and random input approaches
   *   this ceiling.
   * - Very long inputs (`symbolCount - 1 >> k²`) are alphabet-limited: the
   *   ceiling approaches `2 * bitsPerSymbol` for an independent source.
   *
   * Structured inputs stay meaningfully below the applicable ceiling
   * (sequential, alternating, and blocked patterns have far fewer unique
   * bigrams than random noise). Rather than comparing against a fixed
   * threshold, compare the metric to a known-random control of the same
   * length — or pair it with `longestRun` for short inputs where
   * finite-sample effects dominate this metric.
   */
  bigramBitsPerSymbol: number;
  /**
   * Length of the longest strictly monotonic run — the maximum count of
   * consecutive symbols whose pairwise comparisons all move in the same
   * direction (ascending or descending).
   *
   * A single symbol or all-equal input yields `1`. An empty input yields `0`.
   * A fully sorted `"abcdefgh"` yields `8`; its reverse yields `8` as well.
   */
  longestRun: number;
  /**
   * Direction of the longest monotonic run. `"none"` when the input has no
   * strict-inequality pair (empty, single-symbol, all-equal), or when the
   * longest ascending and descending runs are tied in length.
   */
  monotonicDirection: "ascending" | "descending" | "none";
}

/**
 * Compute Shannon entropy of the given data, plus bigram entropy and
 * monotonic-run detection.
 *
 * For strings, analysis is per Unicode code point (handles emoji, CJK, etc.).
 * For `Uint8Array`, analysis is per byte value (0–255).
 *
 * The unigram-entropy fields (`bits`, `bitsPerSymbol`, …) measure only
 * frequency distribution and are blind to symbol order — they rate
 * `"abcdefgh"` as having maximum entropy for its alphabet even though it's
 * deterministic. The extra fields compensate:
 *
 * - `bigramBitsPerSymbol` picks up local structure (a truly random source
 *   over alphabet size `k` tends toward `~2 * log2(k)` per symbol on long
 *   inputs; sequential and alternating patterns stay well below that).
 * - `longestRun` catches sorted and reverse-sorted runs directly, and is
 *   reliable even on short inputs.
 *
 * @param data The input to analyze.
 * @returns An {@link EntropyResult} with unigram, bigram, and run metrics.
 *
 * @example
 * // Measure a generated token
 * const token = secureGenerate({ length: 32 });
 * const result = entropy(token);
 * console.log(result.bits); // ~150+ bits for a strong token
 *
 * @example
 * // Detect a weak secret — low unigram entropy
 * entropy("aaaaaaa").bitsPerSymbol; // 0
 *
 * @example
 * // Detect a sorted-alphabet "fake"
 * const e = entropy("abcdefghijklmnop");
 * e.bitsPerSymbol;        // 4 (maximum for 16 unique chars)
 * e.longestRun;           // 16
 * e.monotonicDirection;   // "ascending"
 * e.bigramBitsPerSymbol;  // ~3.7 — noticeably below 2 * 4 = 8 for random
 *
 * @example
 * // Analyze random bytes
 * const bytes = secureRandomBytes(256);
 * entropy(bytes).bitsPerSymbol; // ~7.9+ (close to max of 8 for 256 byte values)
 */
export function entropy(data: string | Uint8Array | null | undefined): EntropyResult {
  if (!data || data.length === 0) {
    return {
      bits: 0,
      bitsPerSymbol: 0,
      symbolCount: 0,
      uniqueSymbols: 0,
      maxBitsPerSymbol: 0,
      bigramBits: 0,
      bigramBitsPerSymbol: 0,
      longestRun: 0,
      monotonicDirection: "none",
    };
  }

  const frequencies = new Map<number, number>();
  const bigramFreq = new Map<number, number>();

  let symbolCount = 0;
  let longestAsc = 1;
  let longestDesc = 1;
  let currentAsc = 1;
  let currentDesc = 1;
  let prev = -1;
  let havePrev = false;

  // Monotonic-run update is shared across both input paths. The bigram key
  // is computed inline per branch so each path uses the fastest encoding:
  // - Bytes fit in 16 bits, so `(p << 8) | c` stays in int32 range and is
  //   cheaper than multiplication.
  // - Code points go up to 0x10FFFF (21 bits), which overflows bitwise ops;
  //   `p * 2^21 + c` produces a unique key in ≤ 42 bits, well within
  //   `Number.MAX_SAFE_INTEGER` (53).
  const observeMonotonic = (p: number, c: number): void => {
    if (c > p) {
      currentAsc++;
      currentDesc = 1;
    } else if (c < p) {
      currentDesc++;
      currentAsc = 1;
    } else {
      currentAsc = 1;
      currentDesc = 1;
    }
    if (currentAsc > longestAsc) longestAsc = currentAsc;
    if (currentDesc > longestDesc) longestDesc = currentDesc;
  };

  if (typeof data === "string") {
    for (const char of data) {
      const cp = char.codePointAt(0)!;
      frequencies.set(cp, (frequencies.get(cp) ?? 0) + 1);
      symbolCount++;
      if (havePrev) {
        const key = prev * 0x200000 + cp;
        bigramFreq.set(key, (bigramFreq.get(key) ?? 0) + 1);
        observeMonotonic(prev, cp);
      }
      prev = cp;
      havePrev = true;
    }
  } else {
    symbolCount = data.length;
    for (let i = 0; i < data.length; i++) {
      const b = data[i]!;
      frequencies.set(b, (frequencies.get(b) ?? 0) + 1);
      if (havePrev) {
        const key = (prev << 8) | b;
        bigramFreq.set(key, (bigramFreq.get(key) ?? 0) + 1);
        observeMonotonic(prev, b);
      }
      prev = b;
      havePrev = true;
    }
  }

  // Unigram Shannon entropy.
  let bitsPerSymbol = 0;
  for (const count of frequencies.values()) {
    const p = count / symbolCount;
    bitsPerSymbol -= p * Math.log2(p);
  }
  const uniqueSymbols = frequencies.size;

  // Bigram Shannon entropy. Normalized per-symbol (total bits / symbolCount)
  // to match the units of `bitsPerSymbol` for ergonomic side-by-side reads.
  const bigramCount = symbolCount - 1;
  let bigramPerBigram = 0;
  if (bigramCount > 0) {
    for (const count of bigramFreq.values()) {
      const p = count / bigramCount;
      bigramPerBigram -= p * Math.log2(p);
    }
  }
  const bigramBits = bigramPerBigram * bigramCount;
  const bigramBitsPerSymbol = bigramBits / symbolCount;

  // Monotonic-run summary. Direction is "none" if there was no strict
  // inequality (single-symbol or all-equal) or if the two run lengths tie.
  const longestRun = longestAsc > longestDesc ? longestAsc : longestDesc;
  let monotonicDirection: "ascending" | "descending" | "none";
  if (longestAsc === longestDesc) {
    monotonicDirection = "none";
  } else if (longestAsc > longestDesc) {
    monotonicDirection = "ascending";
  } else {
    monotonicDirection = "descending";
  }

  return {
    bits: bitsPerSymbol * symbolCount,
    bitsPerSymbol,
    symbolCount,
    uniqueSymbols,
    maxBitsPerSymbol: uniqueSymbols > 1 ? Math.log2(uniqueSymbols) : 0,
    bigramBits,
    bigramBitsPerSymbol,
    longestRun,
    monotonicDirection,
  };
}
