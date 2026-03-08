export interface EntropyResult {
  /**
   * Total Shannon entropy of the input in bits.
   */
  bits: number;
  /**
   * Shannon entropy per symbol (character for strings, byte for Uint8Array).
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
}

/**
 * Compute Shannon entropy of the given data.
 *
 * For strings, analysis is per Unicode code point (handles emoji, CJK, etc.).
 * For Uint8Array, analysis is per byte value (0–255).
 *
 * @param data The input to analyze.
 * @returns An {@link EntropyResult} with entropy metrics.
 *
 * @example
 * // Measure a generated token
 * const token = secureGenerate({ length: 32 });
 * const result = entropy(token);
 * console.log(result.bits); // ~150+ bits for a strong token
 *
 * @example
 * // Detect a weak secret
 * entropy("aaaaaaa").bitsPerSymbol; // 0 — completely predictable
 *
 * @example
 * // Analyze random bytes
 * const bytes = new Uint8Array(256);
 * crypto.getRandomValues(bytes);
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
    };
  }

  const frequencies = new Map<number, number>();
  let symbolCount = 0;

  if (typeof data === "string") {
    for (const char of data) {
      const cp = char.codePointAt(0)!;
      frequencies.set(cp, (frequencies.get(cp) ?? 0) + 1);
      symbolCount++;
    }
  } else {
    symbolCount = data.length;
    for (let i = 0; i < data.length; i++) {
      const b = data[i]!;
      frequencies.set(b, (frequencies.get(b) ?? 0) + 1);
    }
  }

  let bitsPerSymbol = 0;
  for (const count of frequencies.values()) {
    const p = count / symbolCount;
    bitsPerSymbol -= p * Math.log2(p);
  }

  const uniqueSymbols = frequencies.size;

  return {
    bits: bitsPerSymbol * symbolCount,
    bitsPerSymbol,
    symbolCount,
    uniqueSymbols,
    maxBitsPerSymbol: uniqueSymbols > 1 ? Math.log2(uniqueSymbols) : 0,
  };
}
