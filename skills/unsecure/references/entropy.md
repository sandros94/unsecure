# entropy()

Shannon entropy analysis plus structural signals (bigram entropy, monotonic-run detection) for measuring randomness quality of strings or byte arrays.

## Signature

```ts
function entropy(data: string | Uint8Array | null | undefined): EntropyResult;

interface EntropyResult {
  // Unigram (standard Shannon) — blind to symbol order.
  bits: number; // Total Shannon entropy in bits
  bitsPerSymbol: number; // Entropy per character/byte
  symbolCount: number; // Total symbols analyzed
  uniqueSymbols: number; // Distinct symbols found
  maxBitsPerSymbol: number; // log2(uniqueSymbols), theoretical max

  // Bigram entropy — picks up local structure (sequential, alternating, blocked).
  bigramBits: number; // Total entropy over adjacent-pair frequencies
  bigramBitsPerSymbol: number; // Same scale as bitsPerSymbol

  // Monotonic-run detection — targets sorted / reverse-sorted sequences.
  longestRun: number; // Length of longest strictly-monotonic run
  monotonicDirection: "ascending" | "descending" | "none";
}
```

For strings, analysis is per Unicode code point (handles emoji, CJK, etc.). For `Uint8Array`, analysis is per byte value (0–255).

## Why three metrics

Shannon entropy over symbol frequencies is famously blind to order: `"abcdefghijklmnop"` scores `bitsPerSymbol = 4` (the maximum for 16 unique chars), same as a truly random 16-char string over the same alphabet. The two extra fields compensate:

- **`longestRun` + `monotonicDirection`** catch sorted and reverse-sorted runs directly. `"abcdefghijklmnop"` → `longestRun: 16, monotonicDirection: "ascending"`. Works reliably on **any input length**.
- **`bigramBits` / `bigramBitsPerSymbol`** catch more general local structure (sequential, alternating `ababab`, blocked `aaabbbccc`) via the distribution of adjacent pairs. More powerful than the run detector on long inputs; less useful on short ones (see caveat below).

The Shannon (unigram) fields are unchanged from the previous design — this addition is purely additive.

## Examples

```ts
import { entropy } from "unsecure/entropy";

// A generated token — random across all three metrics.
entropy("Zk(p4@L!v9{g~8sB");
// bitsPerSymbol ≈ 4, bigramBitsPerSymbol close to log2(15), longestRun small.

// A sorted-alphabet fake — caught by longestRun
const fake = entropy("abcdefghijklmnop");
fake.bitsPerSymbol; // 4 (maximum for 16 unique chars)
fake.longestRun; // 16
fake.monotonicDirection; // "ascending"
fake.bigramBitsPerSymbol; // ≈ 3.66 — well below 2 * bitsPerSymbol = 8 that a truly random source would approach

// All-equal input — low across the board
entropy("aaaaaaa");
// bitsPerSymbol: 0, bigramBits: 0, longestRun: 1, monotonicDirection: "none"

// Random bytes
const bytes = crypto.getRandomValues(new Uint8Array(256));
entropy(bytes).bitsPerSymbol; // ~7.9+ (close to 8)

// Null/undefined/empty inputs return all zeros gracefully.
entropy(null); // all zeros
entropy(""); // all zeros
```

## Use Case: Password Quality Validation

Combine unigram entropy with a run-length guard to reject sorted-alphabet fakes:

```ts
import { entropy } from "unsecure/entropy";

function passesQualityGate(secret: string, minBits = 60): boolean {
  const r = entropy(secret);
  if (r.bits < minBits) return false;
  // Reject anything with ≥ 5 consecutive monotonic characters (e.g. "12345").
  if (r.longestRun >= 5) return false;
  return true;
}
```

## Use Case: Entropy-Gated Secret Acceptance

```ts
import { entropy } from "unsecure/entropy";

function validateSecretStrength(secret: string): boolean {
  const { bitsPerSymbol, uniqueSymbols, longestRun } = entropy(secret);
  return bitsPerSymbol >= 3.0 && uniqueSymbols >= 10 && longestRun < 4;
}
```

## Interpreting `bigramBitsPerSymbol`

The absolute value is length-sensitive because the per-bigram entropy is capped by `log2(min(symbolCount - 1, k²))`, where `k = uniqueSymbols`:

- **Short/moderate inputs** (`symbolCount - 1 < k²`) are sample-limited. Random input approaches `log2(symbolCount - 1)`; structure shows as values noticeably below that.
- **Very long inputs** (`symbolCount - 1 >> k²`) are alphabet-limited. Random input approaches `2 * bitsPerSymbol`; structure (like `"abcabc…"`) collapses toward `log2(k)` per bigram — far below.

Don't compare against a fixed threshold in isolation. Either compare to a known-random control of the same length, or — for short inputs — rely primarily on `longestRun`.

## Pitfall: Shannon Entropy vs. Cryptographic Strength

Shannon entropy measures information density of the **observed** data, not cryptographic security of the generator that produced it. A keyboard-pattern password like `"Qwerty123!@#"` can score highly on unigram entropy yet be trivially guessable. Use `entropy()` as a heuristic quality check, not a security guarantee — and always pair it with `longestRun` / `bigramBitsPerSymbol` when the input is short enough for a single pattern to dominate.
