# entropy()

Shannon entropy analysis for measuring randomness quality of strings or byte arrays.

## Signature

```ts
function entropy(data: string | Uint8Array | null | undefined): EntropyResult;

interface EntropyResult {
  bits: number; // Total Shannon entropy in bits
  bitsPerSymbol: number; // Entropy per character/byte
  symbolCount: number; // Total symbols analyzed
  uniqueSymbols: number; // Distinct symbols found
  maxBitsPerSymbol: number; // log2(uniqueSymbols), theoretical max
}
```

For strings, analysis is per Unicode code point (handles emoji, CJK, etc.).
For `Uint8Array`, analysis is per byte value (0–255).

## Examples

```ts
import { entropy } from "unsecure";

const result = entropy("Zk(p4@L!v9{g~8sB");
// result.bits          — total entropy in bits (~60+)
// result.bitsPerSymbol — entropy per character
// result.symbolCount   — total characters analyzed
// result.uniqueSymbols — distinct characters
// result.maxBitsPerSymbol — log2(uniqueSymbols), theoretical max

// Detect weak input
entropy("aaaaaaa").bitsPerSymbol; // 0 — completely predictable

// Analyze random bytes
const bytes = crypto.getRandomValues(new Uint8Array(256));
entropy(bytes).bitsPerSymbol; // ~7.9+ (close to max of 8 for 256 byte values)

// Handles null/undefined/empty gracefully (all zeros)
entropy(null); // { bits: 0, bitsPerSymbol: 0, ... }
entropy(""); // { bits: 0, bitsPerSymbol: 0, ... }
```

## Use Case: Password Quality Validation

```ts
import { secureGenerate, entropy } from "unsecure";

function generateStrongPassword(minBits = 80) {
  let password: string;
  let result;
  do {
    password = secureGenerate({ length: 20 });
    result = entropy(password);
  } while (result.bits < minBits);
  return { password, entropyBits: result.bits };
}
```

## Use Case: Entropy-Gated Secret Acceptance

```ts
import { entropy } from "unsecure";

function validateSecretStrength(secret: string): boolean {
  const { bitsPerSymbol, uniqueSymbols } = entropy(secret);
  // Require reasonable distribution and variety
  return bitsPerSymbol >= 3.0 && uniqueSymbols >= 10;
}
```

## Note: Shannon Entropy vs. Cryptographic Strength

Shannon entropy measures information density of the _observed_ data, not cryptographic security. A string like `"abcdefghijklmnop"` has high Shannon entropy (all unique chars) but is predictable. Use `entropy()` as a heuristic quality check, not a security guarantee.
