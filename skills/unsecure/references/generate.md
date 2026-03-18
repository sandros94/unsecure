# secureGenerate()

Generates cryptographically secure random strings/tokens/passwords with customizable character sets. Uses a buffered CSPRNG internally for performance.

## Signature

```ts
function secureGenerate(options?: {
  length?: number; // default: 16
  uppercase?: boolean | string; // default: true
  lowercase?: boolean | string; // default: true
  numbers?: boolean | string; // default: true
  specials?: boolean | string; // default: true
  timestamp?: true | Date; // default: false
}): string;
```

**Key behavior:** Each enabled character category is guaranteed to appear at least once in the output — the function picks one random character from each category, fills the rest from the full charset, then securely shuffles.

When a `string` is passed instead of `true` for a category, it replaces the default character set with the provided characters.

Default character sets:

- Uppercase: `ABCDEFGHIJKLMNOPQRSTUVWXYZ`
- Lowercase: `abcdefghijklmnopqrstuvwxyz`
- Numbers: `0123456789`
- Specials: `!@#$%^&*()_+{}:<>?|[];,./~-=`

## Examples

```ts
import { secureGenerate } from "unsecure";

// Default 16-char password with all character types
const password = secureGenerate();
// e.g. 'Zk(p4@L!v9{g~8sB'

// 32-char alphanumeric token (no specials)
const token = secureGenerate({ length: 32, specials: false });

// 6-digit numeric PIN
const pin = secureGenerate({
  length: 6,
  uppercase: false,
  lowercase: false,
  specials: false,
});

// Custom character set for numbers
const oddPin = secureGenerate({
  length: 6,
  uppercase: false,
  lowercase: false,
  specials: false,
  numbers: "13579",
});

// Token with timestamp prefix (sortable)
const stamped = secureGenerate({ length: 24, timestamp: true });

// Token with specific date prefix
const dated = secureGenerate({ length: 24, timestamp: new Date("2023-01-01") });
```

## Use Case: Secure Password Generation with Quality Check

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

## Pitfall: Short Length with Many Categories

Each enabled category will have at least one character. If `length` is too short for all enabled categories, the guaranteed characters take priority and the output is truncated after shuffle.

```ts
// ❌ length=2 with 4 categories enabled — only 2 of 4 guarantees fit
const short = secureGenerate({ length: 2 });

// ✅ Use length >= number of enabled categories for full guarantees
const good = secureGenerate({ length: 8 }); // 4 categories, 8 chars = fine
```

## Pitfall: Timestamp Consumes Output Length

When `timestamp` is enabled, the timestamp prefix is included in the total `length`. If the timestamp is longer than `length`, an error is thrown.

```ts
// ❌ Timestamp prefix is ~8 chars; length=8 leaves no room for random chars
secureGenerate({ length: 8, timestamp: true }); // Error

// ✅ Leave room for random characters after the timestamp
secureGenerate({ length: 24, timestamp: true }); // ~8 timestamp + 16 random
```
