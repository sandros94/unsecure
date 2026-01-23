# unsecure

<!-- automd:badges bundlephobia style="flat" color="FFDC3B" -->

[![npm version](https://img.shields.io/npm/v/unsecure?color=FFDC3B)](https://npmjs.com/package/unsecure)
[![npm downloads](https://img.shields.io/npm/dm/unsecure?color=FFDC3B)](https://npm.chart.dev/unsecure)
[![bundle size](https://img.shields.io/bundlephobia/minzip/unsecure?color=FFDC3B)](https://bundlephobia.com/package/unsecure)

<!-- /automd -->

`unsecure` is a collection of runtime-agnostic cryptographically-secure utilities. (ba dum tss 🥁)

## Usage

Install the package:

```sh
# ✨ Auto-detect (supports npm, yarn, pnpm, deno and bun)
npx nypm install unsecure
```

Import:

**ESM** (Node.js, Bun, Deno)

```js
// Main functions
import { hash, secureGenerate, secureCompare } from "unsecure";
// Utility functions
import {
  hexEncode,
  hexDecode,
  secureShuffle,
  // ...
} from "unsecure/utils";
```

**CDN** (Deno, Bun and Browsers)

```js
// Main functions
import { hash, secureGenerate, secureCompare } from "https://esm.sh/unsecure";
// Utility functions
import {
  hexEncode,
  hexDecode,
  secureShuffle,
  // ...
} from "https://esm.sh/unsecure/utils";
```

### hash

Hashes input data using a specified cryptographic algorithm. It uses the Web Crypto API, so it works in any modern JavaScript runtime.

options:

- **algorithm**: `SHA-256`, `SHA-384`, `SHA-512` (default `SHA-256`)
- **returnAs**: `hex`, `base64`, `base64url`, `bytes` (default `hex`)

```ts
import { hash } from "unsecure";

// Hash an input using the default SHA-256 and return as a hex string
const hashHex = await hash("hello world");
// 'b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9'

// Hash an input using the default SHA-256 and return as a base64 string
const hashBase64 = await hash("hello world", { returnAs: "base64" });
// 'UhywQV8aBkKEVtnvTpSMAnCoBkQjJSU8t6imt+Q9qcc='

// Hash an input using the default SHA-256 and return as a base64 URL string
const hashBase64URL = await hash("hello world", { returnAs: "base64url" });
// 'UhywQV8aBkKEVtnvTpSMAnCoBkQjJSU8t6imt-Q9qcc'

// Hash and get raw bytes (Uint8Array)
const hashBytes = await hash("hello world", { returnAs: "bytes" });
// Uint8Array(32) [ 185, 77, 39, 185, 147, 77, ... ]

// Hash using SHA-512
const hash512 = await hash("hello world", { algorithm: "SHA-512" });
// '309ecc489c12d6eb4cc40f50c902f2b4d0ed77ee511a7c7a9bcd3ca86d4cd86f...'
```

### secureGenerate (or generateSecureToken)

Generates a cryptographically secure string. You can customize its length and character set (all enabled by default). If a string is passed it will be used as a set of allowed characters.

Internally it uses a buffer, which is constantly updated, to minimize Web Crypto API calls and greatly improve performance. This becomes useful when generating 128-512 characters long tokens.

```ts
import { secureGenerate } from "unsecure";

// Generate a default 16-character password
const password = secureGenerate();
// e.g. 'Zk(p4@L!v9{g~8sB'

// Generate 28-character password
const password = secureGenerate(28);
// e.g. '4~j&zgf-tO+PoMBVl}tK/}5$FgzF'

// Generate a 24-character token with no special characters
const token = secureGenerate({
  length: 24,
  specials: false,
});

// Generate a pin using only custom numbers
const pin = secureGenerate({
  length: 6,
  uppercase: false,
  lowercase: false,
  specials: false,
  numbers: "13579",
});

// Generate a token with current timestamp prefix
const stamp = secureGenerate({ length: 20, timestamp: true });
// Output example: "mi6dcq...random..."

// Generate a token with a specific date prefix
const date = new Date("2023-01-01T00:00:00Z");
const datestamp = secureGenerate({ length: 20, timestamp: date });
// Output example: "lcclw5...random..."
```

### secureCompare

Compares two values (string or Uint8Array) in a timing-attack-safe manner. The first argument is always the reference value, which determines the time it takes for verification.

```ts
import { secureCompare } from "unsecure";

const secret = "my-super-secret-token";
const userInput = "my-super-secret-token";
// from user input

if (secureCompare(secret, userInput)) {
  console.log("Tokens match!");
} else {
  console.log("Tokens do not match!");
}

// Also works with Uint8Array and mixed types
const mac1 = new Uint8Array([1, 2, 3]);
const mac2 = new Uint8Array([1, 2, 3]);
secureCompare(mac1, mac2); // true
secureCompare(secret, mac2); // false
```

### Utilities (`unsecure/utils`)

A collection of supplementary utilities for encoding, decoding, and random number generation.

#### Encoding

Includes `hexEncode`, `hexDecode`, `base64Encode`, `base64Decode`, `base64UrlEncode`, and `base64UrlDecode`.

```ts
import { hexEncode, hexDecode } from "unsecure/utils";

const hex = hexEncode("hello"); // "68656c6c6f"
const text = hexDecode(hex); // "hello"
```

#### Randomness

Includes `createSecureRandomGenerator`, `secureRandomNumber` and `secureShuffle`.

```ts
import {
  createSecureRandomGenerator,
  secureRandomNumber,
  secureShuffle,
} from "unsecure/utils";

// Creates a secure random number generator (more performant for subsequent calls)
const generator = createSecureRandomGenerator();

// Get a random number in range [0, max)
const n = generator.next(1000); // 0 to 999

// Get a random number in range [min, max)
const n2 = generator.next(50, 150); // 50 to 149

// Exclude specific values using an array or Set
const n3 = generator.next(10, [3, 5, 7]); // 0-9, excluding 3, 5, 7
const n4 = generator.next(50, 100, new Set([55, 60, 65])); // 50-99, excluding 55, 60, 65

// Get a secure random number (more memory-efficient for single use)
const num = secureRandomNumber(100); // 0 to 99
const num2 = secureRandomNumber(50, 150); // 50 to 149
const num3 = secureRandomNumber(10, [2, 4, 6]); // 0-9, excluding 2, 4, 6

// Securely shuffle an array in-place
const list = [1, 2, 3, 4, 5];
secureShuffle(list); // e.g. [ 3, 1, 5, 2, 4 ]

// Or spread the original to not mutate it
const shuffled = secureShuffle([...list]);

// Reuse generator for better performance when shuffling multiple times
const gen = createSecureRandomGenerator();
secureShuffle(list1, gen);
secureShuffle(list2, gen);
```

### sanitizeObject

Remove prototype-pollution vectors from a plain record in-place. It strips the dangerous own properties `__proto__`, `prototype`, and `constructor` from the target and all nested objects/arrays. It returns the same reference you pass in.

- Deep, in-place sanitization over objects and arrays
- Cycle-safe (handles circular references)
- Leaves non-objects, functions, Dates, Maps/Sets unchanged

```ts
import { sanitizeObject } from "unsecure";

const payload: Record<string, unknown> = {
  user: {
    name: "alice",
    // potential pollution vectors
    __proto__: { hacked: true },
    profile: [{ constructor: "bad" }, { prototype: { x: 1 } }],
  },
};

sanitizeObject(payload); // returns the same reference

// After sanitization
Object.hasOwn(payload.user, "__proto__"); // false
Object.hasOwn(payload.user.profile[0]!, "constructor"); // false
Object.hasOwn(payload.user.profile[1]!, "prototype"); // false
```

Notes:

- Only own properties named exactly `__proto__`, `prototype`, and `constructor` are removed.
- The function doesn't clone; it mutates the input value in-place for performance and memory efficiency.
- Values like Date, Map, Set, functions, and primitives are returned unchanged (but still traversed through if found as nested values on a plain object/array).

## Development

<details>

<summary>local development</summary>

- Clone this repository
- Install latest LTS version of [Node.js](https://nodejs.org/en/)
- Enable [Corepack](https://github.com/nodejs/corepack) using `corepack enable`
- Install dependencies using `pnpm install`
- Run interactive tests using `pnpm dev`

</details>

## Credits

Inspired by [DeepSource Corp work](https://github.com/DeepSourceCorp/shifty).

## License

<!-- automd:contributors license=MIT -->

Published under the [MIT](https://github.com/sandros94/unsecure/blob/main/LICENSE) license.
Made by [community](https://github.com/sandros94/unsecure/graphs/contributors) 💛
<br><br>
<a href="https://github.com/sandros94/unsecure/graphs/contributors">
<img src="https://contrib.rocks/image?repo=sandros94/unsecure" />
</a>

<!-- /automd -->

<!-- automd:with-automd -->

---

_🤖 auto updated with [automd](https://automd.unjs.io)_

<!-- /automd -->
