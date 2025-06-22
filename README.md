# unsecure

<!-- automd:badges bundlephobia style="flat" color="FFDC3B" -->

[![npm version](https://img.shields.io/npm/v/unsecure?color=FFDC3B)](https://npmjs.com/package/unsecure)
[![npm downloads](https://img.shields.io/npm/dm/unsecure?color=FFDC3B)](https://npm.chart.dev/unsecure)
[![bundle size](https://img.shields.io/bundlephobia/minzip/unsecure?color=FFDC3B)](https://bundlephobia.com/package/unsecure)

<!-- /automd -->

`unsecure` is a collection of runtime-agnostic cryptographycally-secure utilities. (ba dum tss 🥁)

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
import { hash, generateSecurePassword, secureVerify } from "unsecure";
// Utility functions
import {
  hexEncode,
  hexDecode,
  secureRandomNumber,
  secureShuffle,
} from "unsecure/utils";
```

**CDN** (Deno, Bun and Browsers)

```js
// Main functions
import {
  hash,
  generateSecurePassword,
  secureVerify,
} from "https://esm.sh/unsecure";
// Utility functions
import {
  hexEncode,
  hexDecode,
  secureRandomNumber,
  secureShuffle,
} from "https://esm.sh/unsecure/utils";
```

### hash

Hashes input data using a specified cryptographic algorithm. It uses the Web Crypto API, so it works in any modern JavaScript runtime.

```ts
import { hash } from "unsecure";

// Hash a string using the default SHA-256
const hashHex = await hash("hello world");
// 'b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9'

// Hash and get raw bytes (Uint8Array)
const hashBytes = await hash("hello world", { asString: false });
// Uint8Array(32) [ 185, 77, 39, 185, 147, 77, ... ]

// Hash using SHA-512
const hash512 = await hash("hello world", { algorithm: "SHA-512" });
// '309ecc489c12d6eb4cc40f50c902f2b4d0ed77ee511a7c7a9bcd3ca86d4cd86f...'
```

### generateSecurePassword

Generates a cryptographically secure password. You can customize its length and character set (all enabled by default). If a string is passed it will be used as a set of allowed characters.

```ts
import { generateSecurePassword } from "unsecure";

// Generate a default 16-character password
const password = generateSecurePassword();
// e.g. 'Zk(p4@L!v9{g~8sB'

// Generate a 24-character password with no special characters
const longPassword = generateSecurePassword({
  length: 24,
  specials: false,
});

// Generate a password using only custom numbers
const pin = generateSecurePassword({
  length: 6,
  uppercase: false,
  lowercase: false,
  specials: false,
  numbers: "13579",
});
```

### secureVerify

Compares two values (string or Uint8Array) in a timing-attack-safe manner. The first argument is always the reference value, which determines the time it takes for verification.

```ts
import { secureVerify } from "unsecure";

const secret = "my-super-secret-token";
const userInput = "my-super-secret-token";
// from user input

if (secureVerify(secret, userInput)) {
  console.log("Tokens match!");
} else {
  console.log("Tokens do not match!");
}

// Also works with Uint8Array and mixed types
const mac1 = new Uint8Array([1, 2, 3]);
const mac2 = new Uint8Array([1, 2, 3]);
secureVerify(mac1, mac2); // true
secureVerify(secret, mac2); // false
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

Includes `secureRandomNumber` and `secureShuffle`.

```ts
import { secureRandomNumber, secureShuffle } from "unsecure/utils";

// Get a secure random number between 0 and 99
const n = secureRandomNumber(100);

// Securely shuffle an array in-place
const list = [1, 2, 3, 4, 5];
secureShuffle(list); // e.g. [ 3, 1, 5, 2, 4 ]

// Or spread the original to not mutate it
const shuffled = secureShuffle([...list]);
```

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
