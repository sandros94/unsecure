# unsecure

[![npm version](https://npmx.dev/api/registry/badge/version/unsecure?name=true)](https://npmx.dev/package/unsecure)
[![npm downloads](https://npmx.dev/api/registry/badge/downloads/unsecure)](https://npmx.dev/package/unsecure)
[![bundle size](https://npmx.dev/api/registry/badge/size/unsecure)](https://npmx.dev/package/unsecure)

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
import {
  hash,
  hmac,
  hmacVerify,
  secureGenerate,
  secureCompare,
  entropy,
  sanitizeObject,
  // OTP
  hotp,
  hotpVerify,
  totp,
  totpVerify,
  generateOTPSecret,
  otpauthURI,
  // Randomness
  createSecureRandomGenerator,
  secureRandomNumber,
  secureRandomBytes,
  secureShuffle,
  randomJitter,
} from "unsecure";
// Utility functions
import {
  hexEncode,
  hexDecode,
  base64Encode,
  base64Decode,
  base32Encode,
  base32Decode,
  // ...
} from "unsecure/utils";
```

**CDN** (Deno, Bun and Browsers)

```js
import { hash, hmac, totp, secureGenerate } from "https://esm.sh/unsecure";
import { hexEncode, base64Encode, base32Encode } from "https://esm.sh/unsecure/utils";
```

### hash

Hashes input data using a specified cryptographic algorithm. It uses the Web Crypto API, so it works in any modern JavaScript runtime.

options:

- **algorithm**: `SHA-1`, `SHA-256`, `SHA-384`, `SHA-512` (default `SHA-256`)
- **returnAs**: `hex`, `base64`, `base64url`, `bytes` (default `hex`)

> [!WARNING]
> `hash()` operates on complete data. The Web Crypto API does not support incremental/streaming digests, so for hashing large streams (e.g. file uploads) you'll need a platform-specific API like Node.js's `crypto.createHash()` or Deno's `crypto.subtle.digestStream()`.

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

### hmac

Computes an HMAC signature using the Web Crypto API. Supports the same algorithms and output formats as `hash()`. When `returnAs` is not specified, the output type mirrors the input: string data returns a hex string, BufferSource data returns a Uint8Array.

options:

- **algorithm**: `SHA-1`, `SHA-256`, `SHA-384`, `SHA-512` (default `SHA-256`)
- **returnAs**: `hex`, `base64`, `base64url`, `bytes` (default mirrors input type)

```ts
import { hmac, hmacVerify } from "unsecure";

// Sign a string — returns hex by default
const sig = await hmac("my-secret", "hello world");
// 'a3a65e5...'

// Sign with SHA-512 and return as base64
const sig64 = await hmac("my-secret", payload, {
  algorithm: "SHA-512",
  returnAs: "base64",
});

// Verify a webhook signature in constant time
const expected = request.headers["x-hub-signature-256"].replace("sha256=", "");
const valid = await hmacVerify(webhookSecret, requestBody, expected);
// true or false

// Verify a base64-encoded signature
const valid = await hmacVerify(secret, body, expectedBase64Sig, {
  returnAs: "base64",
});
```

### OTP (HOTP / TOTP)

RFC 4226 (HOTP) and RFC 6238 (TOTP) one-time password generation and verification, built on top of `hmac()`.

Secrets can be passed as raw `Uint8Array` bytes or as a base32-encoded `string`.

> [!NOTE]
> The RFCs recommend the secret to be at least as long as the hash output (20 bytes for SHA-1, 32 for SHA-256, 48 for SHA-384, 64 for SHA-512). The default `generateOTPSecret()` produces 20 bytes, which works with any algorithm but is ideal for SHA-1. Use `generateOTPSecret(32)` or `generateOTPSecret(64)` when targeting SHA-256 or SHA-512.

#### hotp / hotpVerify

Generate and verify HMAC-based One-Time Passwords (RFC 4226).

options:

- **algorithm**: `SHA-1`, `SHA-256`, `SHA-384`, `SHA-512` (default `SHA-1`)
- **digits**: number of digits in the OTP code (default `6`)
- **window**: (verify only) number of counter values to check ahead (default `0`)

```ts
import { hotp, hotpVerify } from "unsecure";

// Generate an OTP for counter 0
const code = await hotp(secretBytes, 0);
// "755224"

// Generate an 8-digit OTP
const code8 = await hotp(secretBytes, 0, { digits: 8 });

// Verify an OTP
const { valid, delta } = await hotpVerify(secret, "287082", 0, { window: 5 });
// valid: true, delta: 1 (matched at counter 0 + 1)
```

#### totp / totpVerify

Generate and verify Time-based One-Time Passwords (RFC 6238).

options:

- **algorithm**: `SHA-1`, `SHA-256`, `SHA-384`, `SHA-512` (default `SHA-1`)
- **digits**: number of digits in the OTP code (default `6`)
- **period**: time step duration in seconds (default `30`)
- **time**: Unix timestamp in seconds (defaults to current time)
- **window**: (verify only) number of time steps to check in each direction (default `1`)

```ts
import { totp, totpVerify } from "unsecure";

// Generate a TOTP for the current time
const code = await totp(base32Secret);

// Verify a user-provided code (checks current, previous, and next time steps)
const { valid, delta } = await totpVerify(secret, userCode);
// delta: 0 = current step, -1 = previous, +1 = next
```

#### generateOTPSecret

Generates a cryptographically random OTP secret, returned as a base32-encoded string (without padding).

```ts
import { generateOTPSecret } from "unsecure";

const secret = generateOTPSecret();
// "JBSWY3DPEHPK3PXP..."

// Custom length (32 bytes for SHA-256)
const secret256 = generateOTPSecret(32);
```

#### otpauthURI

Builds an `otpauth://` URI for provisioning OTP tokens via QR code.

```ts
import { otpauthURI } from "unsecure";

const uri = otpauthURI({
  type: "totp",
  secret: base32Secret,
  account: "user@example.com",
  issuer: "MyApp",
});
// "otpauth://totp/MyApp:user%40example.com?secret=...&issuer=MyApp&algorithm=SHA1&digits=6&period=30"

// HOTP URI (counter is required)
const hotpUri = otpauthURI({
  type: "hotp",
  secret: secretBytes,
  account: "user@example.com",
  counter: 0,
});
```

### secureGenerate

Generates a cryptographically secure string. You can customize its length and character set (all enabled by default). If a string is passed it will be used as a set of allowed characters.

Internally it uses a buffer, which is constantly updated, to minimize Web Crypto API calls and greatly improve performance. This becomes useful when generating 128-512 characters long tokens.

```ts
import { secureGenerate } from "unsecure";

// Generate a default 16-character password
const password = secureGenerate();
// e.g. 'Zk(p4@L!v9{g~8sB'

// Generate a 28-character password
const password = secureGenerate({ length: 28 });
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

Compares two values (string or Uint8Array) in a timing-attack-safe manner. The first argument (`expected`) is always the trusted, server-side value, which determines the loop length. The second argument (`received`) is the untrusted, user-provided value.

```ts
import { secureCompare } from "unsecure";

const expected = "my-super-secret-token";
const received = "my-super-secret-token"; // from user input

if (secureCompare(expected, received)) {
  console.log("Tokens match!");
} else {
  console.log("Tokens do not match!");
}

// Also works with Uint8Array and mixed types
const mac1 = new Uint8Array([1, 2, 3]);
const mac2 = new Uint8Array([1, 2, 3]);
secureCompare(mac1, mac2); // true
secureCompare(expected, mac2); // false

// Handles undefined received gracefully (returns false)
secureCompare(expected, undefined); // false
```

### entropy

Computes Shannon entropy of a string or Uint8Array. Useful for measuring the quality of generated tokens, passwords, or random data.

```ts
import { entropy } from "unsecure";

// Measure a generated token
const result = entropy("Zk(p4@L!v9{g~8sB");
console.log(result.bits); // ~60+ bits for a strong 16-char token
console.log(result.bitsPerSymbol); // entropy per character
console.log(result.uniqueSymbols); // number of distinct characters

// Detect a weak secret
entropy("aaaaaaa").bitsPerSymbol; // 0 — completely predictable

// Analyze random bytes
const bytes = new Uint8Array(256);
crypto.getRandomValues(bytes);
entropy(bytes).bitsPerSymbol; // ~7.9+ (close to max of 8 for 256 byte values)
```

### Randomness

Includes `createSecureRandomGenerator`, `secureRandomNumber`, `secureRandomBytes`, `secureShuffle`, and `randomJitter`.

```ts
import {
  createSecureRandomGenerator,
  secureRandomNumber,
  secureRandomBytes,
  secureShuffle,
  randomJitter,
} from "unsecure";

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

// Generate random bytes
const key = secureRandomBytes(32); // 256-bit key material (Uint8Array)

// Securely shuffle an array in-place
const list = [1, 2, 3, 4, 5];
secureShuffle(list); // e.g. [ 3, 1, 5, 2, 4 ]

// Or spread the original to not mutate it
const shuffled = secureShuffle([...list]);

// Reuse generator for better performance when shuffling multiple times
const gen = createSecureRandomGenerator();
secureShuffle(list1, gen);
secureShuffle(list2, gen);

// Add a random delay as defense-in-depth against timing side-channels
await randomJitter(); // 0-99ms
await randomJitter(50); // 0-49ms
await randomJitter(50, 100); // 50-99ms
```

### Utilities (`unsecure/utils`)

A collection of supplementary utilities for encoding and decoding.

Includes `hexEncode`, `hexDecode`, `base64Encode`, `base64Decode`, `base64UrlEncode`, `base64UrlDecode`, `base32Encode`, and `base32Decode`.

```ts
import { hexEncode, hexDecode, base32Encode, base32Decode } from "unsecure/utils";

const hex = hexEncode("hello"); // "68656c6c6f"
const text = hexDecode(hex); // "hello"

// Base32 (RFC 4648) — commonly used for OTP secrets
const b32 = base32Encode("foobar"); // "MZXW6YTBOI======"
const decoded = base32Decode("MZXW6YTBOI"); // Uint8Array (handles unpadded, case-insensitive)
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
