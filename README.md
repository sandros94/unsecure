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
  // Hashing / MAC / KDF
  hash,
  hmac,
  hmacVerify,
  hkdf,
  // OTP
  hotp,
  hotpVerify,
  totp,
  totpVerify,
  generateOTPSecret,
  otpauthURI,
  // UUID
  uuidv4,
  uuidv7,
  secureUUID,
  createUUIDv7Generator,
  uuidv7Timestamp,
  isUUIDv4,
  isUUIDv7,
  // Generation / comparison / entropy
  secureGenerate,
  secureCompare,
  entropy,
  // Sanitization
  sanitizeObject,
  sanitizeObjectCopy,
  safeJsonParse,
  // Randomness
  createSecureRandomGenerator,
  secureRandomNumber,
  secureRandomBytes,
  secureShuffle,
  randomJitter,
  // Encoding (also available via `unsecure/utils`)
  hexEncode,
  hexDecode,
  base64Encode,
  base64Decode,
  base64UrlEncode,
  base64UrlDecode,
  base32Encode,
  base32Decode,
} from "unsecure";
```

**CDN** (Deno, Bun and Browsers)

For CDN delivery, prefer the per-module subpaths — each module ships as its own bundle so only the bytes you import are downloaded.

```js
// Per-module — ships only what the module needs
import { uuidv7, createUUIDv7Generator } from "https://esm.sh/unsecure/uuid";
import { hkdf } from "https://esm.sh/unsecure/hkdf";
import { totp, generateOTPSecret } from "https://esm.sh/unsecure/otp";
import { base64Encode, base32Decode } from "https://esm.sh/unsecure/utils";
```

Each of `compare`, `entropy`, `generate`, `hash`, `hkdf`, `hmac`, `otp`, `random`, `sanitize`, `uuid`, `utils` is an independent subpath.

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

### hkdf

HKDF key derivation (RFC 5869) via `crypto.subtle.deriveBits`. Extract-and-expand from **high-entropy** input keying material — shared secrets, ECDH output, seeds. For **password-based** derivation use PBKDF2/Argon2 instead; HKDF has no work factor.

options:

- **algorithm**: `SHA-1`, `SHA-256`, `SHA-384`, `SHA-512` (default `SHA-256`)
- **length**: output length in bytes (default `32`, max `255 * HashLen`)
- **salt**: non-secret but strongly recommended (string or `BufferSource`, default empty)
- **info**: context label for domain separation (string or `BufferSource`, default empty)
- **returnAs**: `hex`, `base64`, `base64url`, `bytes` (default `uint8array`)

```ts
import { hkdf } from "unsecure";

// Derive a 256-bit key from a shared secret
const key = await hkdf(sharedSecret, { salt, info: "my-app/auth/v1" });

// 512-bit key, SHA-512, base64url output
const keyB64 = await hkdf(ikm, {
  algorithm: "SHA-512",
  length: 64,
  info: "encryption-key",
  returnAs: "base64url",
});

// Domain separation — same IKM, different `info` → independent keys
const encKey = await hkdf(ikm, { salt, info: "encrypt" });
const macKey = await hkdf(ikm, { salt, info: "authenticate" });
```

> [!TIP]
> A different `info` per usage site (ideally versioned, e.g. `"myapp/enc/v1"`) lets you rotate key derivation without breaking old data. Requests beyond `255 * HashLen` throw a `RangeError` before reaching Web Crypto.

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

// Handles undefined / empty `expected` gracefully — returns false by default
secureCompare(expected, undefined); // false
secureCompare("", received); // false
secureCompare(undefined, undefined); // false — never "empty matches empty"

// Opt-in strict mode throws on empty / undefined `expected` (pre-0.2 behavior).
// Useful during development to surface server-side config bugs — avoid in
// attacker-reachable code paths since the throw itself is a side-channel.
secureCompare(undefined, "x", { strict: true }); // throws
```

### entropy

Computes three complementary quality signals for a string or `Uint8Array`: Shannon unigram entropy (frequency-based), bigram entropy (adjacent-pair structure), and the longest strictly-monotonic run (ascending/descending). Unigram entropy alone is blind to symbol order — `"abcdefghijklmnop"` scores the maximum for its alphabet despite being deterministic. The other two fields close that gap.

Result fields:

- **`bits` / `bitsPerSymbol` / `symbolCount` / `uniqueSymbols` / `maxBitsPerSymbol`**: classic Shannon entropy, unchanged.
- **`bigramBits` / `bigramBitsPerSymbol`**: entropy over adjacent-pair frequencies. Catches sequential, alternating, and blocked patterns. Length-sensitive — see below.
- **`longestRun` + `monotonicDirection`**: length of the longest strictly ascending or descending run, with its direction (`"ascending" | "descending" | "none"`). Reliable on any input length.

```ts
import { entropy } from "unsecure";

// Strong 16-char token — high across all metrics
const result = entropy("Zk(p4@L!v9{g~8sB");
console.log(result.bits); // ~60+ bits
console.log(result.bitsPerSymbol); // entropy per character
console.log(result.uniqueSymbols); // distinct characters
console.log(result.longestRun); // small

// Weak secret — low unigram entropy
entropy("aaaaaaa").bitsPerSymbol; // 0

// Sorted-alphabet fake — caught by longestRun
const fake = entropy("abcdefghijklmnop");
fake.bitsPerSymbol; // 4 (maximum for 16 unique chars)
fake.longestRun; // 16
fake.monotonicDirection; // "ascending"
fake.bigramBitsPerSymbol; // ~2.46 — noticeably low

// Random bytes — near-max across the board
const bytes = new Uint8Array(256);
crypto.getRandomValues(bytes);
entropy(bytes).bitsPerSymbol; // ~7.9+
```

> [!TIP]
> `bigramBitsPerSymbol` is length-sensitive: its ceiling is `log2(min(symbolCount - 1, k²))` where `k = uniqueSymbols`. Compare against a known-random control of the same length, or rely on `longestRun` for short inputs. For a password gate, requiring `longestRun < 5` rejects obvious keyboard-walk and sorted patterns that slip past unigram entropy.

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

### UUID (v4 / v7)

UUID generation per RFC 9562, backed by `crypto.getRandomValues`. `uuidv7()` is the default new-UUID choice — its timestamp prefix sorts chronologically, which is ideal for database primary keys (e.g. Postgres 18 native `uuidv7()` semantics).

Neither version delegates to `crypto.randomUUID()`; the version/variant bits are set explicitly so the implementation is self-contained and won't shift if a runtime changes its shortcut behavior.

```ts
import {
  uuidv4,
  uuidv7,
  secureUUID,
  createUUIDv7Generator,
  uuidv7Timestamp,
  isUUIDv4,
  isUUIDv7,
} from "unsecure";

// Pure random (122 bits of randomness)
uuidv4(); // "8a7c…-4xxx-…"

// Time-ordered; 48-bit Unix-ms prefix + 74 bits of random filler
uuidv7(); // "0195c…-7xxx-…"

// Alias of uuidv7 — use when the version isn't part of the contract
secureUUID();

// Embed a specific timestamp (tests, backfills, replay)
uuidv7(new Date("2020-01-01"));
uuidv7(1_609_459_200_000); // numeric ms

// Read the embedded timestamp back
const u = uuidv7();
new Date(uuidv7Timestamp(u));

// Type guards (case-insensitive; format + version + variant checks)
if (isUUIDv7(input)) {
  /* input: string */
}
if (isUUIDv4(input)) {
  /* input: string */
}
```

#### createUUIDv7Generator

Stateful generator with a **dual-clock** design: the internal counter and its reference timestamp progress from `Date.now()` only (never perturbed by user-supplied arguments), while the embedded 48-bit timestamp field reflects either `Date.now()` or a caller-supplied value. Out-of-order backfills are safe — UUIDs for past events remain unique and sort by their embedded timestamp.

```ts
const gen = createUUIDv7Generator();

gen.next(); // Counter monotonic per process
gen.next(new Date("2020-01-01")); // Embeds that date; counter still advances
gen.next(1_577_836_800_000); // Numeric ms
```

Key properties:

- Counter follows RFC 9562 §6.2 Method 3 — 12-bit field in `rand_a`, reseeded randomly in `[0, 0x7ff]` each new wall-clock ms (≥2048 increments of headroom before overflow).
- On counter overflow (>4095 calls within one wall-clock ms), the internal reference advances by 1 ms and the counter reseeds.
- `Date.now()` regressions (NTP adjust, VM pause) hold the reference and keep incrementing the counter — output never goes backward.
- A throwing `.next(invalidTs)` does **not** mutate internal state (validation runs before the counter advances).

> [!NOTE]
> Mixing `next()` and `next(pastTs)` calls gives UUIDs that sort by embedded timestamp, not call order — usually what you want for DB PKs. If you need "latest inserted sorts last," omit the argument or feed monotonic timestamps. For true backfills of past events, call the stateless `uuidv7(date)` instead.

### Utilities (`unsecure/utils`)

A collection of supplementary encoding/decoding utilities: `hexEncode`/`hexDecode`, `base64Encode`/`base64Decode`, `base64UrlEncode`/`base64UrlDecode`, `base32Encode`/`base32Decode`, plus shared `textEncoder` / `textDecoder`. All three encoding families share the same shape:

- **Encoders** accept `string | Uint8Array` (any backing buffer, including `SharedArrayBuffer`-backed views) and always return `string`. Empty input (`""` or `new Uint8Array(0)`) returns `""`. `null` / `undefined` throws `TypeError` — for optional fields, normalize at the call site with `?? ""`.
- **Decoders** accept `string | Uint8Array` (any backing buffer). The default return type mirrors the input: `string` in → UTF-8 `string` out (decoded bytes interpreted as UTF-8), `Uint8Array` in → `Uint8Array<ArrayBuffer>` out. When returning bytes, the output is always a freshly-allocated `ArrayBuffer`-backed `Uint8Array` — never a view into Node's internal `Buffer` pool. Override with `{ returnAs: "uint8array" | "bytes" | "string" }`. `null` / `undefined` throws `TypeError`.

Available both from the main barrel and from `unsecure/utils` (use the subpath for CDN delivery to ship only these helpers).

```ts
import { hexEncode, hexDecode, base32Encode, base32Decode } from "unsecure/utils";

const hex = hexEncode("hello"); // "68656c6c6f"
const text = hexDecode(hex); // "hello" (string → string by default)
const bytes = hexDecode(hex, { returnAs: "uint8array" }); // Uint8Array

// Base32 (RFC 4648) — commonly used for OTP secrets; behaves identically
const b32 = base32Encode("foobar"); // "MZXW6YTBOI======"
base32Decode("MZXW6YTBOI"); // "foobar"
base32Decode("MZXW6YTBOI", { returnAs: "uint8array" }); // raw bytes

// Normalize optional fields at the call site rather than relying on coercion
hexEncode(optionalField ?? ""); // "" when field is null/undefined
base64Encode(optionalBuffer ?? new Uint8Array(0));
```

### Sanitization (`sanitizeObject` / `sanitizeObjectCopy` / `safeJsonParse`)

Three complementary tools for stripping prototype-pollution vectors (`__proto__`, `prototype`, `constructor`) from untrusted input.

| If you…                              | Use                        |
| ------------------------------------ | -------------------------- |
| Receive JSON text — parse + sanitize | `safeJsonParse`            |
| Already have a parsed object you own | `sanitizeObject` (fastest) |
| Must preserve the caller's object    | `sanitizeObjectCopy`       |

`safeJsonParse` is cheapest — a reviver drops dangerous keys during parsing so they never materialize on the result. `sanitizeObject` is the fastest post-parse variant: single-pass traversal, mutates in place, no intermediate allocations. `sanitizeObjectCopy` is the non-mutating alternative, cycle-safe via `WeakMap` (cycles in the input become cycles in the output pointing at the copied node, never at the original).

```ts
import { safeJsonParse, sanitizeObject, sanitizeObjectCopy } from "unsecure";

// 1. Parse + sanitize in one step — dangerous keys never exist on the result
const payload = safeJsonParse<{ user: { name: string } }>(untrustedInput);

// 2. Post-parse, mutate in place (cheapest on hot paths)
const parsed = JSON.parse(untrustedInput);
sanitizeObject(parsed); // returns the same reference

// 3. Post-parse, keep the caller's object untouched
const safe = sanitizeObjectCopy(req.body);

// All three handle nested objects + arrays, and preserve cycles safely
const data = {
  user: {
    name: "alice",
    __proto__: { hacked: true },
    profile: [{ constructor: "bad" }, { prototype: { x: 1 } }],
  },
};
sanitizeObject(data);
Object.hasOwn(data.user, "__proto__"); // false
Object.hasOwn(data.user.profile[0]!, "constructor"); // false
```

Notes:

- Only own properties named exactly `__proto__`, `prototype`, and `constructor` are removed.
- `sanitizeObject` mutates in place for performance; use `sanitizeObjectCopy` if the caller may still hold a reference.
- `sanitizeObjectCopy` rebuilds onto plain `Object.prototype` — even null-prototype input comes back rooted normally.
- Values like `Date`, `Map`, `Set`, functions, and primitives are returned unchanged (but still traversed through if found as nested values on a plain object/array).

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
