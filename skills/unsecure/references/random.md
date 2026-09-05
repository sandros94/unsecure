# Randomness Utilities

Cryptographically secure random number generation, byte generation, shuffling, and timing jitter — all built on `crypto.getRandomValues`.

## createSecureRandomGenerator()

Buffered CSPRNG — uses a 256-element `Uint32Array` to batch `crypto.getRandomValues` calls. Best when generating many random numbers. Uses rejection sampling to avoid modulo bias.

```ts
import { createSecureRandomGenerator } from "unsecure";

const rng = createSecureRandomGenerator();

rng.next(100); // [0, 100)
rng.next(50, 150); // [50, 150)

// Exclude specific values
rng.next(10, [3, 5, 7]); // [0, 10) excluding 3, 5, 7
rng.next(50, 100, new Set([75])); // [50, 100) excluding 75
```

**Throws:**

- `RangeError` if `max <= min`, range > 2³², or ignore set excludes all values
- `TypeError` if ignore is not an iterable or Set

## secureRandomNumber()

Same draw as `rng.next()`, taken from a generator shared by the whole process — one `crypto.getRandomValues` call per 256 draws, rejection sampling included. Reach for `createSecureRandomGenerator()` when a caller wants a generator of its own; there is no throughput reason to.

```ts
import { secureRandomNumber } from "unsecure";

secureRandomNumber(100); // [0, 100)
secureRandomNumber(50, 150); // [50, 150)
secureRandomNumber(10, [2, 4, 6]); // [0, 10) excluding evens
```

## secureRandomBytes()

Generate a `Uint8Array` of cryptographically secure random bytes. Handles the 65536-byte `crypto.getRandomValues` limit internally via chunking. `length` must be an integer in `[0, 2**31 - 1]`; anything larger throws `RangeError` instead of allocating gigabytes and filling them for hours.

```ts
import { secureRandomBytes } from "unsecure";

const key = secureRandomBytes(32); // 256-bit key material
const iv = secureRandomBytes(12); // 96-bit IV for AES-GCM
const large = secureRandomBytes(100000); // works fine, chunked internally
```

## secureShuffle()

Fisher-Yates shuffle with CSPRNG. **Mutates in-place**, returns the same array reference.

```ts
import { secureShuffle, createSecureRandomGenerator } from "unsecure";

const arr = [1, 2, 3, 4, 5];
secureShuffle(arr); // shuffled in-place

// Non-mutating: spread first
const shuffled = secureShuffle([...arr]);

// Reuse generator for multiple shuffles (more performant)
const gen = createSecureRandomGenerator();
secureShuffle(list1, gen);
secureShuffle(list2, gen);
```

## randomJitter()

Adds a random delay in milliseconds. Useful as defense-in-depth against timing side-channels.

```ts
import { randomJitter } from "unsecure";

await randomJitter(); // 0–99ms
await randomJitter(50); // 0–49ms
await randomJitter(50, 200); // 50–199ms
await randomJitter(undefined, 50); // 0–49ms — an absent lower bound is 0
```

Bounds must be non-negative integers (`setTimeout` truncates, so a fractional bound never described the delay), and `maxMs === minMs` resolves after exactly that many milliseconds without drawing randomness. Otherwise `RangeError`.

## Use Case: Secure Lottery / Drawing

```ts
import { secureShuffle } from "unsecure";

function drawWinners(participants: string[], count: number) {
  const shuffled = secureShuffle([...participants]); // don't mutate original
  return shuffled.slice(0, count);
}
```

## Use Case: Rate Limiting with Jitter (Anti-Fingerprinting)

```ts
import { randomJitter } from "unsecure";

async function handleLogin(credentials: Credentials) {
  const result = await authenticate(credentials);

  // Always add jitter so response time doesn't reveal
  // whether the user exists or the password was wrong
  await randomJitter(100, 300);

  return result;
}
```

## Pitfall: Expecting an Isolated Generator from secureRandomNumber()

`secureRandomNumber()` and `randomJitter()` draw from one process-wide buffered generator, so a test that stubs `crypto.getRandomValues` sees the stub only once every 256 draws. Create a private generator when the draws must be isolated.

```ts
// ❌ Assumes every call reaches crypto.getRandomValues
vi.spyOn(crypto, "getRandomValues").mockImplementation(fill);
secureRandomNumber(100);

// ✅ A generator of your own, refilled on its first draw
const rng = createSecureRandomGenerator();
rng.next(100);
```

## Pitfall: Using Math.random() Alongside This Library

If you're using `unsecure` for security, don't mix in `Math.random()` for anything security-sensitive — it's not cryptographically secure.

```ts
// ❌ Defeats the purpose
const index = Math.floor(Math.random() * tokens.length);

// ✅ Use the provided CSPRNG
const index = secureRandomNumber(tokens.length);
```
