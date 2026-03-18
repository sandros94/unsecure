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

One-shot version (no buffer reuse). Creates a new `Uint32Array(1)` per call. Better for isolated single calls; prefer the buffered generator for loops.

```ts
import { secureRandomNumber } from "unsecure";

secureRandomNumber(100); // [0, 100)
secureRandomNumber(50, 150); // [50, 150)
secureRandomNumber(10, [2, 4, 6]); // [0, 10) excluding evens
```

## secureRandomBytes()

Generate a `Uint8Array` of cryptographically secure random bytes. Handles the 65536-byte `crypto.getRandomValues` limit internally via chunking.

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
```

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

## Pitfall: Using secureRandomNumber() in Hot Loops

`secureRandomNumber()` creates a new `Uint32Array(1)` per call and calls `crypto.getRandomValues` each time. For many random numbers, the buffered generator is significantly faster.

```ts
// ❌ Slow in tight loops
for (let i = 0; i < 10000; i++) {
  values.push(secureRandomNumber(100));
}

// ✅ Use buffered generator (batches crypto.getRandomValues calls)
const rng = createSecureRandomGenerator();
for (let i = 0; i < 10000; i++) {
  values.push(rng.next(100));
}
```

## Pitfall: Using Math.random() Alongside This Library

If you're using `unsecure` for security, don't mix in `Math.random()` for anything security-sensitive — it's not cryptographically secure.

```ts
// ❌ Defeats the purpose
const index = Math.floor(Math.random() * tokens.length);

// ✅ Use the provided CSPRNG
const index = secureRandomNumber(tokens.length);
```
