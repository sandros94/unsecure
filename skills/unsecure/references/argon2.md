# argon2()

Argon2 password hashing (RFC 9106), in plain JavaScript. No WebAssembly, no native binding, no Node built-ins — the whole module is `Uint32Array` arithmetic over a bundled BLAKE2b (RFC 7693), so it runs in Workers, Deno, Bun, browsers, and Node alike.

**Scope note:** Argon2 is for **low-entropy** input — passwords, passphrases, PINs — where the work factor is the whole point. For **high-entropy** input (shared secrets, ECDH output) use `hkdf()`, which is far cheaper and sufficient.

## Signatures

```ts
// Store and check passwords — this is the pair you usually want.
async function argon2Hash(
  password: string | BufferSource,
  options?: Argon2Parameters & { salt?: string | BufferSource },
): Promise<string>; // a PHC string

async function argon2Verify(
  phc: string,
  password: string | BufferSource,
  options?: { secret?: string | BufferSource; data?: string | BufferSource },
): Promise<boolean>;

// The raw KDF underneath.
async function argon2(
  password: string | BufferSource,
  salt: string | BufferSource,
  options?: Argon2Parameters & {
    returnAs?: "hex" | "base64" | "b64" | "base64url" | "b64url" | "uint8array" | "bytes";
  },
): Promise<string | Uint8Array>;

interface Argon2Parameters {
  variant?: "argon2id" | "argon2i" | "argon2d"; // default: "argon2id"
  m?: number; // memory KiB, default: 19456
  t?: number; // passes, default: 2
  p?: number; // lanes, default: 1
  length?: number; // tag bytes, default: 32, min 4
  secret?: string | BufferSource; // pepper K, never stored
  data?: string | BufferSource; // associated data X, never stored
}
```

**Defaults:** OWASP's argon2id recommendation — `m=19456` (19 MiB), `t=2`, `p=1`, a 32-byte tag, and a fresh 16-byte salt from `secureRandomBytes()`.

**PHC format:** `$argon2id$v=19$m=19456,t=2,p=1$<salt>$<tag>`, standard base64 without padding. This is the same string `argon2` (the reference CLI), `@node-rs/argon2`, `argon2-cffi`, and PHP's `password_hash` produce and accept, so the KDF is replaceable without touching the column.

## Examples

```ts
import { argon2Hash, argon2Verify } from "unsecure/argon2";

// Registration
user.passwordHash = await argon2Hash(plaintext);

// Login
if (!(await argon2Verify(user.passwordHash, submitted))) return unauthorized();
```

```ts
// Raw key material from a passphrase
import { argon2 } from "unsecure/argon2";

const key = await argon2(passphrase, salt, {
  m: 65_536,
  t: 3,
  length: 64,
  returnAs: "uint8array",
});
```

## Use Case: A Pepper

`secret` is mixed into the derivation but never written into the PHC string. Keep it in the environment, not the database, and a stolen dump is not enough to start guessing.

```ts
const stored = await argon2Hash(plaintext, { secret: env.PASSWORD_PEPPER });
const ok = await argon2Verify(stored, submitted, { secret: env.PASSWORD_PEPPER });
```

Rotating the pepper invalidates every hash, so treat it as a value you re-derive on next login, not one you change casually.

## Use Case: Raising the Cost Later

`argon2Verify` reads the parameters out of the stored string, never from the current defaults. An old hash keeps verifying at the cost it was made with, which is what lets you raise the cost and rewrite lazily.

```ts
const ok = await argon2Verify(user.passwordHash, submitted);
if (ok && !user.passwordHash.includes("m=19456,t=2,p=1")) {
  user.passwordHash = await argon2Hash(submitted); // rehash at today's parameters
}
```

## Pitfall: Expecting `false` for a Malformed Hash

Only a wrong password returns `false`. A `phc` that is not a well-formed PHC string throws `SyntaxError`, and one naming an unknown variant or a version other than `0x13` — including a string with no `v=` field, which predates it — throws `Error`. That is deliberate: a stored value in an unexpected format is a bug or a migration nobody ran, and reporting it as "wrong password" would bury it.

```ts
await argon2Verify("not-a-phc-string", password); // throws SyntaxError
await argon2Verify(phc.replace("v=19", "v=16"), password); // throws Error
```

## Pitfall: Expecting `await` to Yield

All three functions are `async` for symmetry with `hash()` and `hmac()`, but the derivation runs synchronously on the calling thread: the promise settles only after every block has been computed, and nothing else on that thread runs in the meantime. At the defaults that is about 140 ms per call, during which a server on the same thread answers nobody. Where logins share a thread with other requests, run the hash in a worker thread and `await` its message instead; a CLI, a build step, or a per-request isolate can call it inline.

## Pitfall: Raising `p` to Go Faster

`p` is a parameter of the function, not a threading hint. Lanes are computed sequentially here (there is no portable shared-memory threading to use), so raising `p` changes the tag without making anything faster. Leave it at `1` unless you have to match tags produced by a parallel implementation.

## Pitfall: Timing the Absent-Account Path

`argon2Verify` is constant-time in the tag comparison, but skipping it entirely when no account matches leaks which addresses exist. Verify against a fixed throwaway PHC string in that branch so both paths cost the same hash.

```ts
const ABSENT = "$argon2id$v=19$m=19456,t=2,p=1$…$…"; // a hash of a value nobody holds
await argon2Verify(user?.passwordHash ?? ABSENT, submitted);
```

## Note on Cost

Pure JavaScript Argon2 is roughly an order of magnitude slower than a native binding — measured on a laptop, about 155 ms per hash at the defaults against about 13 ms for `@node-rs/argon2`, and on par with `@noble/hashes`. That is a real cost per login, paid on the calling thread (see the pitfall above), and it is also what makes the module usable where WebAssembly cannot be compiled from bytes at request time, which is how most Wasm Argon2 packages load. Check the platform's CPU budget before relying on that: a per-request quota of a few milliseconds ends the hash before it finishes. Lower `m` before you lower `t`; OWASP's fallbacks (`m=12288,t=3`, `m=9216,t=4`, `m=7168,t=5`) trade memory for passes at roughly constant strength.
