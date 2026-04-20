# uuidv4() / uuidv7() / secureUUID() / createUUIDv7Generator() / uuidv7Timestamp() / isUUIDv4() / isUUIDv7()

UUID generation backed by `crypto.getRandomValues` (RFC 9562). `uuidv7()` is the default new-UUID choice — its timestamp prefix makes it friendly to ordered indexes (e.g. Postgres 18 native `uuidv7()` semantics).

## Signatures

```ts
function uuidv4(): string;
function uuidv7(timestamp?: Date | number): string;
const secureUUID: typeof uuidv7; // alias

interface UUIDv7Generator {
  next(timestamp?: Date | number): string;
}
function createUUIDv7Generator(): UUIDv7Generator;

function uuidv7Timestamp(uuid: string): number; // throws TypeError if not v7
function isUUIDv4(value: unknown): value is string;
function isUUIDv7(value: unknown): value is string;
```

Both `uuidv7()` and `gen.next()` accept an optional `Date` or Unix-ms `number` to override the default `Date.now()`. Useful for tests, backfills, and replay. Fractional ms are floored; the value must be finite, non-negative, and within `[0, 2^48 - 1]` or a `RangeError` is thrown. Non-Date / non-number inputs throw `TypeError`.

## Which one to use

| Need                                                       | Use                         |
| ---------------------------------------------------------- | --------------------------- |
| A random UUID, don't care about version                    | `secureUUID()` (= `uuidv7`) |
| Sortable UUID for DB PK, scattered calls OK                | `uuidv7()`                  |
| Sortable UUID for DB PK, strict counter monotonicity       | `createUUIDv7Generator()`   |
| Out-of-order backfill of historical events                 | `uuidv7(date)` or generator |
| Fully random UUID (e.g. anti-enumeration, no time leakage) | `uuidv4()`                  |
| Read the creation time back from a UUIDv7                  | `uuidv7Timestamp()`         |
| Verify a string is a canonical UUIDv7                      | `isUUIDv7()`                |
| Verify a string is a canonical UUIDv4                      | `isUUIDv4()`                |

## Examples

```ts
import {
  uuidv4,
  uuidv7,
  secureUUID,
  createUUIDv7Generator,
  uuidv7Timestamp,
  isUUIDv7,
} from "unsecure";

// Pure random
uuidv4(); // "8a7c…-4xxx-…"

// Time-ordered, pure-random filler — 74 bits of entropy per ms
uuidv7(); // "0195c…-7xxx-…"

// Same as uuidv7() — use when the version isn't part of the contract
secureUUID();

// Strict monotonicity: useful as DB PKs so sequential inserts stay local
const gen = createUUIDv7Generator();
gen.next();
gen.next(); // always > previous, even under same-ms bursts or NTP regressions

// Read the embedded timestamp
const u = uuidv7();
new Date(uuidv7Timestamp(u)); // Date

// Embed a specific timestamp (testing, backfill, replay)
uuidv7(new Date("2020-01-01"));
uuidv7(1_609_459_200_000); // numeric ms

// Type-guards (case-insensitive; validate format + version + variant bits)
if (isUUIDv7(input)) {
  // input: string
}
if (isUUIDv4(input)) {
  // input: string
}
```

## UUIDv7 shape (RFC 9562 §5.7)

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                           unix_ts_ms                          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|          unix_ts_ms           |  ver  |       rand_a          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|var|                        rand_b                             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                            rand_b                             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

- 48-bit `unix_ts_ms` big-endian (ms since epoch — safe through year ~10,895).
- 4-bit version nibble (`0111`).
- 12-bit `rand_a` — random in `uuidv7()`, monotonic counter in the generator.
- 2-bit variant (`10`).
- 62-bit `rand_b` — always random.

## Monotonicity details (the generator)

The generator uses a **dual-clock** design. The 12-bit `rand_a` field is repurposed as a monotonic counter (RFC 9562 §6.2 Method 3), but the counter and its reference timestamp are driven **only** by `Date.now()` — the caller-supplied `timestamp` argument controls the _embedded_ ts field of the output and nothing else.

Key properties:

- **Seed.** On each new wall-clock ms, the counter is reseeded with a random value in `[0, 0x7ff]` — the lower half of the 12-bit range. At least 2048 increments of headroom before overflow.
- **Overflow.** If >4095 UUIDs are requested within one wall-clock ms, the internal reference advances by 1 ms and the counter reseeds. Uniqueness is preserved.
- **Clock regression.** If `Date.now()` returns a value ≤ the last internal reference (NTP adjust, VM pause, DST weirdness), the reference is held and the counter keeps incrementing. Output remains unique.
- **User-supplied timestamps do not perturb internal state.** `gen.next(pastTs)` embeds `pastTs` verbatim, but the counter still progresses from the wall-clock ms. This makes out-of-order backfills safe: each UUID is unique (counter + `rand_b`) and sorts by its embedded timestamp.
- **Scope.** Monotonicity is per-process. Two separate generators — or two separate processes — will collide in the counter field but remain distinguishable through the 62-bit `rand_b`.

## Pitfall: Using `uuidv7Timestamp` on an Arbitrary UUID

Only valid for UUIDv7. Passing a UUIDv4 throws because the first 48 bits are random, not a timestamp. Gate the call with `isUUIDv7`.

```ts
// ❌ Throws TypeError on any non-v7 input
const t = uuidv7Timestamp(someUuid);

// ✅ Guarded
if (isUUIDv7(someUuid)) {
  const t = uuidv7Timestamp(someUuid);
}
```

## Pitfall: Assuming `uuidv7()` Is Strictly Monotonic

The stateless `uuidv7()` fills `rand_a` and `rand_b` with **pure random bits**. Two UUIDs generated in the same millisecond may appear in either order when sorted. Across different milliseconds ordering is guaranteed. If you need the stronger guarantee (DB PK inserts that stay on hot pages), use the generator.

## Pitfall: Assuming Emitted-UUID Sort Order Matches Call Order When Mixing Timestamps

Because user-supplied timestamps are embedded verbatim and drive the first 48 bits of the UUID (which dominate lex order), mixing `next()` and `next(pastTs)` calls gives you UUIDs that sort by their embedded timestamp, not by call order. That's usually what you want for DB PKs (records sort chronologically), but it means:

```ts
const a = gen.next(); // embeds Date.now()
const b = gen.next(new Date("2020-01-01")); // embeds 2020 → b < a lex order
```

If you need "latest inserted sorts last," either feed monotonic timestamps or omit the argument. Two UUIDs with the same embedded ts still sort by their counter within the wall-clock ms.

## Pitfall: Treating UUIDv7 Timestamp Precision as Sub-ms

The embedded timestamp is millisecond precision by construction (RFC 9562 §5.7). Do not read `uuidv7Timestamp()` as anything finer than 1 ms. If ordering within a ms matters, use the generator — the counter encodes ordering but not time.

## Note

`uuidv4()` here does not call `crypto.randomUUID()`. The randomness source is the same, but the version/variant bits are set explicitly so the implementation is self-contained and won't shift if a runtime changes its shortcut behavior.
