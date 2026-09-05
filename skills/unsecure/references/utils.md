# Encoding Utilities (`unsecure/utils`)

Codecs for hex, base64 (incl. URL-safe), and base32 — each a `stringify`
(bytes → text) / `parse` (text → bytes) pair, available from the
`unsecure/utils` subpath and re-exported from the main barrel.

```ts
import { hexStringify, hexParse } from "unsecure/utils";

hexStringify(bytes); // "deadbeef…"
hexParse("deadbeef", { returnAs: "bytes" }); // Uint8Array
```

The `Hex`, `Base64` and `Base32` objects group the same functions JSON-style —
`Hex.stringify` _is_ `hexStringify`. Import the flat functions when you want a
bundle to carry one codec instead of three.

For CDN delivery prefer the `unsecure/utils` subpath; for bundlers either the
subpath or the main barrel is fine (tree-shakes under `sideEffects: false`).

## Exports

```ts
import {
  hexStringify,
  hexParse,
  base64Stringify,
  base64Parse,
  base32Stringify,
  base32Parse,
  Hex,
  Base64,
  Base32,
  textEncoder,
  textDecoder,
  // types
  type BytesSource,
  type DecodeReturnAs,
  type DecodeOptions,
  type Base64Alphabet,
  type Base32Alphabet,
} from "unsecure/utils";
```

## Common shape

Every codec follows the same contract:

- **`stringify(data, options?)`** — `data` is a `string` (UTF-8 encoded first)
  or any `BytesSource`: an `ArrayBuffer` (shared or not), a `DataView`, or any
  typed array. Returns the encoded string.
  `null` / `undefined` throws `TypeError`.
- **`parse(input, options?)`** — `input` is the encoded `string` (or its
  `Uint8Array` bytes). Returns bytes or a UTF-8 string; see `returnAs` below.
  **Strict by default** — malformed input throws `SyntaxError`. Pass
  `{ loose: true }` to skip/normalize malformed input instead.

`returnAs` mirrors the input when omitted: `string` in → `string` out (bytes
decoded as UTF-8), `Uint8Array` in → `Uint8Array` out. Override with
`{ returnAs: "string" | "uint8array" | "bytes" }` (`"bytes"` aliases `"uint8array"`).

## Hex

```ts
hexStringify("hello"); // "68656c6c6f"
hexStringify(new Uint8Array([0xde, 0xad])); // "dead"
hexParse("68656c6c6f"); // "hello"
hexParse("68656c6c6f", { returnAs: "uint8array" }); // Uint8Array

hexParse("zz"); // throws SyntaxError (strict)
hexParse("abc", { loose: true, returnAs: "bytes" }); // Uint8Array [0xab] (drops the odd nibble)
```

## Base64

Standard by default. Pass `{ alphabet: "base64url" }` for URL-safe (`-_`,
unpadded by default). `{ padding: false }` drops `=` on any alphabet.

```ts
base64Stringify(new Uint8Array([1, 2, 3])); // "AQID"
base64Stringify(bytes, { padding: false }); // unpadded
base64Stringify(bytes, { alphabet: "base64url" }); // URL-safe, unpadded

base64Parse("AQID", { returnAs: "bytes" }); // Uint8Array
base64Parse(token, { alphabet: "base64url" }); // strict URL-safe decode
base64Parse("Zm9vYg"); // unpadded is canonical too
base64Parse(untrusted, { loose: true }); // tolerant (accepts either alphabet)
```

## Base32

`alphabet` accepts `"base32"` (RFC 4648, default), `"base32hex"`,
`"crockford"`, or a custom 32-character string — 32 distinct ASCII characters,
none of them `=` or whitespace; anything else throws `SyntaxError`. Padded by
default except Crockford; `{ padding: false }` to override.

Strict decode is uppercase-only for `base32` and `base32hex`; `{ loose: true }`
folds case. Crockford is case-insensitive in both modes and maps `O`→0,
`I`/`L`→1, per that alphabet's own spec. A custom alphabet is taken literally
in both modes — its case may carry meaning.

```ts
base32Stringify("foobar"); // "MZXW6YTBOI======"
base32Stringify(secret, { padding: false }); // unpadded (e.g. OTP secrets)
base32Stringify(bytes, { alphabet: "crockford" }); // Crockford, unpadded
base32Parse("MZXW6YTBOI", { returnAs: "bytes" }); // raw bytes

// Crockford decode is case-insensitive and maps O→0, I/L→1.
base32Parse(id, { alphabet: "crockford" });

base32Parse("MZXW6"); // unpadded is canonical too
base32Parse("MZXW7==="); // throws: bits set past the final byte
```

## Strict and loose

`parse` is strict by default to avoid decode malleability — two texts
decoding to the same bytes.

**Strict accepts exactly the canonical encoding of some byte string:**

- characters from the selected alphabet only — whitespace is a character like
  any other, and is rejected;
- `=` only as a trailing run, and only in the count the body length calls for,
  or absent entirely. Unpadded is canonical, so anything `stringify` emits —
  including `{ padding: false }` and the unpadded `base64url` default —
  round-trips;
- a length that can encode whole bytes (`Zm9vY` cannot);
- no set bits past the final byte (`Zg==` decodes `f`; `Zh==` does not decode).

**Loose normalizes and never throws on shape:** every character outside the
alphabet is dropped (whitespace, `=`, junk, anything non-ASCII), base64 folds
`-_` onto `+/` and accepts either alphabet, a trailing symbol that cannot
start a byte is dropped, and bits past the final byte are ignored. Nullish
input still throws `TypeError`.

Use `{ loose: true }` for user-supplied values that may be formatted (e.g.
OTP secrets pasted with spaces).

## Shared instances

```ts
import { textEncoder, textDecoder } from "unsecure/utils";

const bytes = textEncoder.encode("hello");
const str = textDecoder.decode(bytes);
```

## Internal: Buffer / native detection

Encoding prefers Node.js `Buffer` when available, then the TC39
`Uint8Array.toBase64`/`toHex` methods, then manual fallbacks.

Decoding settles the contract in JavaScript first and hands a backend only
canonical, fully padded, standard-alphabet text to bulk-decode. Native
`fromBase64`'s own strict mode is never used: it enforces a different contract
(padding mandatory, whitespace fatal), and the result must not depend on which
runtime is underneath. Same bytes, same error, everywhere.
