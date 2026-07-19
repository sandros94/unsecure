# Encoding Utilities (`unsecure/utils`)

JSON-style codecs for hex, base64 (incl. URL-safe), and base32 — each exposes
`stringify` (bytes → text) and `parse` (text → bytes), available from the
`unsecure/utils` subpath and re-exported from the main barrel.

```ts
import { Hex, Base64, Base32 } from "unsecure/utils";

Hex.stringify(bytes); // "deadbeef…"
Hex.parse("deadbeef", { returnAs: "bytes" }); // Uint8Array
```

For CDN delivery prefer the `unsecure/utils` subpath; for bundlers either the
subpath or the main barrel is fine (tree-shakes under `sideEffects: false`).

## Exports

```ts
import {
  Hex,
  Base64,
  Base32,
  textEncoder,
  textDecoder,
  // types
  type DecodeReturnAs,
  type DecodeOptions,
  type Base64Alphabet,
  type Base32Alphabet,
} from "unsecure/utils";
```

## Common shape

Every codec follows the same contract:

- **`stringify(data, options?)`** — `data` is `Uint8Array` or a `string` (UTF-8
  encoded first). Returns the encoded string. `null` / `undefined` throws `TypeError`.
- **`parse(input, options?)`** — `input` is the encoded `string` (or its
  `Uint8Array` bytes). Returns bytes or a UTF-8 string; see `returnAs` below.
  **Strict by default** — malformed input throws `SyntaxError`. Pass
  `{ loose: true }` to skip/normalize malformed input instead.

`returnAs` mirrors the input when omitted: `string` in → `string` out (bytes
decoded as UTF-8), `Uint8Array` in → `Uint8Array` out. Override with
`{ returnAs: "string" | "uint8array" | "bytes" }` (`"bytes"` aliases `"uint8array"`).

## Hex

```ts
Hex.stringify("hello"); // "68656c6c6f"
Hex.stringify(new Uint8Array([0xde, 0xad])); // "dead"
Hex.parse("68656c6c6f"); // "hello"
Hex.parse("68656c6c6f", { returnAs: "uint8array" }); // Uint8Array

Hex.parse("zz"); // throws SyntaxError (strict)
Hex.parse("abc", { loose: true, returnAs: "bytes" }); // Uint8Array [0xab] (drops the odd nibble)
```

## Base64

Standard by default. Pass `{ alphabet: "base64url" }` for URL-safe (`-_`,
unpadded by default). `{ padding: false }` drops `=` on any alphabet.

```ts
Base64.stringify(new Uint8Array([1, 2, 3])); // "AQID"
Base64.stringify(bytes, { padding: false }); // unpadded
Base64.stringify(bytes, { alphabet: "base64url" }); // URL-safe, unpadded

Base64.parse("AQID", { returnAs: "bytes" }); // Uint8Array
Base64.parse(token, { alphabet: "base64url" }); // strict URL-safe decode
Base64.parse(untrusted, { loose: true }); // tolerant (accepts either alphabet)
```

## Base32

`alphabet` accepts `"base32"` (RFC 4648, default), `"base32hex"`,
`"crockford"`, or a custom 32-character string. Padded by default except
Crockford; `{ padding: false }` to override.

```ts
Base32.stringify("foobar"); // "MZXW6YTBOI======"
Base32.stringify(secret, { padding: false }); // unpadded (e.g. OTP secrets)
Base32.stringify(bytes, { alphabet: "crockford" }); // Crockford, unpadded
Base32.parse("MZXW6YTBOI", { returnAs: "bytes" }); // raw bytes

// Crockford decode is case-insensitive and maps O→0, I/L→1.
Base32.parse(id, { alphabet: "crockford" });
```

## Strictness & runtimes

`parse` is strict by default to avoid decode malleability (distinct inputs
decoding to the same bytes). Where a runtime ships the TC39 methods
(`Uint8Array.fromBase64`/`fromHex`), strict decode uses them directly.

- **base64** tolerates ASCII whitespace in strict mode (matches native `fromBase64`).
- **hex** rejects whitespace in strict mode (matches native `fromHex`).
- **base32** rejects whitespace in strict mode; `{ loose: true }` skips it.

Use `{ loose: true }` for user-supplied values that may be formatted (e.g.
OTP secrets pasted with spaces).

## Shared instances

```ts
import { textEncoder, textDecoder } from "unsecure/utils";

const bytes = textEncoder.encode("hello");
const str = textDecoder.decode(bytes);
```

## Deprecated (removed in 0.3.0)

The flat functions are now thin `loose` wrappers over the codecs — replace them:

| Deprecated              | Replacement                                                                |
| ----------------------- | -------------------------------------------------------------------------- |
| `hexEncode(x)`          | `Hex.stringify(x)`                                                         |
| `hexDecode(x, o)`       | `Hex.parse(x, o)` (strict — add `{ loose: true }` to match old behavior)   |
| `base64Encode(x)`       | `Base64.stringify(x)`                                                      |
| `base64Decode(x, o)`    | `Base64.parse(x, o)` (add `{ loose: true }` for old behavior)              |
| `base64UrlEncode(x)`    | `Base64.stringify(x, { alphabet: "base64url" })`                           |
| `base64UrlDecode(x, o)` | `Base64.parse(x, { alphabet: "base64url", ...o })` (add `{ loose: true }`) |
| `base32Encode(x)`       | `Base32.stringify(x)` (padded) or `{ padding: false }`                     |
| `base32Decode(x, o)`    | `Base32.parse(x, o)` (add `{ loose: true }` for old behavior)              |

## Internal: Buffer / native detection

Encoding prefers Node.js `Buffer` when available, then the TC39
`Uint8Array.toBase64`/`fromBase64`/`toHex`/`fromHex` methods, then manual
fallbacks. Strict decode prefers the TC39 methods (Buffer can't enforce an
alphabet). Transparent to callers — the API is identical everywhere.
