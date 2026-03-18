# Encoding Utilities (`unsecure/utils`)

Supplementary encoding/decoding utilities for hex, base64, base64url, and base32 — available from the `unsecure/utils` entry point.

Also accessible as a namespace from the main entry: `import { utils } from "unsecure"`.

## Exports

```ts
import {
  hexEncode,
  hexDecode,
  base64Encode,
  base64Decode,
  base64UrlEncode,
  base64UrlDecode,
  base32Encode,
  base32Decode,
  textEncoder,
  textDecoder,
} from "unsecure/utils";
```

## Hex

```ts
hexEncode("hello"); // "68656c6c6f"
hexEncode(new Uint8Array([0xde, 0xad])); // "dead"
hexDecode("68656c6c6f"); // "hello"
hexDecode("68656c6c6f", { returnAs: "uint8array" }); // Uint8Array
```

## Base64

```ts
base64Encode("hello"); // "aGVsbG8="
base64Encode(new Uint8Array([1, 2, 3])); // "AQID"
base64Decode("aGVsbG8="); // "hello"
base64Decode("aGVsbG8=", { returnAs: "uint8array" }); // Uint8Array
```

## Base64 URL

URL-safe base64 without padding.

```ts
base64UrlEncode("hello"); // "aGVsbG8"
base64UrlDecode("aGVsbG8"); // "hello"
base64UrlDecode("aGVsbG8", { returnAs: "uint8array" }); // Uint8Array
```

## Base32 (RFC 4648)

Commonly used for OTP secrets.

```ts
base32Encode("foobar"); // "MZXW6YTBOI======"
base32Encode(new Uint8Array([1, 2])); // padded base32 string
base32Decode("MZXW6YTBOI"); // Uint8Array (case-insensitive, handles unpadded)
```

Note: `base32Decode` always returns `Uint8Array` (no string return mode).

## Shared Instances

```ts
import { textEncoder, textDecoder } from "unsecure/utils";

const bytes = textEncoder.encode("hello");
const str = textDecoder.decode(bytes);
```

## Return Type Inference

Decode functions (`hexDecode`, `base64Decode`, `base64UrlDecode`) mirror input type by default:

- `string` input → `string` output
- `Uint8Array` input → `Uint8Array` output

Override with `{ returnAs: "uint8array" | "string" }`.

## Pitfall: Ignoring the returnAs Type System

`hash()`, `hmac()`, and the decode utilities all infer return types based on input. Mixing input types without `returnAs` can cause surprise types.

```ts
// String input → returns string (hex)
const h1 = await hash("data"); // string
// Buffer input → returns Uint8Array
const h2 = await hash(new Uint8Array([1])); // Uint8Array

// ✅ Be explicit when you need a specific type
const h3 = await hash(buffer, { returnAs: "hex" }); // always string
const decoded = hexDecode(hexStr, { returnAs: "uint8array" }); // always Uint8Array
```

## Internal: Buffer Detection

The encoding utilities internally detect Node.js `Buffer` for fastest-path encoding when available, with fallbacks to `Uint8Array.toBase64`/`fromBase64`/`toHex`/`fromHex` (TC39 proposals), then to manual implementations. This is transparent to users — the API is the same everywhere.
