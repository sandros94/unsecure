# hash()

Async SHA hashing via `crypto.subtle.digest`. Returns hex string for string input, `Uint8Array` for buffer input — unless `returnAs` overrides.

## Signature

```ts
async function hash(
  data: string | BufferSource,
  options?: {
    algorithm?: "SHA-1" | "SHA-256" | "SHA-384" | "SHA-512"; // default: "SHA-256"
    returnAs?: "hex" | "base64" | "b64" | "base64url" | "b64url" | "uint8array" | "bytes";
  },
): Promise<string | Uint8Array>;
```

**Return type inference:**

- `string` input → `string` (hex) by default
- `BufferSource` input → `Uint8Array` by default
- Explicit `returnAs` overrides the default

## Examples

```ts
import { hash } from "unsecure/hash";

// Default: SHA-256, returns hex string
const hex = await hash("hello world");

// SHA-512, base64 output
const b64 = await hash("data", { algorithm: "SHA-512", returnAs: "base64" });

// Raw bytes
const bytes = await hash("data", { returnAs: "bytes" });

// Hash a Uint8Array — returns Uint8Array by default
const buf = new TextEncoder().encode("binary data");
const hashBuf = await hash(buf); // Uint8Array

// Explicit returnAs overrides the default
const hashHexFromBuffer = await hash(buf, { returnAs: "hex" }); // string
```

## Use Case: API Token Storage

Never store raw tokens — store their hash instead:

```ts
import { hash } from "unsecure/hash";
import { secureGenerate } from "unsecure/generate";
import { secureCompare } from "unsecure/compare";

// Generate a new API token
const token = secureGenerate({ length: 48, specials: false });

// Store the hash (never store raw tokens)
const tokenHash = await hash(token);
// Store tokenHash in database

// On request: verify token
async function verifyToken(receivedToken: string, storedHash: string) {
  const receivedHash = await hash(receivedToken);
  return secureCompare(storedHash, receivedHash);
}
```

## Pitfall: Streaming / Large Files

`hash()` uses `crypto.subtle.digest` which requires the **entire data in memory**. The Web Crypto API does not support incremental digests.

```ts
// ❌ Will load entire file into memory
const fileHash = await hash(hugeFileBuffer);

// ✅ For large files, use platform-specific streaming APIs
// Node.js: crypto.createHash()
// Deno: crypto.subtle.digestStream() (if available)
```
