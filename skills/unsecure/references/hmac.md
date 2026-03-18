# hmac() / hmacVerify()

HMAC signing and constant-time verification via `crypto.subtle`.

## Signatures

```ts
async function hmac(
  secret: string | BufferSource,
  data: string | BufferSource,
  options?: {
    algorithm?: "SHA-1" | "SHA-256" | "SHA-384" | "SHA-512"; // default: "SHA-256"
    returnAs?: "hex" | "base64" | "base64url" | "bytes" | "uint8array";
  },
): Promise<string | Uint8Array>;

async function hmacVerify(
  secret: string | BufferSource,
  data: string | BufferSource,
  signature: string | Uint8Array,
  options?: { algorithm?; returnAs? },
): Promise<boolean>;
```

**Return type inference** (for `hmac()`):

- `string` data → `string` (hex) by default
- `BufferSource` data → `Uint8Array` by default
- Explicit `returnAs` overrides the default

`hmacVerify()` uses `secureCompare()` internally for constant-time comparison.

## Examples

```ts
import { hmac, hmacVerify } from "unsecure";

// Sign a string — returns hex by default
const sig = await hmac("my-secret-key", "payload data");

// Sign with SHA-512, base64 output
const sig64 = await hmac("key", "data", {
  algorithm: "SHA-512",
  returnAs: "base64",
});

// Verify (constant-time comparison internally)
const isValid = await hmacVerify("my-secret-key", "payload data", sig);

// Verify a base64-encoded signature
const valid = await hmacVerify(secret, body, expectedBase64Sig, {
  returnAs: "base64",
});
```

## Use Case: Webhook Signature Verification

```ts
import { hmacVerify, randomJitter } from "unsecure";

async function handleWebhook(req: Request) {
  const signature = req.headers.get("x-signature")!;
  const body = await req.text();

  const valid = await hmacVerify(WEBHOOK_SECRET, body, signature);

  // Add jitter to prevent timing oracle even on failure path
  await randomJitter(10, 50);

  if (!valid) return new Response("Forbidden", { status: 403 });
  // process webhook...
}
```

## Pitfall: Using `===` Instead of hmacVerify()

```ts
// ❌ Vulnerable to timing attacks
if (computedHmac === receivedHmac) { ... }

// ✅ Use constant-time comparison
if (secureCompare(computedHmac, receivedHmac)) { ... }

// ✅ Or use hmacVerify() which does this internally
if (await hmacVerify(secret, data, receivedHmac)) { ... }
```

## Pitfall: Mismatched returnAs for Verification

When using `hmacVerify()`, the `returnAs` option must match the format of the `signature` argument. If the signature was produced as base64, verify with `{ returnAs: "base64" }`.

```ts
// ❌ Signature is base64 but verifying without returnAs (defaults to hex)
const sig = await hmac(secret, data, { returnAs: "base64" });
await hmacVerify(secret, data, sig); // WRONG — will fail

// ✅ Match the format
await hmacVerify(secret, data, sig, { returnAs: "base64" }); // correct
```
