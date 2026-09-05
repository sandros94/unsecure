# hmac() / hmacVerify()

HMAC signing and constant-time verification via `crypto.subtle`.

## Signatures

```ts
async function hmac(
  secret: string | BytesSource,
  data: string | BytesSource,
  options?: {
    algorithm?: "SHA-1" | "SHA-256" | "SHA-384" | "SHA-512"; // default: "SHA-256"
    returnAs?: "hex" | "base64" | "b64" | "base64url" | "b64url" | "uint8array" | "bytes";
  },
): Promise<string | Uint8Array>;

async function hmacVerify(
  secret: string | BytesSource,
  data: string | BytesSource,
  signature: string | BytesSource | null | undefined,
  options?: { algorithm?; returnAs? },
): Promise<boolean>;
```

Algorithm names are matched case-insensitively (`"sha-256"` works); anything else throws a `RangeError` naming the four supported digests, before Web Crypto is reached.

**Return type inference** (for `hmac()`):

- `string` data → `string` (hex) by default
- `BytesSource` data → `Uint8Array` by default
- Explicit `returnAs` overrides the default

`hmacVerify()` compares raw MAC bytes with `secureCompare()`, in constant time. A `BytesSource` signature is compared as-is; a **string** signature is decoded strictly with the codec named by `returnAs` — the format `hmac()` would have produced for the same options — so one options object serves both calls. `returnAs: "uint8array"` / `"bytes"` (and an omitted `returnAs`) read a string signature as hex.

Untrusted input never throws: a `null` or `undefined` signature, text that is not a canonical encoding, or a value that is neither text nor bytes simply fails to verify. An empty `secret` or an unsupported `algorithm` still throws — those describe the server, not the request.

`hmac()` and `hmacVerify()` both reject an empty `secret` with `RangeError: hmac: secret must not be empty.` before Web Crypto is reached; a secret that failed to load is a deployment bug, not a bad signature.

## Examples

```ts
import { hmac, hmacVerify } from "unsecure/hmac";

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
import { hmacVerify } from "unsecure/hmac";
import { randomJitter } from "unsecure/random";

async function handleWebhook(req: Request) {
  const signature = req.headers.get("x-signature");
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
// ❌ Signature is base64 but verifying without returnAs (decoded as hex)
const sig = await hmac(secret, data, { returnAs: "base64" });
await hmacVerify(secret, data, sig); // WRONG — will fail

// ✅ Match the format
await hmacVerify(secret, data, sig, { returnAs: "base64" }); // correct
```
