# hkdf()

HKDF key derivation (RFC 5869) via `crypto.subtle.deriveBits`. Extracts and expands input keying material into an arbitrary-length output key, with optional salt and context `info` for domain separation.

**Scope note:** HKDF is for deriving keys from **high-entropy** input (shared secrets, ECDH output, seeds). For **password-based** key derivation, use PBKDF2/Argon2 (available in the companion `unjwt` library) — HKDF does not provide the iteration count / memory cost needed to defend against brute force.

## Signature

```ts
async function hkdf(
  ikm: string | BufferSource,
  options?: {
    algorithm?: "SHA-1" | "SHA-256" | "SHA-384" | "SHA-512"; // default: "SHA-256"
    length?: number; // output bytes, default: 32, max: 255 * HashLen
    salt?: string | BufferSource; // default: empty (RFC 5869 §2.2 "no salt")
    info?: string | BufferSource; // default: empty
    returnAs?: "hex" | "base64" | "b64" | "base64url" | "b64url" | "uint8array" | "bytes"; // mirrors ikm type
  },
): Promise<string | Uint8Array>;
```

**Defaults:**

- `returnAs` mirrors the `ikm` input type when omitted: `string` ikm → hex `string` output; `BufferSource` ikm → `Uint8Array<ArrayBuffer>` output. Pass `returnAs` explicitly when the IKM shape and the desired output shape don't line up — key material is typically consumed as bytes, so pass `returnAs: "uint8array"` (or `"bytes"`) when deriving from a string IKM.
- `length` default is `32` (256-bit key — fits SHA-256, AES-256, etc.).
- `algorithm` default is `"SHA-256"`.

## Examples

```ts
import { hkdf } from "unsecure/hkdf";

// Derive a 256-bit key from a shared secret
const key = await hkdf(sharedSecret, { salt, info: "my-app/auth/v1" });

// 512-bit key, SHA-512, base64url output
const keyB64 = await hkdf(ikm, {
  algorithm: "SHA-512",
  length: 64,
  info: "encryption-key",
  returnAs: "base64url",
});

// String inputs are UTF-8 encoded
const derived = await hkdf("shared-secret-string", {
  salt: "a-pinch-of-salt",
  info: "ctx",
});
```

## Use Case: Domain Separation

The golden rule of HKDF: **one IKM, many keys via `info`.** Different `info` values produce cryptographically-independent keys, so a compromise of one does not compromise the others.

```ts
import { hkdf } from "unsecure/hkdf";

const ikm = sharedSecret; // e.g. from ECDH

// Independent keys for different purposes
const encKey = await hkdf(ikm, { salt, info: "encrypt" }); // for AES-GCM
const macKey = await hkdf(ikm, { salt, info: "authenticate" }); // for HMAC
const idKey = await hkdf(ikm, { salt, info: "derive-id" }); // for identifier
```

## Use Case: Session Key Expansion

```ts
import { hkdf } from "unsecure/hkdf";

async function deriveSessionKeys(sharedSecret: Uint8Array, sessionId: string) {
  // 64 bytes = two 256-bit keys concatenated
  const okm = await hkdf(sharedSecret, {
    salt: sessionId,
    info: "session-keys-v1",
    length: 64,
  });
  return {
    clientToServer: okm.slice(0, 32),
    serverToClient: okm.slice(32, 64),
  };
}
```

## Pitfall: Using HKDF on a Password

HKDF does **not** include a work factor. Running it on a low-entropy password is no stronger than running a single HMAC on that password — an attacker with a GPU can iterate billions of guesses per second.

```ts
// ❌ WRONG — passwords need a KDF with a work factor
const key = await hkdf(userPassword, { salt, info: "account" });

// ✅ Use PBKDF2 (see `unjwt`) or Argon2 for passwords
// Then optionally use HKDF to expand that into sub-keys.
```

## Pitfall: Reusing the Same `info` for Different Purposes

If two derivations use the same IKM + salt + info, they produce the same key. Always pick a unique, descriptive `info` per usage site, ideally including a version tag so you can rotate without breaking old data.

```ts
// ❌ Ambiguous — is this the MAC key or the encryption key?
await hkdf(ikm, { salt, info: "key" });

// ✅ Specific + versioned
await hkdf(ikm, { salt, info: "myapp/mac/v1" });
await hkdf(ikm, { salt, info: "myapp/enc/v1" });
```

## Pitfall: Exceeding `255 * HashLen`

RFC 5869 caps the output at `255 * HashLen` bytes per derivation (8160 for SHA-256, 16320 for SHA-512). `hkdf` throws `RangeError` before reaching Web Crypto rather than surfacing an opaque `OperationError`. If you need more material, derive multiple keys with distinct `info` values.

## Note

Because `returnAs` mirrors `ikm` when omitted, deriving from a `string` IKM returns a hex string — which is rarely what you want for raw key material. Pass `returnAs: "uint8array"` when deriving from strings and the bytes are about to be fed into another primitive (AES, HMAC, …). Pick `returnAs: "base64url"` only for transport/storage.
