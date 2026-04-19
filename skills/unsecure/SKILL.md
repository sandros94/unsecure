---
name: unsecure
description: "Expert knowledge for working with unsecure — a zero-dependency, runtime-agnostic cryptographic utilities library using the Web Crypto API. Use this skill whenever the user is working with hashing, HMAC, OTP, secure string generation, constant-time comparison, entropy analysis, randomness utilities, or object sanitization. Trigger on any mention of unsecure or related cryptographic operations."
metadata:
  version: 0.1.0
  library: unsecure
  library-version: 0.1.0
  org: sandros94
  documentation: https://github.com/sandros94/unsecure
---

# unsecure Skill

> Zero-dependency, runtime-agnostic cryptographic utilities built on the Web Crypto API.

**Package:** `unsecure` (npm)
**Requires:** Node.js ^22.12 or >=24, or any runtime with Web Crypto (Bun, Deno, browsers)

**Two entry points:**

- `unsecure` — all crypto utilities (also re-exports `utils` as a namespace)
- `unsecure/utils` — encoding helpers (hex, base64, base32)

**CDN usage** (browsers, Deno, Bun):

```ts
import { hash, hmac, totp } from "https://esm.sh/unsecure";
import { hexEncode, base64Encode } from "https://esm.sh/unsecure/utils";
```

---

## Reference Files

Load the relevant file(s) based on what the user needs:

### [hash.md](./references/hash.md)

SHA hashing via `crypto.subtle.digest`. Load when working with `hash()`, content hashing, data integrity checks, or token storage patterns.

### [hmac.md](./references/hmac.md)

HMAC signing and verification. Load when working with `hmac()`, `hmacVerify()`, webhook signature verification, or message authentication.

### [otp.md](./references/otp.md)

One-time passwords (RFC 4226 HOTP / RFC 6238 TOTP). Load when working with `hotp()`, `totp()`, `hotpVerify()`, `totpVerify()`, `generateOTPSecret()`, `otpauthURI()`, two-factor authentication, or QR code provisioning.

### [generate.md](./references/generate.md)

Secure string/token/password generation. Load when working with `secureGenerate()`, API tokens, passwords, PINs, or custom character set generation.

### [compare.md](./references/compare.md)

Constant-time comparison. Load when working with `secureCompare()`, the `strict` option, timing-attack prevention, or secure equality checks for tokens/secrets.

### [entropy.md](./references/entropy.md)

Shannon entropy analysis. Load when working with `entropy()`, measuring randomness quality, password strength validation, or input quality heuristics.

### [random.md](./references/random.md)

Randomness utilities. Load when working with `createSecureRandomGenerator()`, `secureRandomNumber()`, `secureRandomBytes()`, `secureShuffle()`, `randomJitter()`, cryptographic random number generation, fair shuffling, or timing jitter.

### [sanitize.md](./references/sanitize.md)

Prototype-pollution sanitization. Load when working with `sanitizeObject()`, untrusted JSON input, or request body sanitization middleware.

### [utils.md](./references/utils.md)

Encoding/decoding utilities. Load when working with `hexEncode`/`hexDecode`, `base64Encode`/`base64Decode`, `base64UrlEncode`/`base64UrlDecode`, `base32Encode`/`base32Decode`, `textEncoder`/`textDecoder`, or the `unsecure/utils` entry point.

---

## Architecture Notes

- **Zero dependencies** — everything is built on Web Crypto API (`crypto.subtle`, `crypto.getRandomValues`)
- Internal buffer utilities detect Node.js `Buffer` for fastest-path encoding, with fallbacks to TC39 `Uint8Array` methods or manual implementations
- Random generator uses a 256-element `Uint32Array` buffer with rejection sampling to avoid modulo bias
- `secureRandomBytes()` handles the 65536-byte `crypto.getRandomValues` limit via chunking
- All verification functions (`hmacVerify`, `hotpVerify`, `totpVerify`) use `secureCompare()` internally
