---
name: unsecure
description: "Working with unsecure, a zero-dependency cryptographic utilities library on the Web Crypto API: hashing, HMAC, HKDF, Argon2 password hashing, HOTP/TOTP, UUIDs, CSPRNG helpers, constant-time comparison, prototype-pollution sanitizing and strict codecs. Use whenever code imports from `unsecure` or `unsecure/*`, or the user asks how to do one of those tasks in Node, Bun, Deno, Workers or a browser."
metadata:
  version: 0.2.0
  library: unsecure
  org: sandros94
  documentation: https://unsecure.s94.dev
  repository: https://github.com/sandros94/unsecure
---

# unsecure

The documentation site is the single source of truth, and every page is also served as Markdown. Read the page for the task before writing code; do not rely on memory of the API.

- Index of every page: https://unsecure.s94.dev/llms.txt
- One page as Markdown: `https://unsecure.s94.dev/raw/<path>.md`, e.g. https://unsecure.s94.dev/raw/crypto/password-hashing.md
- Start with https://unsecure.s94.dev/raw/getting-started/concepts.md when the user is new to hashing, MACs, key derivation or constant-time comparison.

## Which page

| Task | Page |
| --- | --- |
| Store and check passwords (Argon2, pepper, rehash on login) | `/raw/crypto/password-hashing.md` |
| Sign or verify a message or webhook (HMAC) | `/raw/crypto/hashing/hmac.md`, recipe `/raw/examples/webhook-verification.md` |
| Fingerprint data (SHA-2) | `/raw/crypto/hashing/hash.md` |
| Derive several keys from one secret (HKDF) | `/raw/crypto/key-derivation.md` |
| Add a second factor (TOTP/HOTP, QR URI, replay refusal) | `/raw/crypto/otp.md`, recipe `/raw/examples/two-factor-auth.md` |
| Generate tokens, compare secrets, measure entropy | `/raw/generate/secrets.md` and its subpages |
| Random numbers, bytes, shuffles, jitter | `/raw/generate/random.md` |
| UUIDv4 / UUIDv7 | `/raw/generate/uuid.md` |
| Fair odds (decks, pity, cascades) | `/raw/generate/odds.md` |
| Parse untrusted JSON safely | `/raw/safety/sanitize.md` |
| Hex / base64 / base32 | `/raw/safety/codecs.md` |
| Errors and their codes | `/raw/safety/errors.md` |
| Install, subpaths vs barrel, CDN, migration | `/raw/getting-started/installation.md`, `/raw/getting-started/migration.md` |

## Rules that hold everywhere

- Import from the subpath (`unsecure/argon2`, `unsecure/otp`, …) unless a bundler is in play; a CDN import of the barrel downloads every module.
- `secureCompare`, `hmacVerify`, `hotpVerify`, `totpVerify` return `false` on untrusted input and throw only for configuration mistakes. `argon2Verify` throws for a stored string it cannot read and for a non-text password.
- Everything thrown is an `UnsecureError` with a `code`: `INVALID_TYPE`, `OUT_OF_RANGE`, `MALFORMED`, `UNSUPPORTED`, `FROZEN`, `PLATFORM`.
- The library holds no state: persist the TOTP `step` / HOTP `counter + 1` with a conditional write, and never ship a placeholder hash literal; build an absent-account dummy with `argon2Hash` at start-up.
- JOSE (JWT/JWS/JWE/JWK) is out of scope: use `unjwt` (https://unjwt.s94.dev).
