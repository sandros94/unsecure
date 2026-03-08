<!-- NOTE: Keep this file updated as the project evolves. When making architectural changes, adding new patterns, or discovering important conventions, update the relevant sections. -->

## Project Overview

`unsecure` is a zero-dependency, runtime-agnostic library of cryptographically-secure utilities built on the Web Crypto API. It targets Node.js ^22.12 or >=24, and works in any runtime supporting Web Crypto (browsers, Bun, Deno).

## Commands

- **Build:** `pnpm build` (uses `obuild`)
- **Dev:** `pnpm dev` (runs `playground/main.ts` with bun --watch)
- **Lint:** `pnpm lint` (runs `oxlint` then `oxfmt --check`)
- **Format:** `pnpm format` (runs `automd`, `oxlint --fix`, `oxfmt`)
- **Typecheck:** `pnpm typecheck` (uses `tsgo --noEmit`)
- **Test all:** `pnpm test` (vitest run)
- **Test single file:** `pnpm vitest run test/<file>.test.ts`
- **Benchmarks:** `pnpm bench`
- **Coverage:** `pnpm test:coverage`

## Architecture

Two entry points exported via `package.json` exports:

- **`unsecure`** (main) — `src/index.ts` re-exports from:
  - `src/hash.ts` — `hash()`: async hashing via `crypto.subtle.digest`
  - `src/hmac.ts` — `hmac()`, `hmacVerify()`: HMAC signing and constant-time verification
  - `src/otp.ts` — `hotp()`, `hotpVerify()`, `totp()`, `totpVerify()`, `generateOTPSecret()`, `otpauthURI()`: RFC 4226/6238 OTP
  - `src/generate.ts` — `secureGenerate()`: secure string/token generation with customizable charsets, buffered RNG
  - `src/verification.ts` — `secureCompare()`: constant-time comparison to prevent timing attacks
  - `src/entropy.ts` — `entropy()`: Shannon entropy analysis
  - `src/random.ts` — `createSecureRandomGenerator()`, `secureRandomNumber()`, `secureRandomBytes()`, `secureShuffle()`, `randomJitter()`
  - `src/sanitize.ts` — `sanitizeObject()`: in-place prototype-pollution sanitization

- **`unsecure/utils`** — `src/utils.ts` re-exports from `src/internal/utils/`:
  - `base32.ts` — base32 encode/decode (RFC 4648)
  - `base64.ts` — base64/base64url encode/decode
  - `hex.ts` — hex encode/decode
  - Also provides shared `textEncoder` and `textDecoder`

The `src/random.ts` generator uses a 256-element `Uint32Array` buffer to batch `crypto.getRandomValues` calls, with rejection sampling to avoid modulo bias.

## Key Conventions

- All crypto uses the Web Crypto API (`crypto.subtle`, `crypto.getRandomValues`) — no Node.js-specific crypto imports
- Package manager is **pnpm** (v10.30.3, via corepack)
- Linting uses **oxlint** and formatting uses **oxfmt** (not eslint/prettier)
- TypeScript checking uses **tsgo** (not tsc)
- Build uses **obuild** (not unbuild)
- Tests are colocated in `test/` with `.test.ts` suffix, benchmarks use `.bench.ts`
