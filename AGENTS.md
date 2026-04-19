<!-- NOTE: Keep this file updated as the project evolves. When making architectural changes, adding new patterns, or discovering important conventions, update the relevant sections. -->

## Project Overview

`unsecure` is a zero-dependency, runtime-agnostic library of cryptographically-secure utilities built on the Web Crypto API. It targets Node.js ^22.12 or >=24, and works in any runtime supporting Web Crypto (browsers, Bun, Deno).

## Core Principle — Ask First

**When in doubt, ask before acting.** It is always more important to understand the vision and the request than to assume. There is no shame or wasted time in asking clarifying questions — this applies to every conversation and every task in this project.

### Q&A Sessions

When a task involves design decisions, ambiguity, or changes to the project vision, run a structured Q&A session before implementing. Format each question with **2–4 concrete options** the user can pick from, mix, or override with a custom answer. This keeps sessions concise and efficient:

- **Number questions** (Q1, Q2, …) so answers can reference them quickly.
- **Each option** should be a short, self-contained description (1–2 sentences) with a label (A, B, C, D).
- **Avoid open-ended questions** — always propose options. If genuinely unsure, provide your best guesses as options.
- **Group related questions** in a single message rather than asking one at a time.
- After answers, **synthesize** the decisions into a summary and confirm before implementing.
- If the answers reveal further ambiguity, do another focused round — don't assume.

## Commands

- **Build:** `pnpm build` (uses `obuild`)
- **Dev prepare:** `pnpm dev:prepare` (runs `obuild --stub` for development stubs)
- **Lint:** `pnpm lint` (runs `oxlint` then `oxfmt --check`)
- **Format:** `pnpm fmt` (runs `automd`, `oxlint --fix`, `oxfmt`)
- **Typecheck:** `pnpm typecheck` (uses `tsgo --noEmit`)
- **Test all:** `pnpm test` (vitest run)
- **Test single file:** `pnpm vitest run test/<file>.test.ts`
- **Benchmarks:** `pnpm bench`
- **Coverage:** `pnpm test:coverage`

## Architecture

Two entry points exported via `package.json` exports:

- **`unsecure`** (main) — `src/index.ts` re-exports from (also re-exports `utils` as a namespace via `export * as utils`):
  - `src/hash.ts` — `hash()`: async hashing via `crypto.subtle.digest`
  - `src/hmac.ts` — `hmac()`, `hmacVerify()`: HMAC signing and constant-time verification
  - `src/otp.ts` — `hotp()`, `hotpVerify()`, `totp()`, `totpVerify()`, `generateOTPSecret()`, `otpauthURI()`: RFC 4226/6238 OTP
  - `src/generate.ts` — `secureGenerate()`: secure string/token generation with customizable charsets, buffered RNG
  - `src/compare.ts` — `secureCompare()`: constant-time comparison (returns `false` on empty/undefined `expected` by default; opt-in `strict: true` preserves the pre-0.2 throw)
  - `src/entropy.ts` — `entropy()`: Shannon entropy analysis
  - `src/random.ts` — `createSecureRandomGenerator()`, `secureRandomNumber()`, `secureRandomBytes()`, `secureShuffle()`, `randomJitter()`
  - `src/sanitize.ts` — `sanitizeObject()` (in-place, single-pass), `sanitizeObjectCopy()` (non-mutating, cycle-preserving copy), `safeJsonParse()` (parse-time prototype-pollution reviver)
  - `src/internal/encoding.ts` — shared `encodeBytes(bytes, returnAs, source)` helper used by `hash`, `hmac`, and `hkdf` to keep `returnAs` behavior consistent

- **`unsecure/utils`** — `src/utils.ts` re-exports from `src/internal/utils/`:
  - `base32.ts` — base32 encode/decode (RFC 4648)
  - `base64.ts` — base64/base64url encode/decode
  - `hex.ts` — hex encode/decode
  - Also provides shared `textEncoder` and `textDecoder`

The `src/random.ts` generator uses a 256-element `Uint32Array` buffer to batch `crypto.getRandomValues` calls, with rejection sampling to avoid modulo bias.

## Key Conventions

- All crypto uses the Web Crypto API (`crypto.subtle`, `crypto.getRandomValues`) — no Node.js-specific crypto imports
- Package manager is **pnpm** (v10.32.1, via corepack)
- Linting uses **oxlint** and formatting uses **oxfmt** (not eslint/prettier)
- TypeScript checking uses **tsgo** (not tsc)
- Build uses **obuild** (not unbuild)
- Tests are colocated in `test/` with `.test.ts` suffix, benchmarks use `.bench.ts`
