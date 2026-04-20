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

**Per-module subpath exports, plus a convenience barrel.** Every public module is listed as its own bundle input in `build.config.ts` and mapped to an `./<name>` entry in `package.json` `exports`, producing one `dist/<name>.mjs` + `dist/<name>.d.mts` pair per module. CDN consumers (e.g. `https://esm.sh/unsecure/uuid`) tree-shake only what they import. Bundler consumers (Vite, etc.) can still use `import { x } from "unsecure"` via the barrel at `src/index.ts` — both paths coexist. Public modules:

- `src/compare.ts` → `unsecure/compare` — `secureCompare()`: constant-time comparison (returns `false` on empty/undefined `expected` by default; opt-in `strict: true` preserves the pre-0.2 throw)
- `src/entropy.ts` → `unsecure/entropy` — `entropy()`: Shannon unigram entropy + bigram entropy (catches local structure) + longest-monotonic-run detection (catches sorted/reverse-sorted fakes). All additive; unigram fields unchanged.
- `src/generate.ts` → `unsecure/generate` — `secureGenerate()`: secure string/token generation with customizable charsets, buffered RNG
- `src/hash.ts` → `unsecure/hash` — `hash()`: async hashing via `crypto.subtle.digest`
- `src/hkdf.ts` → `unsecure/hkdf` — `hkdf()`: HKDF key derivation (RFC 5869) via `crypto.subtle.deriveBits`, with `returnAs` matching `hash`/`hmac`
- `src/hmac.ts` → `unsecure/hmac` — `hmac()`, `hmacVerify()`: HMAC signing and constant-time verification
- `src/otp.ts` → `unsecure/otp` — `hotp()`, `hotpVerify()`, `totp()`, `totpVerify()`, `generateOTPSecret()`, `otpauthURI()`: RFC 4226/6238 OTP
- `src/random.ts` → `unsecure/random` — `createSecureRandomGenerator()`, `secureRandomNumber()`, `secureRandomBytes()`, `secureShuffle()`, `randomJitter()`
- `src/sanitize.ts` → `unsecure/sanitize` — `sanitizeObject()` (in-place, single-pass), `sanitizeObjectCopy()` (non-mutating, cycle-preserving copy), `safeJsonParse()` (parse-time prototype-pollution reviver)
- `src/uuid.ts` → `unsecure/uuid` — `uuidv4()`, `uuidv7(timestamp?)`, `secureUUID` (alias of `uuidv7`), `createUUIDv7Generator()` (dual-clock: counter driven by `Date.now()` for per-process uniqueness, embedded ts honors the optional caller argument verbatim — RFC 9562 §6.2 Method 3 counter, safe for out-of-order backfills; a throwing `.next(invalid)` does not mutate state), `uuidv7Timestamp()`, `isUUIDv4()`, `isUUIDv7()`
- `src/utils/index.ts` → `unsecure/utils` — `hexEncode`/`hexDecode`, `base64Encode`/`base64Decode`, `base64UrlEncode`/`base64UrlDecode`, `base32Encode`/`base32Decode`, plus shared `textEncoder` / `textDecoder` instances. Also re-exported flat from the main barrel — tree-shakes cleanly under `sideEffects: false`. For CDN delivery prefer the subpath so only these helpers are shipped.

Internal-only (not exported, inlined into the bundles that import them):

- `src/_internal/encoding.ts` — shared `encodeBytes(bytes, returnAs, source)` helper used by `hash`, `hmac`, and `hkdf` to keep `returnAs` behavior consistent
- `src/utils/_buffer.ts` — Node `Buffer` fast-path detection for the encoding helpers

When adding a new public module, three edits are required in lockstep: add the input to `build.config.ts`, add the `./<name>` entry to `package.json` `exports`, and (if user-facing) add a `skills/unsecure/references/<name>.md` entry plus `skills/unsecure/SKILL.md` link.

The `src/random.ts` generator uses a 256-element `Uint32Array` buffer to batch `crypto.getRandomValues` calls, with rejection sampling to avoid modulo bias.

## Key Conventions

- All crypto uses the Web Crypto API (`crypto.subtle`, `crypto.getRandomValues`) — no Node.js-specific crypto imports
- Package manager is **pnpm** (v10.32.1, via corepack)
- Linting uses **oxlint** and formatting uses **oxfmt** (not eslint/prettier)
- TypeScript checking uses **tsgo** (not tsc)
- Build uses **obuild** (not unbuild)
- Tests are colocated in `test/` with `.test.ts` suffix, benchmarks use `.bench.ts`
