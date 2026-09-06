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
- **Format:** `pnpm fmt` (runs `oxlint --fix`, `oxfmt`)
- **Typecheck:** `pnpm typecheck` (uses `tsc --noEmit`)
- **Test all:** `pnpm test` (vitest run)
- **Test single file:** `pnpm vitest run test/<file>.test.ts`
- **Benchmarks:** `pnpm bench`
- **Coverage:** `pnpm test:coverage`

## Architecture

**Per-module subpath exports, plus a convenience barrel.** Every public module is listed as its own bundle input in `build.config.ts` and mapped to an `./<name>` entry in `package.json` `exports`, producing one `dist/<name>.mjs` + `dist/<name>.d.mts` pair per module. CDN consumers (e.g. `https://esm.sh/unsecure/uuid`) tree-shake only what they import. Bundler consumers (Vite, etc.) can still use `import { x } from "unsecure"` via the barrel at `src/index.ts` — both paths coexist. Public modules:

- `src/compare.ts` → `unsecure/compare` — `secureCompare()`: constant-time comparison of text or any `BytesSource` (returns `false` on empty/undefined `expected` by default; opt-in `strict: true` preserves the pre-0.2 throw). `received` is untrusted: anything that is not text or bytes — `null`, a number, a plain array — is a mismatch, never a throw; a wrong `expected` type is a caller bug and throws `TypeError`
- `src/entropy.ts` → `unsecure/entropy` — `entropy()`: Shannon unigram entropy + bigram entropy (catches local structure) + longest-monotonic-run detection (catches sorted/reverse-sorted fakes). All additive; unigram fields unchanged.
- `src/errors.ts` → `unsecure/errors` — `UnsecureError` and `UnsecureErrorCode`: the one class every function in the library throws, carrying a machine-readable `code` (`INVALID_TYPE`, `OUT_OF_RANGE`, `MALFORMED`, `UNSUPPORTED`, `FROZEN`, `PLATFORM`) and, where the failure came from outside, a `cause`
- `src/generate.ts` → `unsecure/generate` — `secureGenerate()`: secure string/token generation with customizable charsets, buffered RNG. `length` is an integer >= 1 counted in code points, a `Date` timestamp must be valid, sets are iterated by code point (no lone surrogates) and must not repeat a character within or across sets — a repeat biases the draw
- `src/hash.ts` → `unsecure/hash` — `hash()`: async hashing via `crypto.subtle.digest`; input is `string | BytesSource` coerced through `toCryptoBytes`
- `src/hkdf.ts` → `unsecure/hkdf` — `hkdf()`: HKDF key derivation (RFC 5869) via `crypto.subtle.deriveBits`, with `returnAs` matching `hash`/`hmac`; `ikm`/`salt`/`info` are `string | BytesSource`
- `src/hmac.ts` → `unsecure/hmac` — `hmac()`, `hmacVerify()`: HMAC signing and constant-time verification. An empty secret throws `RangeError`; `hmacVerify` compares raw MAC bytes and decodes a string `signature` strictly by `returnAs` (hex when it names bytes), while `null`/`undefined`/malformed signatures verify as `false`
- `src/otp.ts` → `unsecure/otp` — `hotp()`, `hotpVerify()`, `totp()`, `totpVerify()`, `generateOTPSecret()`, `otpauthURI()`: RFC 4226/6238 OTP. Every numeric option is range-checked at the boundary (`counter` >= 0, `digits` 6–8, `period` >= 1, `window` >= 0, `time` finite) and the resolved secret must be non-empty; the `otp` argument of both verifies is `string | null | undefined` and anything else is invalid, never a throw. Both verifies walk the whole window on every call (no early return, so the HMAC count never leaks which step matched) and report the nearest matching `delta` plus the absolute `counter` / `step` that matched (`HOTPVerifyResult` / `TOTPVerifyResult`); `totpVerify()` refuses every candidate at or before `lastAccepted`, the caller-persisted step of the last success (RFC 6238 §5.2 replay protection — the library holds no state). `otpauthURI()` percent-encodes every value (`%20`, not `+`), canonicalizes a string secret through base32, and validates `type`
- `src/random.ts` → `unsecure/random` — `createSecureRandomGenerator()`, `secureRandomNumber()` and `randomJitter()` (both drawing from one shared buffered generator), `secureRandomBytes()` (integer length, ceiling `2**31 - 1`), `secureShuffle()`
- `src/sanitize.ts` → `unsecure/sanitize` — `sanitizeObject()` (in-place, single-pass), `sanitizeObjectCopy()` (non-mutating, cycle-preserving copy), `safeJsonParse()` (`JSON.parse` plus the in-place sanitizer). All three traverse with an explicit stack, so deep nesting cannot overflow the call stack. `sanitizeObject` walks into every object it reaches, stripping dangerous own keys wherever it finds them; `sanitizeObjectCopy` rebuilds only arrays and plain objects and carries every other value into the copy by reference. Neither reads what a `Map`, `Set` or other non-plain object holds, so those contents are never sanitized
- `src/uuid.ts` → `unsecure/uuid` — `uuidv4()`, `uuidv7(timestamp?)`, `secureUUID` (alias of `uuidv7`), `createUUIDv7Generator()` (dual-clock: counter driven by `Date.now()` for per-process uniqueness, embedded ts honors the optional caller argument verbatim — RFC 9562 §6.2 Method 3 counter, safe for out-of-order backfills; a throwing `.next(invalid)` does not mutate state), `uuidv7Timestamp()`, `isUUIDv4()`, `isUUIDv7()`
- `src/utils/index.ts` → `unsecure/utils` — six codec functions (`hexStringify`/`hexParse`, `base64Stringify`/`base64Parse`, `base32Stringify`/`base32Parse`; strict decode is canonical and padding-agnostic, `{ loose: true }` drops what it cannot use; base64 takes `{ alphabet: "base64url" }`, base32 takes `base32`/`base32hex`/`crockford`/a validated custom 32-char alphabet), the `Hex` / `Base64` / `Base32` objects that group them JSON-style, and the shared `textEncoder` / `textDecoder` instances. Also re-exported flat from the main barrel — tree-shakes cleanly under `sideEffects: false`, so importing one flat function ships one codec. For CDN delivery prefer the subpath.

Internal-only (not exported, inlined into the bundles that import them):

- `src/_internal/assert.ts` — `assertInteger(source, name, value, min, max?)` and `showValue()`: the one range check behind every bounded numeric option (`otp`, `generate`, `hkdf`, `random`), so the wording and the accepted range are identical everywhere
- `src/_internal/bytes.ts` — `toBytes()` / `toCryptoBytes()`: the one place a caller value (`string` or any `BytesSource`) becomes a `Uint8Array`; also owns the shared `textEncoder`. `toCryptoBytes` copies `SharedArrayBuffer`-backed views, which Web Crypto refuses.
- `src/_internal/algorithm.ts` — `HASH_LENGTH` (digest sizes in bytes) and `normalizeAlgorithm()`: the single place an algorithm name is accepted. `hash`, `hmac`, `hkdf` and `otp` resolve through it, so names match case-insensitively (`"sha-256"` works) and anything else throws a `RangeError` before Web Crypto is reached
- `src/_internal/encoding.ts` — shared `encodeBytes(bytes, returnAs, source)` / `decodeBytes(text, returnAs, source)` pair used by `hash`, `hmac`, and `hkdf` to keep `returnAs` behavior consistent in both directions
- `src/utils/_codec.ts` — shared codec primitives (`textEncoder`/`textDecoder`, `DecodeReturnAs`/`DecodeOptions`, input/output helpers); a leaf module so the `utils/index.ts` barrel can re-export without an import cycle
- `src/utils/_buffer.ts` — Node `Buffer` fast-path detection for the encoding helpers

When adding a new public module, three edits are required in lockstep: add the input to `build.config.ts`, add the `./<name>` entry to `package.json` `exports`, and (if user-facing) add a `skills/unsecure/references/<name>.md` entry plus `skills/unsecure/SKILL.md` link.

The `src/random.ts` generator uses a 256-element `Uint32Array` buffer to batch `crypto.getRandomValues` calls, with rejection sampling to avoid modulo bias. `secureRandomNumber` and `randomJitter` are thin wrappers over a module-level instance of it, so the module has exactly one draw path and no unbiased-vs-biased split.

## Key Conventions

- Everything the library throws is an `UnsecureError` (`src/errors.ts`) with a `code` from the documented union; no native `TypeError` / `RangeError` / `SyntaxError` is constructed in `src/`, and a platform failure is re-thrown as `PLATFORM` with the original as `cause`. The code union is growable — adding a member is a minor, so callers are told to keep a `default` branch. Verify functions (`secureCompare`, `hmacVerify`, `hotpVerify`, `totpVerify`) still return `false` for untrusted input and throw only for caller or configuration mistakes
- All crypto uses the Web Crypto API (`crypto.subtle`, `crypto.getRandomValues`) — no Node.js-specific crypto imports
- Package manager is **pnpm** (v11.13.0, via corepack)
- Linting uses **oxlint** and formatting uses **oxfmt** (not eslint/prettier)
- TypeScript checking uses native **tsc** (`typescript` v7, the Go implementation)
- Build uses **obuild** (not unbuild)
- Tests are colocated in `test/` with `.test.ts` suffix, benchmarks use `.bench.ts`
