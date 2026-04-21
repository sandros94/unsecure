import { bench, describe } from "vitest";

// -----------------------------------------------------------------------------
// Fallback-only base64 encode strategies.
//
// These reimplement just the slow path the library takes when:
//   - Node's `Buffer` is unavailable, AND
//   - `Uint8Array.prototype.toBase64` is unavailable.
//
// We intentionally skip the native fast paths so the bench measures only the
// fallback alternatives. Every approach writes to `btoa` (or avoids it
// entirely, for the pure-JS variant) — no `Buffer`, no `toBase64`.
// -----------------------------------------------------------------------------

/** Original library impl (pre-audit). Throws past V8's ~65535 arg limit. */
function encodeUnchunked(bytes: Uint8Array): string {
  return btoa(String.fromCodePoint(...bytes));
}

/** Chunked spread — initially considered fix, benched and rejected. Never wins. */
function encodeChunked(bytes: Uint8Array): string {
  const CHUNK = 0x8000; // 32 KiB
  if (bytes.length <= CHUNK) {
    return btoa(String.fromCharCode(...bytes));
  }
  let binary = "";
  for (let i = 0; i < bytes.length; i += CHUNK) {
    binary += String.fromCharCode(...bytes.subarray(i, i + CHUNK));
  }
  return btoa(binary);
}

/** Byte-by-byte + btoa. Fastest on V8 at ≤64 KiB. No arg-count ceiling. */
function encodeByteByByte(bytes: Uint8Array): string {
  let binary = "";
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]!);
  }
  return btoa(binary);
}

const _B64_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/** Pure JS encoder — bypasses `btoa` entirely. Wins at ≥256 KiB across engines. */
function encodePureJs(bytes: Uint8Array): string {
  const len = bytes.length;
  let result = "";
  let i = 0;
  for (; i + 2 < len; i += 3) {
    const b1 = bytes[i]!;
    const b2 = bytes[i + 1]!;
    const b3 = bytes[i + 2]!;
    result +=
      _B64_ALPHABET[b1 >> 2]! +
      _B64_ALPHABET[((b1 & 0x03) << 4) | (b2 >> 4)]! +
      _B64_ALPHABET[((b2 & 0x0f) << 2) | (b3 >> 6)]! +
      _B64_ALPHABET[b3 & 0x3f]!;
  }
  if (i < len) {
    const b1 = bytes[i]!;
    if (i + 1 < len) {
      const b2 = bytes[i + 1]!;
      result +=
        _B64_ALPHABET[b1 >> 2]! +
        _B64_ALPHABET[((b1 & 0x03) << 4) | (b2 >> 4)]! +
        _B64_ALPHABET[(b2 & 0x0f) << 2]! +
        "=";
    } else {
      result += _B64_ALPHABET[b1 >> 2]! + _B64_ALPHABET[(b1 & 0x03) << 4]! + "==";
    }
  }
  return result;
}

const _HYBRID_THRESHOLD = 0x10000; // 64 KiB

function encodeHybrid(bytes: Uint8Array): string {
  if (bytes.length <= _HYBRID_THRESHOLD) {
    return encodeByteByByte(bytes);
  }
  return encodePureJs(bytes);
}

function makeBytes(size: number): Uint8Array {
  // Deterministic filler — we only need byte variety for the encode to exercise
  // every alphabet slot, not cryptographic randomness. Also avoids the 64 KiB
  // per-call limit on `crypto.getRandomValues` for the larger sizes.
  const bytes = new Uint8Array(size);
  for (let i = 0; i < size; i++) {
    bytes[i] = i & 0xff;
  }
  return bytes;
}

// Fail the run early if any implementation drifts from the reference.
// Sample both branches of the hybrid (small + large) to cover them too.
for (const size of [1024, _HYBRID_THRESHOLD + 1024]) {
  const sanity = makeBytes(size);
  const ref = encodeByteByByte(sanity);
  if (size <= 32768 && encodeUnchunked(sanity) !== ref) throw new Error("unchunked drift");
  if (encodeChunked(sanity) !== ref) throw new Error("chunked drift");
  if (encodePureJs(sanity) !== ref) throw new Error("pureJs drift");
  if (encodeHybrid(sanity) !== ref) throw new Error("hybrid drift");
}

// V8's `String.fromCodePoint(...args)` arg limit is ~65535. Stay strictly
// under that for the unchunked runs so they don't throw mid-bench.
const UNCHUNKED_MAX = 32 << 10; // 32 KiB

// Byte-by-byte: initially capped at 64 KiB out of caution, but the first bench
// run showed it's actually the *fastest* strategy, so run it on every size.
const BYTE_BY_BYTE_MAX = Infinity;

const SIZES: ReadonlyArray<readonly [string, number]> = [
  ["1 KiB", 1 << 10],
  ["4 KiB", 4 << 10],
  ["16 KiB", 16 << 10],
  ["32 KiB", 32 << 10],
  ["64 KiB", 64 << 10],
  ["256 KiB", 256 << 10],
  ["1 MiB", 1 << 20],
];

describe("base64 encode — fallback-only paths (no Buffer, no toBase64)", () => {
  for (const [label, size] of SIZES) {
    describe(label, () => {
      const input = makeBytes(size);

      if (size <= UNCHUNKED_MAX) {
        bench("1. unchunked spread (current impl)", () => {
          encodeUnchunked(input);
        });
      }

      bench("2. chunked spread (proposed fix)", () => {
        encodeChunked(input);
      });

      if (size <= BYTE_BY_BYTE_MAX) {
        bench("3. byte-by-byte fromCharCode", () => {
          encodeByteByByte(input);
        });
      }

      bench("4. pure JS (no btoa)", () => {
        encodePureJs(input);
      });

      bench("5. hybrid byte-by-byte + pure JS", () => {
        encodeHybrid(input);
      });
    });
  }
});
