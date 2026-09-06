import { hexStringify } from "./utils/index.ts";
import { UnsecureError } from "./errors.ts";

/**
 * Generate a UUID version 4 (RFC 9562 §5.4) backed by
 * `crypto.getRandomValues`. 122 bits of randomness — collision probability
 * reaches ~50% at roughly 2^61 UUIDs (birthday bound).
 *
 * This does not delegate to `crypto.randomUUID()` — the version and variant
 * bits are set explicitly so the implementation stays self-contained and
 * decoupled from runtime-specific shortcuts.
 */
/* @__NO_SIDE_EFFECTS__ */
export function uuidv4(): string {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  // Version 4: set the high nibble of byte 6 to 0b0100.
  bytes[6] = (bytes[6]! & 0x0f) | 0x40;
  // Variant RFC 9562: set the top two bits of byte 8 to 0b10.
  bytes[8] = (bytes[8]! & 0x3f) | 0x80;
  return _formatUUID(bytes);
}

/**
 * Generate a UUID version 7 (RFC 9562 §5.7): a 48-bit Unix-millisecond
 * timestamp followed by 74 bits of random filler and the required
 * version/variant bits.
 *
 * UUIDs from different milliseconds sort chronologically, which makes them
 * suitable as database primary keys on ordered indexes. Within the same
 * millisecond the order is random — use {@link createUUIDv7Generator} if
 * you need strict monotonic ordering.
 *
 * @param timestamp Optional `Date` or Unix-millisecond `number` to embed
 *                  instead of `Date.now()`. Useful for testing, backfills,
 *                  and replaying historical events. Fractional numbers are
 *                  floored. Must resolve to a finite non-negative value
 *                  within the 48-bit range.
 * @throws {UnsecureError} `INVALID_TYPE` if `timestamp` is neither a `Date` nor a
 *                         `number`; `OUT_OF_RANGE` if it is not finite, is negative, or
 *                      exceeds `2^48 - 1` ms (~year 10,895).
 */
/* @__NO_SIDE_EFFECTS__ */
export function uuidv7(timestamp?: Date | number): string {
  return _formatV7Random(timestamp === undefined ? Date.now() : _coerceMs(timestamp));
}

/**
 * Alias of {@link uuidv7}. Use this when you just want "a secure UUID"
 * without committing to a version at the call site.
 */
export const secureUUID: typeof uuidv7 = uuidv7;

export interface UUIDv7Generator {
  /**
   * Produce the next UUIDv7.
   *
   * The internal counter and its reference timestamp are driven **only** by
   * `Date.now()` — never contaminated by a user-supplied argument. That
   * means the counter field is always monotonic relative to call order on
   * this process, and uniqueness is guaranteed regardless of what
   * timestamps callers feed.
   *
   * The 48-bit embedded timestamp field reflects the caller's intent:
   * - No argument → `Date.now()` (with same-ms / regression / overflow
   *   handling per RFC 9562 §6.2 Method 3).
   * - Argument → that exact value.
   *
   * Ordering of the emitted UUIDs:
   * - No argument → strictly monotonic. Each UUID sorts after the one before
   *   it, through same-ms calls, counter overflow, and clock regressions.
   * - Argument → UUIDs sort by their embedded timestamp, so out-of-order
   *   backfills land where the data says they belong rather than where the
   *   call happened to fall.
   * - Two calls carrying the *same* timestamp are ordered by the counter only
   *   while they fall in one wall-clock millisecond of this process. Across a
   *   millisecond boundary the counter reseeds randomly and the pair sorts in
   *   either order.
   *
   * Uniqueness holds in every one of those cases.
   *
   * @param timestamp Optional `Date` or Unix-millisecond `number` to embed
   *                  instead of `Date.now()`.
   * @throws {UnsecureError} `INVALID_TYPE` if `timestamp` is neither a `Date` nor a
   *                         `number`; `OUT_OF_RANGE` if it is not finite, is negative, or
   *                      exceeds `2^48 - 1` ms.
   */
  next(timestamp?: Date | number): string;
}

/**
 * Create a stateful UUIDv7 generator using a dual-clock design: the
 * internal counter and its reference timestamp progress **only** from
 * `Date.now()`, while the embedded 48-bit timestamp field reflects either
 * `Date.now()` or a caller-supplied value.
 *
 * Counter semantics follow RFC 9562 §6.2 Method 3 — the 12-bit `rand_a`
 * field is repurposed as a monotonic counter within a given wall-clock ms:
 *
 * - Each new wall-clock ms reseeds the counter with a random value in the
 *   lower half of the 12-bit range, leaving ≥2048 increments of headroom
 *   before overflow.
 * - On counter overflow (>4095 calls within one wall-clock ms), the
 *   internal reference timestamp advances by 1 ms and the counter reseeds.
 * - If `Date.now()` regresses (NTP adjust, VM pause, etc.), the internal
 *   reference is held and the counter keeps incrementing.
 *
 * Because the user-supplied timestamp never touches the internal reference,
 * out-of-order backfills are safe — UUIDs emitted for past events remain
 * unique and sort by their embedded timestamp.
 *
 * Strict monotonicity covers the argument-free calls: `next()` always emits a
 * UUID that sorts after the previous one. It is not a property of the
 * embedded-timestamp field, which the caller controls — two `next(sameTs)`
 * calls are ordered by the counter only while both fall in one wall-clock
 * millisecond of this process, and sort in either order once the counter has
 * reseeded across a millisecond boundary. All of this is per-process; do not
 * assume it across processes.
 */
/* @__NO_SIDE_EFFECTS__ */
export function createUUIDv7Generator(): UUIDv7Generator {
  let lastWallTs = 0;
  let counter = 0;
  return {
    next(timestamp?: Date | number): string {
      // Validate the caller's timestamp first so a thrown error leaves the
      // generator's state untouched (a failed call must not consume a
      // counter slot).
      const userMs = timestamp === undefined ? undefined : _coerceMs(timestamp);

      // Always advance the internal counter from Date.now(), regardless of
      // any user-supplied timestamp. This is the "immutable reference":
      // counter ordering tracks the process's own call order and is never
      // perturbed by external input.
      const now = Date.now();
      let wallTs: number;
      if (now > lastWallTs) {
        wallTs = now;
        counter = _seedCounter();
      } else {
        // Same wall ms, or wall clock regressed — hold the reference and
        // keep incrementing the counter.
        wallTs = lastWallTs;
        counter++;
        if (counter > 0xfff) {
          // Overflow: advance the reference by 1 ms and reseed the counter.
          wallTs = lastWallTs + 1;
          counter = _seedCounter();
        }
      }
      lastWallTs = wallTs;

      // Embedded timestamp: caller's value if supplied, otherwise the
      // wall-clock-driven reference.
      return _formatV7Counter(userMs ?? wallTs, counter);
    },
  };
}

/**
 * Extract the Unix-millisecond timestamp embedded in a UUIDv7's first 48 bits.
 *
 * @throws {UnsecureError} `MALFORMED` if `uuid` is a string that is not a
 *                         canonical-format UUIDv7; `INVALID_TYPE` if it is not a
 *                         string at all.
 */
/* @__NO_SIDE_EFFECTS__ */
export function uuidv7Timestamp(uuid: string): number {
  if (!isUUIDv7(uuid)) {
    // A string that does not carry the shape is text claiming to be something
    // it is not; a value that is not text never made the claim.
    throw new UnsecureError(
      typeof uuid === "string" ? "MALFORMED" : "INVALID_TYPE",
      `uuidv7Timestamp: Not a valid UUIDv7: ${String(uuid)}`,
    );
  }
  // First 12 hex chars (positions 0-7 and 9-12 around the first hyphen) are
  // the 48-bit big-endian Unix-ms. 48 bits fits safely in a JS number.
  return Number.parseInt(uuid.slice(0, 8) + uuid.slice(9, 13), 16);
}

/**
 * Type guard for canonical-format UUIDv4 strings. Checks hex alphabet,
 * hyphen positions, the version nibble (`4`), and the variant bits (`10xx`).
 * Case-insensitive.
 */
/* @__NO_SIDE_EFFECTS__ */
export function isUUIDv4(value: unknown): value is string {
  return _isCanonicalUUIDWithVersion(value, "4");
}

/**
 * Type guard for canonical-format UUIDv7 strings. Checks hex alphabet,
 * hyphen positions, the version nibble (`7`), and the variant bits (`10xx`).
 * Case-insensitive.
 */
/* @__NO_SIDE_EFFECTS__ */
export function isUUIDv7(value: unknown): value is string {
  return _isCanonicalUUIDWithVersion(value, "7");
}

// #region Internal

const _UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

const _MAX_V7_MS = 0xffffffffffff;

/* @__NO_SIDE_EFFECTS__ */
function _isCanonicalUUIDWithVersion(value: unknown, version: string): value is string {
  if (typeof value !== "string" || !_UUID_REGEX.test(value)) return false;
  // Version nibble is at index 14 (first char of the third group).
  if (value[14] !== version) return false;
  // Variant nibble is at index 19 (first char of the fourth group). The
  // RFC 9562 variant has top two bits `10`, so the nibble is 8, 9, a, or b
  // (case-insensitive).
  const v = value[19]!.toLowerCase();
  return v === "8" || v === "9" || v === "a" || v === "b";
}

/* @__NO_SIDE_EFFECTS__ */
function _coerceMs(value: Date | number): number {
  let ms: number;
  if (value instanceof Date) {
    ms = value.getTime();
  } else if (typeof value === "number") {
    ms = Math.floor(value);
  } else {
    throw new UnsecureError("INVALID_TYPE", "UUIDv7 timestamp must be a Date or number.");
  }
  if (!Number.isFinite(ms) || ms < 0 || ms > _MAX_V7_MS) {
    throw new UnsecureError(
      "OUT_OF_RANGE",
      `UUIDv7 timestamp must be a finite ms value in [0, 2^48 - 1], got ${String(value)}.`,
    );
  }
  return ms;
}

/* @__NO_SIDE_EFFECTS__ */
function _seedCounter(): number {
  const buf = new Uint8Array(2);
  crypto.getRandomValues(buf);
  // Seed in the lower half of the 12-bit range so we always have ≥2048
  // monotonic increments before the counter would overflow into a new ms.
  return ((buf[0]! << 8) | buf[1]!) & 0x7ff;
}

function _writeTimestampBE(bytes: Uint8Array, tsMs: number): void {
  // 48-bit big-endian: 16-bit high word, 32-bit low word.
  const hi = Math.floor(tsMs / 0x100000000);
  const lo = tsMs >>> 0;
  bytes[0] = (hi >>> 8) & 0xff;
  bytes[1] = hi & 0xff;
  bytes[2] = (lo >>> 24) & 0xff;
  bytes[3] = (lo >>> 16) & 0xff;
  bytes[4] = (lo >>> 8) & 0xff;
  bytes[5] = lo & 0xff;
}

/* @__NO_SIDE_EFFECTS__ */
function _formatV7Random(tsMs: number): string {
  const bytes = new Uint8Array(16);
  _writeTimestampBE(bytes, tsMs);
  // Fill the 10 remaining bytes with random material, then overwrite the
  // version nibble (byte 6) and the variant bits (byte 8).
  crypto.getRandomValues(bytes.subarray(6));
  bytes[6] = (bytes[6]! & 0x0f) | 0x70;
  bytes[8] = (bytes[8]! & 0x3f) | 0x80;
  return _formatUUID(bytes);
}

/* @__NO_SIDE_EFFECTS__ */
function _formatV7Counter(tsMs: number, counter: number): string {
  const bytes = new Uint8Array(16);
  _writeTimestampBE(bytes, tsMs);
  // Version 7 in the high nibble of byte 6; counter fills rand_a (12 bits
  // spanning the low nibble of byte 6 and all of byte 7).
  bytes[6] = 0x70 | ((counter >>> 8) & 0x0f);
  bytes[7] = counter & 0xff;
  // Fill rand_b (bytes 8-15) with random material, then overwrite the
  // top two bits of byte 8 with the RFC 9562 variant (0b10).
  crypto.getRandomValues(bytes.subarray(8));
  bytes[8] = (bytes[8]! & 0x3f) | 0x80;
  return _formatUUID(bytes);
}

/* @__NO_SIDE_EFFECTS__ */
function _formatUUID(bytes: Uint8Array<ArrayBuffer>): string {
  const hex = hexStringify(bytes);
  return (
    hex.slice(0, 8) +
    "-" +
    hex.slice(8, 12) +
    "-" +
    hex.slice(12, 16) +
    "-" +
    hex.slice(16, 20) +
    "-" +
    hex.slice(20, 32)
  );
}
