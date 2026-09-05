import { assertInteger, showValue } from "./_internal/assert.ts";

/**
 * Defines the interface for a secure random number generator.
 */
export interface SecureRandomGenerator {
  /**
   * Gets a single cryptographically secure random integer in the range [0, max).
   * @param {number} max - The exclusive upper bound for the random number.
   * @param {Iterable<number> | Set<number>} [ignore] - Optional iterable or set of values to ignore.
   *
   * @returns {number} A cryptographically secure random integer.
   *
   * @throws {RangeError} If `max` is not a positive integer or is greater than 2^32.
   * @throws {TypeError} If `ignore` is not an iterable of numbers or a Set<number>.
   * @throws {RangeError} If `ignore` excludes all possible values in the range.
   */
  next(max: number, ignore?: Iterable<number> | Set<number>): number;

  /**
   * Gets a single cryptographically secure random integer in the range [min, max).
   * @param {number} min - The inclusive lower bound for the random number.
   * @param {number} max - The exclusive upper bound for the random number.
   * @param {Iterable<number> | Set<number>} [ignore] - Optional iterable or set of values to ignore.
   *
   * @returns {number} A cryptographically secure random integer.
   *
   * @throws {RangeError} If `min` or `max` are not integers, if `max` <= `min`, or if the range is greater than 2^32.
   * @throws {TypeError} If `ignore` is not an iterable of numbers or a Set<number>.
   * @throws {RangeError} If `ignore` excludes all possible values in the range.
   */
  next(min: number, max: number, ignore?: Iterable<number> | Set<number>): number;
}

/**
 * Creates a cryptographically secure random number generator that uses a buffer
 * to reduce the number of calls to the Web Crypto API. This is a performant
 * way to generate multiple random numbers.
 * Supports next(max), next(min, max) and both variants with an optional
 * ignore iterable or Set of values to exclude from results.
 * @returns {SecureRandomGenerator} An object with a `next` method for generating numbers.
 */
/** What a caller holds when `next` throws, whichever entry point led there. */
const _SOURCE = "SecureRandomGenerator.next";

export function createSecureRandomGenerator(): SecureRandomGenerator {
  const BUFFER_SIZE = 256;
  const buffer = new Uint32Array(BUFFER_SIZE);
  let index = BUFFER_SIZE; // Initialize to force a refill on the first call.

  /** Fills the buffer with new random values. */
  function _refillBuffer(): void {
    crypto.getRandomValues(buffer);
    index = 0;
  }

  function next(max: number, ignore?: Iterable<number> | Set<number>): number;
  function next(min: number, max: number, ignore?: Iterable<number> | Set<number>): number;
  function next(
    a: number,
    b?: Iterable<number> | Set<number> | number,
    c?: Iterable<number> | Set<number>,
  ): number {
    let min: number;
    let max: number;
    let rawIgnore: Iterable<number> | Set<number> | undefined;

    // Determine which overload was used.
    if (typeof b === "number") {
      min = a;
      max = b;
      rawIgnore = c;
    } else {
      min = 0;
      max = a;
      rawIgnore = b;
    }

    // Every message names the interface a caller holds: `next` is reached
    // through `secureRandomNumber`, `secureShuffle` and `randomJitter` as well
    // as directly, so naming any one of those would be wrong three times out
    // of four.
    if (!Number.isInteger(min) || !Number.isInteger(max)) {
      throw new RangeError(`${_SOURCE}: min and max must be integers.`);
    }
    if (max <= min) {
      throw new RangeError(`${_SOURCE}: max must be greater than min.`);
    }

    const range = max - min;
    if (range > 2 ** 32) {
      throw new RangeError(`${_SOURCE}: range must be less than or equal to 2^32.`);
    }

    // Normalize ignore to a Set for O(1) lookups if provided.
    let ignoreSet: Set<number> | undefined;
    if (rawIgnore != null) {
      if (rawIgnore instanceof Set) {
        ignoreSet = rawIgnore;
      } else if (
        typeof rawIgnore !== "string" &&
        (Array.isArray(rawIgnore) || typeof (rawIgnore as any)[Symbol.iterator] === "function")
      ) {
        ignoreSet = new Set(rawIgnore as Iterable<number>);
      } else {
        throw new TypeError(`${_SOURCE}: ignore must be an iterable of numbers or a Set<number>.`);
      }

      // Quick sanity: if ignoreSet excludes all possible values in range, it's impossible to generate a value.
      let excludedInRange = 0;
      for (const v of ignoreSet) {
        if (!Number.isInteger(v)) continue;
        if (v >= min && v < max) {
          excludedInRange++;
          if (excludedInRange >= range) {
            throw new RangeError(
              `${_SOURCE}: ignore set excludes all possible values in the range.`,
            );
          }
        }
      }
    }

    const maxSafe = 2 ** 32 - (2 ** 32 % range);
    let randomValue: number;
    let candidate: number;
    do {
      if (index >= BUFFER_SIZE) {
        _refillBuffer();
      }
      randomValue = buffer[index++]!;
      candidate = min + (randomValue % range);
      // Loop while value is biased (>= maxSafe) or candidate is in ignore set.
    } while (randomValue >= maxSafe || (ignoreSet !== undefined && ignoreSet.has(candidate)));

    return candidate;
  }

  return { next };
}

/**
 * The generator behind {@link secureRandomNumber} and {@link randomJitter}.
 * Shared so one buffered refill serves the whole process. The purity
 * annotation lets a bundler drop it from builds that import neither.
 */
const _sharedGenerator: SecureRandomGenerator = /* @__PURE__ */ createSecureRandomGenerator();

/**
 * Gets a single cryptographically secure random integer in the range [0, max).
 * Draws from a shared buffered generator, so it avoids modulo bias through
 * rejection sampling and amortizes the `crypto.getRandomValues` call across
 * calls.
 * @param {number} max - The exclusive upper bound for the random number.
 * @param {Iterable<number> | Set<number>} [ignore] - Optional iterable or set of values to ignore.
 *
 * @returns {number} A cryptographically secure random integer between 0 (inclusive) and max (exclusive).
 *
 * @throws {RangeError} If `max` is not a positive integer or is greater than 2^32.
 * @throws {TypeError} If `ignore` is not an iterable of numbers or a Set<number>.
 * @throws {RangeError} If `ignore` excludes all possible values in the range.
 *
 * @description Use `createSecureRandomGenerator()` when a caller needs a
 * generator of its own rather than the shared one.
 */
export function secureRandomNumber(max: number, ignore?: Iterable<number> | Set<number>): number;
/**
 * Gets a single cryptographically secure random integer in the range [min, max).
 * Draws from a shared buffered generator, so it avoids modulo bias through
 * rejection sampling and amortizes the `crypto.getRandomValues` call across
 * calls.
 * @param {number} min - The inclusive lower bound for the random number.
 * @param {number} max - The exclusive upper bound for the random number.
 * @param {Iterable<number> | Set<number>} [ignore] - Optional iterable or set of values to ignore.
 *
 * @returns {number} A cryptographically secure random integer between min (inclusive) and max (exclusive).
 *
 * @throws {RangeError} If `min` or `max` are not integers, if `max` <= `min`, or if the range is greater than 2^32.
 * @throws {TypeError} If `ignore` is not an iterable of numbers or a Set<number>.
 * @throws {RangeError} If `ignore` excludes all possible values in the range.
 *
 * @description Use `createSecureRandomGenerator()` when a caller needs a
 * generator of its own rather than the shared one.
 */
export function secureRandomNumber(
  min: number,
  max: number,
  ignore?: Iterable<number> | Set<number>,
): number;
export function secureRandomNumber(
  a: number,
  b?: Iterable<number> | Set<number> | number,
  c?: Iterable<number> | Set<number>,
): number {
  return typeof b === "number" ? _sharedGenerator.next(a, b, c) : _sharedGenerator.next(a, b);
}

/**
 * The largest draw {@link secureRandomBytes} accepts: 2 GiB - 1. Nothing
 * legitimate asks for key material anywhere near this, and above it the call
 * degenerates into a multi-hour fill of an allocation the caller did not
 * expect to make.
 */
const MAX_RANDOM_BYTES = 2 ** 31 - 1;

/**
 * Generate a Uint8Array of cryptographically secure random bytes.
 *
 * @param length Number of random bytes to generate, from 0 to `2**31 - 1`.
 * @returns A Uint8Array filled with random bytes.
 *
 * @throws {RangeError} If `length` is not an integer in `[0, 2**31 - 1]`.
 *
 * @example
 * const key = secureRandomBytes(32); // 256-bit key material
 */
export function secureRandomBytes(length: number): Uint8Array<ArrayBuffer> {
  assertInteger("secureRandomBytes", "length", length, 0, MAX_RANDOM_BYTES);
  const bytes = new Uint8Array(length);
  if (length > 0) {
    // crypto.getRandomValues has a 65536-byte limit per call
    for (let offset = 0; offset < length; offset += 65536) {
      const chunk = bytes.subarray(offset, Math.min(offset + 65536, length));
      crypto.getRandomValues(chunk);
    }
  }
  return bytes;
}

/**
 * Shuffles an array in-place using the Fisher-Yates algorithm with a
 * cryptographically secure random number generator.
 * @template T
 * @param {Array<T>} array The array to shuffle.
 * @param {SecureRandomGenerator} [generator] - An optional random number generator to reuse.
 *
 * @description If you require to shuffle multiple times it is adviced to pass the `generator` parameter to avoid creating a new generator for each shuffle. (refer to `createSecureRandomGenerator()` factory)
 *
 * @returns {Array<T>} The shuffled array.
 */
export function secureShuffle<T>(array: Array<T>, generator?: SecureRandomGenerator): Array<T> {
  const gen = generator ?? createSecureRandomGenerator();
  // Loop from the last element down to the second.
  for (let i = array.length - 1; i > 0; i--) {
    // Pick a random index from the start of the array up to the current position.
    const j = gen.next(i + 1);
    // Swap the elements at the current and random positions.
    [array[i], array[j]] = [array[j]!, array[i]!];
  }
  return array;
}

/**
 * Add a random delay in milliseconds. Useful as defense-in-depth against
 * timing side-channels.
 *
 * - `randomJitter()` — delay in `[0, 100)`
 * - `randomJitter(maxMs)` — delay in `[0, maxMs)`
 * - `randomJitter(minMs, maxMs)` — delay in `[minMs, maxMs)`
 *
 * `maxMs === minMs` resolves after exactly that many milliseconds and draws
 * no randomness. Milliseconds must be integers: `setTimeout` truncates, so a
 * fractional bound never described the delay a caller would get. Only an
 * absent bound (`undefined`) takes a default; `null` is a value and throws.
 *
 * @throws {RangeError} If `minMs` or `maxMs` is not a non-negative integer, or
 *                      if `maxMs` is less than `minMs`.
 */
export function randomJitter(maxMs?: number): Promise<void>;
export function randomJitter(minMs: number | undefined, maxMs: number): Promise<void>;
export function randomJitter(minOrMax?: number, maxMs?: number): Promise<void> {
  // No default parameter: `randomJitter(undefined, 50)` must read as "no
  // lower bound, upper bound 50", not as the one-argument form. Only
  // `undefined` takes a default — `null` is a value the caller passed, and it
  // fails the range check below like any other non-integer.
  const oneArgument = maxMs === undefined;
  const min = oneArgument || minOrMax === undefined ? 0 : minOrMax;
  const max = oneArgument ? (minOrMax === undefined ? 100 : minOrMax) : maxMs;

  assertInteger("randomJitter", "minMs", min, 0);
  assertInteger("randomJitter", "maxMs", max, 0);
  if (max < min) {
    throw new RangeError(
      `randomJitter: maxMs must be an integer >= minMs (${min}), got ${showValue(max)}.`,
    );
  }

  const delay = max === min ? min : secureRandomNumber(min, max);
  return new Promise((resolve) => setTimeout(resolve, delay));
}
