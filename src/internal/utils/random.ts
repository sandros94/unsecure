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
  next(
    min: number,
    max: number,
    ignore?: Iterable<number> | Set<number>,
  ): number;
}

/**
 * Creates a cryptographically secure random number generator that uses a buffer
 * to reduce the number of calls to the Web Crypto API. This is a performant
 * way to generate multiple random numbers.
 * Supports next(max), next(min, max) and both variants with an optional
 * ignore iterable or Set of values to exclude from results.
 * @returns {SecureRandomGenerator} An object with a `next` method for generating numbers.
 */
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
  function next(
    min: number,
    max: number,
    ignore?: Iterable<number> | Set<number>,
  ): number;
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

    if (!Number.isInteger(min) || !Number.isInteger(max)) {
      throw new RangeError("min and max must be integers.");
    }
    if (max <= min) {
      throw new RangeError("max must be greater than min.");
    }

    const range = max - min;
    if (range > 2 ** 32) {
      throw new RangeError("range must be less than or equal to 2^32.");
    }

    // Normalize ignore to a Set for O(1) lookups if provided.
    let ignoreSet: Set<number> | undefined;
    if (rawIgnore != null) {
      if (rawIgnore instanceof Set) {
        ignoreSet = rawIgnore;
      } else if (
        typeof rawIgnore !== "string" &&
        (Array.isArray(rawIgnore) ||
          typeof (rawIgnore as any)[Symbol.iterator] === "function")
      ) {
        ignoreSet = new Set(rawIgnore as Iterable<number>);
      } else {
        throw new TypeError(
          "ignore must be an iterable of numbers or a Set<number>.",
        );
      }

      // Quick sanity: if ignoreSet excludes all possible values in range, it's impossible to generate a value.
      let excludedInRange = 0;
      for (const v of ignoreSet) {
        if (!Number.isInteger(v)) continue;
        if (v >= min && v < max) {
          excludedInRange++;
          if (excludedInRange >= range) {
            throw new RangeError(
              "Ignore set excludes all possible values in the range.",
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
    } while (
      randomValue >= maxSafe ||
      (ignoreSet !== undefined && ignoreSet.has(candidate))
    );

    return candidate;
  }

  return { next };
}

/**
 * Gets a single cryptographically secure random integer in the range [0, max).
 * This function avoids modulo bias by rejecting values that would cause an
 * uneven distribution.
 * @param {number} max - The exclusive upper bound for the random number.
 * @param {Iterable<number> | Set<number>} [ignore] - Optional iterable or set of values to ignore.
 *
 * @returns {number} A cryptographically secure random integer between 0 (inclusive) and max (exclusive).
 *
 * @throws {RangeError} If `max` is not a positive integer or is greater than 2^32.
 * @throws {TypeError} If `ignore` is not an iterable of numbers or a Set<number>.
 * @throws {RangeError} If `ignore` excludes all possible values in the range.
 *
 * @description For generating multiple random numbers, it is more performant to
 * use `createSecureRandomGenerator()`.
 */
export function secureRandomNumber(
  max: number,
  ignore?: Iterable<number> | Set<number>,
): number;
/**
 * Gets a single cryptographically secure random integer in the range [min, max).
 * This function avoids modulo bias by rejecting values that would cause an
 * uneven distribution.
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
 * @description For generating multiple random numbers, it is more performant to
 * use `createSecureRandomGenerator()`.
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

  // Validate input: min and max must be integers
  if (!Number.isInteger(min) || !Number.isInteger(max)) {
    throw new RangeError("min and max must be integers.");
  }
  if (max <= min) {
    throw new RangeError("max must be greater than min.");
  }

  const range = max - min;
  if (range > 2 ** 32) {
    // A single Uint32Array cannot reliably generate numbers in this range without bias
    throw new RangeError("range must be less than or equal to 2^32.");
  }

  // Normalize ignore to a Set for O(1) lookups if provided.
  let ignoreSet: Set<number> | undefined;
  if (rawIgnore != null) {
    if (rawIgnore instanceof Set) {
      ignoreSet = rawIgnore;
    } else if (
      typeof rawIgnore !== "string" &&
      (Array.isArray(rawIgnore) ||
        typeof (rawIgnore as any)[Symbol.iterator] === "function")
    ) {
      ignoreSet = new Set(rawIgnore as Iterable<number>);
    } else {
      throw new TypeError(
        "ignore must be an iterable of numbers or a Set<number>.",
      );
    }

    // Quick sanity: if ignoreSet excludes all possible values in range, it's impossible to generate a value.
    let excludedInRange = 0;
    for (const v of ignoreSet) {
      if (!Number.isInteger(v)) continue;
      if (v >= min && v < max) {
        excludedInRange++;
        if (excludedInRange >= range) {
          throw new RangeError(
            "Ignore set excludes all possible values in the range.",
          );
        }
      }
    }
  }

  // Uses a 32-bit unsigned integer array for random values.
  const randomBytes = new Uint32Array(1);
  // Values above this threshold will be rejected to prevent bias.
  const maxSafe = 2 ** 32 - (2 ** 32 % range);
  let randomValue: number;
  let candidate: number;

  do {
    // Get a random value from the Web Crypto API.
    crypto.getRandomValues(randomBytes);
    randomValue = randomBytes[0]!;
    candidate = min + (randomValue % range);
    // Loop while value is biased (>= maxSafe) or candidate is in ignore set.
  } while (
    randomValue >= maxSafe ||
    (ignoreSet !== undefined && ignoreSet.has(candidate))
  );

  return candidate;
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
export function secureShuffle<T>(
  array: Array<T>,
  generator?: SecureRandomGenerator,
): Array<T> {
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
