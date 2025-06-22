/**
 * Defines the interface for a secure random number generator.
 */
export interface SecureRandomGenerator {
  /**
   * Gets a single cryptographically secure random integer within a specified range.
   * @param {number} max - The exclusive upper bound for the random number.
   * @returns {number} A cryptographically secure random integer.
   */
  next(max: number): number;
}

/**
 * Creates a cryptographically secure random number generator that uses a buffer
 * to reduce the number of calls to the Web Crypto API. This is a performant
 * way to generate multiple random numbers.
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

  return {
    next: (max: number): number => {
      if (!Number.isInteger(max) || max <= 0) {
        throw new RangeError("max must be a positive integer.");
      }
      if (max > 2 ** 32) {
        throw new RangeError("max must be less than or equal to 2^32.");
      }
      const maxSafe = 2 ** 32 - (2 ** 32 % max);
      let randomValue: number;
      do {
        if (index >= BUFFER_SIZE) {
          _refillBuffer();
        }
        randomValue = buffer[index++]!;
      } while (randomValue >= maxSafe); // Reject biased values and retry.
      return randomValue % max;
    },
  };
}

/**
 * Gets a single cryptographically secure random integer within a specified range.
 * This function avoids modulo bias by rejecting values that would cause an
 * uneven distribution.
 * @param {number} max - The exclusive upper bound for the random number.
 * @returns {number} A cryptographically secure random integer between 0 (inclusive) and max (exclusive).
 *
 * @throws {RangeError} If `max` is not a positive integer or is greater than 2^32.
 *
 * @description For generating multiple random numbers, it is more performant to
 * use `createSecureRandomGenerator()`.
 */
export function secureRandomNumber(max: number): number {
  return createSecureRandomGenerator().next(max);
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
