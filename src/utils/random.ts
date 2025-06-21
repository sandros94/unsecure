/**
 * Gets a single cryptographically secure random integer within a specified range.
 * This function avoids modulo bias by rejecting values that would cause an
 * uneven distribution.
 * @param {number} max - The exclusive upper bound for the random number.
 * @returns {number} A cryptographically secure random integer between 0 (inclusive) and max (exclusive).
 * @throws {RangeError} If `max` is not a positive integer or is greater than 2^32.
 */
export function secureRandomNumber(max: number): number {
  // Validate input: max must be a positive integer <= 2^32
  if (!Number.isInteger(max) || max <= 0) {
    throw new RangeError("max must be a positive integer.");
  }
  if (max > 2 ** 32) {
    // A single Uint32Array cannot reliably generate numbers in this range without bias
    throw new RangeError("max must be less than or equal to 2^32.");
  }

  // Uses a 32-bit unsigned integer array for random values.
  const randomBytes = new Uint32Array(1);
  // Values above this threshold will be rejected to prevent bias.
  const maxSafe = 2 ** 32 - (2 ** 32 % max);
  let randomValue: number;

  do {
    // Get a random value from the Web Crypto API.
    crypto.getRandomValues(randomBytes);
    randomValue = randomBytes[0]!;
  } while (randomValue >= maxSafe); // Reject biased values and retry.

  return randomValue % max;
}

/**
 * Shuffles an array in-place using the Fisher-Yates algorithm with a
 * cryptographically secure random number generator.
 * @template T
 * @param {Array<T>} array The array to shuffle.
 * @returns {Array<T>} The shuffled array.
 */
export function secureShuffle<T>(array: Array<T>): Array<T> {
  // Loop from the last element down to the second.
  for (let i = array.length - 1; i > 0; i--) {
    // Pick a random index from the start of the array up to the current position.
    const j = secureRandomNumber(i + 1);
    // Swap the elements at the current and random positions.
    [array[i], array[j]] = [array[j]!, array[i]!];
  }
  return array;
}
