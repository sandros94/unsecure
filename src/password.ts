import {
  createSecureRandomGenerator,
  type SecureRandomGenerator,
  secureShuffle,
} from "./utils";
import type { GeneratePasswordOptions } from "./types";

/**
 * Default character sets. The SPECIALS set is curated to avoid characters that
 * can break strings or commands in shells and .env files.
 */
const DEFAULT_UPPERCASE = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const DEFAULT_LOWERCASE = "abcdefghijklmnopqrstuvwxyz";
const DEFAULT_NUMBERS = "0123456789";
const DEFAULT_SPECIALS = "!@#$%^&*()_+{}:<>?|[];,./~-=";

const DEFAULT_LENGTH = 16;

/**
 * Generates a cryptographically secure password based on the provided options.
 * @param {number} length - The desired length of the password.
 * @returns {string} The generated password.
 * @throws {Error} if no character types are selected.
 */
export function generateSecurePassword(length?: number): string;
/**
 * Generates a cryptographically secure password based on the provided options.
 * @param {GeneratePasswordOptions} options - The configuration for password generation.
 * @returns {string} The generated password.
 * @throws {Error} if no character types are selected.
 */
export function generateSecurePassword(
  options?: GeneratePasswordOptions,
): string;
/**
 * Generates a cryptographically secure password based on the provided options.
 * @param {number | GeneratePasswordOptions} numOrOptions - The desired length or the configuration for password generation.
 * @returns {string} The generated password.
 * @throws {Error} if no character types are selected.
 */
export function generateSecurePassword(
  numOrOptions: number | GeneratePasswordOptions = DEFAULT_LENGTH,
): string {
  let length: number;
  let uppercase: boolean | string = true;
  let lowercase: boolean | string = true;
  let numbers: boolean | string = true;
  let specials: boolean | string = true;

  if (typeof numOrOptions === "number") {
    length = numOrOptions;
  } else {
    length = numOrOptions.length ?? DEFAULT_LENGTH;
    uppercase = numOrOptions.uppercase ?? true;
    lowercase = numOrOptions.lowercase ?? true;
    numbers = numOrOptions.numbers ?? true;
    specials = numOrOptions.specials ?? true;
  }

  if (length < 1) {
    throw new TypeError("Password length must be at least 1.");
  }

  const random = createSecureRandomGenerator();

  let charset = "";
  const guaranteedChars: Array<string> = [];

  // Build the full character set and the list of guaranteed characters
  if (_shouldIncludeSet(uppercase)) {
    const { used, guaranteed } = _characterSetBuilder(
      uppercase,
      DEFAULT_UPPERCASE,
      random,
    );
    charset += used;
    guaranteedChars.push(guaranteed);
  }
  if (_shouldIncludeSet(lowercase)) {
    const { used, guaranteed } = _characterSetBuilder(
      lowercase,
      DEFAULT_LOWERCASE,
      random,
    );
    charset += used;
    guaranteedChars.push(guaranteed);
  }
  if (_shouldIncludeSet(numbers)) {
    const { used, guaranteed } = _characterSetBuilder(
      numbers,
      DEFAULT_NUMBERS,
      random,
    );
    charset += used;
    guaranteedChars.push(guaranteed);
  }
  if (_shouldIncludeSet(specials)) {
    const { used, guaranteed } = _characterSetBuilder(
      specials,
      DEFAULT_SPECIALS,
      random,
    );
    charset += used;
    guaranteedChars.push(guaranteed);
  }

  if (!charset) {
    throw new Error("Cannot generate password. No character types selected.");
  }

  const remainingLength = length - guaranteedChars.length;
  const randomChars = [];

  // Fill the rest of the password length with random characters from the full set
  if (remainingLength > 0) {
    for (let i = 0; i < remainingLength; i++) {
      randomChars.push(charset[random.next(charset.length)]);
    }
  }

  // Combine guaranteed characters with random ones and shuffle securely
  const finalPasswordArray = secureShuffle(
    [...guaranteedChars, ...randomChars],
    random,
  );

  // Ensure the password is the exact length requested
  return finalPasswordArray.slice(0, length).join("");
}

/**
 * Generates a cryptographically secure token based on the provided options.
 * @param {number | GeneratePasswordOptions} numOrOptions - The desired length or the configuration for token generation.
 * @returns {string} The generated token.
 * @throws {Error} if no character types are selected.
 */
export const generateSecureToken = generateSecurePassword;

/**
 * INTERNAL FUNCTIONS
 */

function _shouldIncludeSet<T extends boolean | string>(
  set: T,
): set is Exclude<T, false> {
  return (
    set !== false &&
    (set === true || (typeof set === "string" && set.length > 0))
  );
}

function _characterSetBuilder(
  set: string | true | undefined,
  defaultSet: string,
  random: SecureRandomGenerator,
) {
  const used = typeof set === "string" ? set : defaultSet;

  return {
    used,
    guaranteed: used[random.next(used.length)]!,
  };
}
