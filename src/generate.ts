import {
  createSecureRandomGenerator,
  type SecureRandomGenerator,
  secureShuffle,
} from "./utils";
import type { SecureGenerateOptions } from "./types";

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
 * Generates a cryptographically secure string based on the provided options.
 * @param {number} length - The desired length of the string.
 * @returns {string} The generated string.
 * @throws {Error} if no character types are selected.
 */
export function secureGenerate(length?: number): string;
/**
 * Generates a cryptographically secure string based on the provided options.
 * @param {SecureGenerateOptions} options - The configuration for string generation.
 * @returns {string} The generated string.
 * @throws {Error} if no character types are selected.
 */
export function secureGenerate(options?: SecureGenerateOptions): string;
/**
 * Generates a cryptographically secure string based on the provided options.
 * @param {number | SecureGenerateOptions} numOrOptions - The desired length or the configuration for string generation.
 * @returns {string} The generated string.
 * @throws {Error} if no character types are selected.
 */
export function secureGenerate(
  numOrOptions: number | SecureGenerateOptions = DEFAULT_LENGTH,
): string {
  let length: number;
  let uppercase: boolean | string = true;
  let lowercase: boolean | string = true;
  let numbers: boolean | string = true;
  let specials: boolean | string = true;
  let timestamp: true | Date | undefined;

  if (typeof numOrOptions === "number") {
    length = numOrOptions;
  } else {
    length = numOrOptions.length ?? DEFAULT_LENGTH;
    uppercase = numOrOptions.uppercase ?? true;
    lowercase = numOrOptions.lowercase ?? true;
    numbers = numOrOptions.numbers ?? true;
    specials = numOrOptions.specials ?? true;
    timestamp = numOrOptions.timestamp;
  }

  let timestampStr = "";
  if (timestamp) {
    const date = timestamp === true ? new Date() : timestamp;
    timestampStr = date.getTime().toString(36);
  }

  if (length < 1) {
    throw new TypeError("Password length must be at least 1.");
  }

  if (timestampStr && length <= timestampStr.length) {
    throw new Error(
      `Password length must be greater than timestamp length (${timestampStr.length}).`,
    );
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
    throw new Error("Cannot generate string. No character types selected.");
  }

  const lengthToGenerate = length - timestampStr.length;
  const remainingLength = lengthToGenerate - guaranteedChars.length;
  const randomChars = [];

  // Fill the rest of the string length with random characters from the full set
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

  // Ensure the string is the exact length requested
  return timestampStr + finalPasswordArray.slice(0, lengthToGenerate).join("");
}

/**
 * @deprecated Use `secureGenerate` instead.
 */
export const generateSecureToken = secureGenerate;
/**
 * @deprecated Use `secureGenerate` instead.
 */
export const generateSecurePassword = secureGenerate;

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
