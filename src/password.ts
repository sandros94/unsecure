import { secureRandomNumber, secureShuffle } from "./utils";
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
 * @param {GeneratePasswordOptions} options - The configuration for password generation.
 * @returns {string} The generated password.
 * @throws {Error} if no character types are selected.
 */
export const generateSecurePassword = (
  options: GeneratePasswordOptions = {},
): string => {
  const {
    length = DEFAULT_LENGTH,
    uppercase = true,
    lowercase = true,
    numbers = true,
    specials = true,
  } = options;

  if (length < 1) {
    throw new TypeError("Password length must be at least 1.");
  }

  let charset = "";
  const guaranteedChars: Array<string> = [];

  // Build the full character set and the list of guaranteed characters
  if (_shouldIncludeSet(uppercase)) {
    const { used, guaranteed } = _characterSetBuilder(
      uppercase,
      DEFAULT_UPPERCASE,
    );
    charset += used;
    guaranteedChars.push(guaranteed);
  }
  if (_shouldIncludeSet(lowercase)) {
    const { used, guaranteed } = _characterSetBuilder(
      lowercase,
      DEFAULT_LOWERCASE,
    );
    charset += used;
    guaranteedChars.push(guaranteed);
  }
  if (_shouldIncludeSet(numbers)) {
    const { used, guaranteed } = _characterSetBuilder(numbers, DEFAULT_NUMBERS);
    charset += used;
    guaranteedChars.push(guaranteed);
  }
  if (_shouldIncludeSet(specials)) {
    const { used, guaranteed } = _characterSetBuilder(
      specials,
      DEFAULT_SPECIALS,
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
      randomChars.push(charset[secureRandomNumber(charset.length)]);
    }
  }

  // Combine guaranteed characters with random ones and shuffle securely
  const finalPasswordArray = secureShuffle([
    ...guaranteedChars,
    ...randomChars,
  ]);

  // Ensure the password is the exact length requested
  return finalPasswordArray.slice(0, length).join("");
};

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
) {
  const used = typeof set === "string" ? set : defaultSet;

  return {
    used,
    guaranteed: used[secureRandomNumber(used.length)]!,
  };
}
