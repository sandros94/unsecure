import { createSecureRandomGenerator, secureShuffle } from "./random.ts";
import { assertInteger, showValue } from "./_internal/assert.ts";

export interface SecureGenerateOptions {
  /**
   * The desired length of the password, in code points. An integer >= 1.
   *
   * @default 16
   */
  length?: number;
  /**
   * Include uppercase letters, or a custom set of characters to draw from.
   *
   * @default true
   */
  uppercase?: boolean | string;
  /**
   * Include lowercase letters, or a custom set of characters to draw from.
   *
   * @default true
   */
  lowercase?: boolean | string;
  /**
   * Include numbers, or a custom set of characters to draw from.
   *
   * @default true
   */
  numbers?: boolean | string;
  /**
   * Include special characters, or a custom set of characters to draw from.
   *
   * @default true
   */
  specials?: boolean | string;
  /**
   * Include a timestamp at the beginning of the string. `true` stamps the
   * current time; a `Date` stamps that instant. It must be a valid date.
   *
   * @default false
   */
  timestamp?: true | Date;
}

/**
 * Default character sets. The SPECIALS set is curated to avoid characters that
 * can break strings or commands in shells and .env files. The four are
 * disjoint, which is what {@link secureGenerate} requires of any set.
 */
const DEFAULT_UPPERCASE = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const DEFAULT_LOWERCASE = "abcdefghijklmnopqrstuvwxyz";
const DEFAULT_NUMBERS = "0123456789";
const DEFAULT_SPECIALS = "!@#$%^&*()_+{}:<>?|[];,./~-=";

const DEFAULT_LENGTH = 16;

/**
 * Generates a cryptographically secure string based on the provided options.
 *
 * Every enabled category contributes at least one character when `length` —
 * less any timestamp prefix — is at least the number of enabled categories;
 * below that the shuffled result is cut to `length`, so which categories
 * survive is a draw. The rest is drawn from their union, and the result is
 * shuffled. Sets are read by code point, so
 * `length` counts characters as a reader would — an emoji is one — and the
 * output never contains half of a surrogate pair.
 *
 * @param options The configuration for string generation.
 * @returns The generated string.
 *
 * @throws {RangeError} If `length` is not an integer >= 1, if `timestamp` is an
 *                      invalid `Date`, or if a character appears in more than one
 *                      place across the selected sets.
 * @throws {TypeError} If `timestamp` is neither `true` nor a `Date`.
 * @throws {Error} If no character types are selected, or `length` leaves no room
 *                 after the timestamp prefix.
 */
export function secureGenerate(options?: SecureGenerateOptions): string {
  const {
    length = DEFAULT_LENGTH,
    uppercase = true,
    lowercase = true,
    numbers = true,
    specials = true,
    timestamp,
  } = options ?? {};

  assertInteger("secureGenerate", "length", length, 1);

  const timestampStr = _timestampPrefix(timestamp);
  if (timestampStr && length <= timestampStr.length) {
    throw new Error(
      `secureGenerate: length must be greater than the timestamp prefix (${timestampStr.length} characters), got ${length}.`,
    );
  }

  // Each selected set, by code point, in the order their guaranteed characters
  // are drawn.
  const sets: Array<Array<string>> = [];
  if (_shouldIncludeSet(uppercase)) sets.push(_codePoints(uppercase, DEFAULT_UPPERCASE));
  if (_shouldIncludeSet(lowercase)) sets.push(_codePoints(lowercase, DEFAULT_LOWERCASE));
  if (_shouldIncludeSet(numbers)) sets.push(_codePoints(numbers, DEFAULT_NUMBERS));
  if (_shouldIncludeSet(specials)) sets.push(_codePoints(specials, DEFAULT_SPECIALS));

  if (sets.length === 0) {
    throw new Error(
      "secureGenerate: no character types selected. Enable uppercase, lowercase, numbers or specials.",
    );
  }

  const charset = sets.flat();
  _assertDistinct(charset);

  const random = createSecureRandomGenerator();
  const guaranteedChars = sets.map((set) => set[random.next(set.length)]!);

  const lengthToGenerate = length - timestampStr.length;
  const remainingLength = lengthToGenerate - guaranteedChars.length;
  const randomChars: Array<string> = [];

  // Fill the rest of the string length with random characters from the full set
  for (let i = 0; i < remainingLength; i++) {
    randomChars.push(charset[random.next(charset.length)]!);
  }

  // Combine guaranteed characters with random ones and shuffle securely
  const finalPasswordArray = secureShuffle([...guaranteedChars, ...randomChars], random);

  // Ensure the string is the exact length requested
  return timestampStr + finalPasswordArray.slice(0, lengthToGenerate).join("");
}

/**
 * INTERNAL FUNCTIONS
 */

function _shouldIncludeSet<T extends boolean | string>(set: T): set is Exclude<T, false> {
  return set !== false && (set === true || (typeof set === "string" && set.length > 0));
}

/** Split a set into whole code points, so an astral character stays one draw. */
function _codePoints(set: string | true, defaultSet: string): Array<string> {
  return Array.from(typeof set === "string" ? set : defaultSet);
}

/**
 * A character repeated within one set, or shared by two of them, would be drawn
 * twice as often as its neighbours — a silent bias in the distribution the
 * generator exists to provide.
 */
function _assertDistinct(charset: Array<string>): void {
  const seen = new Set<string>();
  for (const char of charset) {
    if (seen.has(char)) {
      throw new RangeError(
        `secureGenerate: character sets must not repeat a character; ${showValue(char)} appears more than once.`,
      );
    }
    seen.add(char);
  }
}

/** The base36 timestamp prefix, or an empty string when none was asked for. */
function _timestampPrefix(timestamp: true | Date | undefined): string {
  if (!timestamp) return "";
  const date = timestamp === true ? new Date() : timestamp;
  if (!(date instanceof Date)) {
    throw new TypeError(`secureGenerate: timestamp must be a Date, got ${showValue(date)}.`);
  }
  const time = date.getTime();
  if (Number.isNaN(time)) {
    throw new RangeError(`secureGenerate: timestamp must be a valid Date, got ${date.toString()}.`);
  }
  return time.toString(36);
}
