import { entropy } from "unsecure/entropy";

// #region docs
/**
 * Why a new password is too weak, or `undefined` when no rule caught it.
 * `undefined` is not a verdict: a phrase from a cracking dictionary can
 * pass every rule here, so check it against a breached-password list too.
 */
export function weakPasswordReason(password: unknown): string | undefined {
  // `entropy` throws INVALID_TYPE for anything but text or bytes.
  if (typeof password !== "string") return "Enter a password.";

  const { symbolCount, uniqueSymbols, longestRun, bits } = entropy(password);
  if (symbolCount < 15) return "Use at least 15 characters.";
  if (uniqueSymbols < 6) return "Use more different characters.";
  if (longestRun >= 8) return "Avoid sequences such as 12345678 or abcdefgh.";
  if (bits < 45) return "Repeat characters less often.";
  return undefined;
}
// #endregion
