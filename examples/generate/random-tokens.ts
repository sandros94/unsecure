import { secureGenerate } from "unsecure/generate";

// #region docs
/** A bearer token for an API client: 32 letters and digits, about 190 bits. */
export function newApiToken(): string {
  return secureGenerate({ length: 32, specials: false });
}

/**
 * An invite code people read off a printout. The sets leave out look-alikes
 * (0 and O, 1 and I and L), and every code holds a letter and a digit.
 */
export function newInviteCode(): string {
  return secureGenerate({
    length: 10,
    uppercase: "ABCDEFGHJKMNPQRSTUVWXYZ",
    lowercase: false,
    numbers: "23456789",
    specials: false,
  });
}

/** A first password for an account an admin creates, shown once. */
export function newTemporaryPassword(): string {
  return secureGenerate({ length: 20 });
}
// #endregion
