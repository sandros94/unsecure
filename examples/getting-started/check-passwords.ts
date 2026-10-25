// #region docs
import { argon2Hash, argon2Verify } from "unsecure/argon2";

/** At sign-up: the string to store in the account's password column. */
export async function hashPassword(password: string): Promise<string> {
  return argon2Hash(password);
}

/** At login: `true` only when `attempt` is the password `stored` was made from. */
export async function checkPassword(stored: string, attempt: unknown): Promise<boolean> {
  // A form field can be missing or an array. Refuse it here, because
  // `argon2Verify` throws for anything that is not text.
  if (typeof attempt !== "string") return false;
  return argon2Verify(stored, attempt);
}
// #endregion
