// #region setup
import { argon2Hash, argon2NeedsRehash, argon2Verify } from "unsecure/argon2";
import { secureRandomBytes } from "unsecure/random";

/** What the application persists per account. */
interface Account {
  id: string;
  passwordHash: string;
}

interface Store {
  findByEmail(email: string): Promise<Account | undefined>;
  setPasswordHash(id: string, hash: string): Promise<void>;
}

// The pepper never sits next to the hashes: a dumped table is useless without it.
const pepper = process.env.PASSWORD_PEPPER;
if (!pepper) throw new Error("PASSWORD_PEPPER is not set");

// A real hash of a value nobody holds, at the same cost as every account's hash,
// so a login for an unknown email takes as long and answers the same `false`.
const absent = await argon2Hash(secureRandomBytes(32), { secret: pepper });
// #endregion

// #region docs
export async function register(store: Store, id: string, password: string): Promise<void> {
  await store.setPasswordHash(id, await argon2Hash(password, { secret: pepper }));
}

export async function login(
  store: Store,
  email: string,
  password: string,
): Promise<Account | null> {
  const account = await store.findByEmail(email);
  const valid = await argon2Verify(account?.passwordHash ?? absent, password, { secret: pepper });
  if (!account || !valid) return null;

  // The plaintext is in hand, so rewrite a hash made with yesterday's cost now.
  if (argon2NeedsRehash(account.passwordHash)) {
    await store.setPasswordHash(account.id, await argon2Hash(password, { secret: pepper }));
  }
  return account;
}
// #endregion
