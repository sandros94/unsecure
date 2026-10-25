export interface TokenRow {
  id: string;
  userId: string;
  label: string;
  /** SHA-256 of the token, hex. Index this column. */
  digest: string;
  expiresAt: Date;
}

export interface TokenStore {
  insertToken(row: Omit<TokenRow, "id">): Promise<void>;
  /** `SELECT … FROM api_tokens WHERE digest = $1` */
  findByDigest(digest: string): Promise<TokenRow | undefined>;
}

// #region docs
import { secureCompare } from "unsecure/compare";
import { secureGenerate } from "unsecure/generate";
import { hash } from "unsecure/hash";

// A fixed prefix lets secret scanners recognize a leaked token
const PREFIX = "acme_pat_";
const NINETY_DAYS_MS = 90 * 86_400_000;

export async function issueToken(
  store: TokenStore,
  userId: string,
  label: string,
): Promise<string> {
  const token = PREFIX + secureGenerate({ length: 32, specials: false });
  const expiresAt = new Date(Date.now() + NINETY_DAYS_MS);
  await store.insertToken({ userId, label, digest: await hash(token), expiresAt });
  return token; // Show it once: only the digest is stored
}

export async function authenticate(
  store: TokenStore,
  authorization: string | null,
): Promise<TokenRow | null> {
  // The scheme name is case-insensitive (RFC 9110 §11.1): "Bearer", "bearer", …
  const token = /^bearer +(\S+)$/i.exec(authorization ?? "")?.[1] ?? "";
  if (!token.startsWith(PREFIX)) return null;
  const digest = await hash(token);
  const row = await store.findByDigest(digest);
  if (!row || !secureCompare(row.digest, digest)) return null;
  return row.expiresAt.getTime() > Date.now() ? row : null;
}
// #endregion
