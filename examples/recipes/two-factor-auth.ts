// #region enroll
import { secureGenerate } from "unsecure/generate";
import { hash } from "unsecure/hash";
import { generateOTPSecret, otpauthURI, totpVerify } from "unsecure/otp";

/** Step 1: render the URI as a QR code. Nothing is enabled yet. */
export async function beginEnrollment(
  store: TwoFactorStore,
  user: { id: string; email: string },
): Promise<string> {
  const secret = generateOTPSecret();
  await store.setPendingSecret(user.id, secret);
  return otpauthURI({ type: "totp", secret, account: user.email, issuer: "Acme Notes" });
}

/** Step 2: a valid code enables the factor. Show the returned codes once. */
export async function confirmEnrollment(
  store: TwoFactorStore,
  userId: string,
  code: string,
): Promise<string[] | null> {
  const secret = await store.getPendingSecret(userId);
  if (!secret) return null;
  const result = await totpVerify(secret, code);
  if (!result.valid) return null;
  const recovery = Array.from({ length: 10 }, () =>
    secureGenerate({ length: 16, uppercase: false, specials: false }),
  );
  const digests = await Promise.all(recovery.map((text) => hash(text)));
  // Recording the step means this code cannot also pass the next login
  await store.enableOtp(userId, secret, result.step, digests);
  return recovery;
}
// #endregion

// #region docs
import { login } from "../crypto/store-passwords.ts";

export type SignIn = { ok: true; account: Account } | { ok: false; needsCode?: true };

export async function signIn(
  store: TwoFactorStore,
  email: string,
  password: string,
  code?: string,
): Promise<SignIn> {
  const account = await login(store, email, password);
  if (!account) return { ok: false };
  const otp = await store.getOtp(account.id);
  if (!otp) return { ok: true, account };
  if (code === undefined) return { ok: false, needsCode: true };

  const lastAccepted = otp.lastStep ?? undefined;
  const result = await totpVerify(otp.secret, code, { lastAccepted });
  // Two requests with the same code can both get here: one write wins
  const ok = result.valid && (await store.advanceStep(account.id, result.step));
  return ok ? { ok: true, account } : { ok: false };
}
// #endregion

// #region recovery
export async function signInWithRecoveryCode(
  store: TwoFactorStore,
  email: string,
  password: string,
  recoveryCode: string,
): Promise<SignIn> {
  const account = await login(store, email, password);
  if (!account) return { ok: false };
  const digest = await hash(recoveryCode.trim().toLowerCase());
  const used = await store.consumeRecoveryCode(account.id, digest);
  return used ? { ok: true, account } : { ok: false };
}
// #endregion

/** The account `login` returns, and the table it reads from. */
type Account = NonNullable<Awaited<ReturnType<typeof login>>>;
type PasswordStore = Parameters<typeof login>[0];

export interface TwoFactorStore extends PasswordStore {
  setPendingSecret(userId: string, secret: string): Promise<void>;
  getPendingSecret(userId: string): Promise<string | undefined>;
  /**
   * One transaction: set `otp_secret`, clear `pending_otp_secret`, record `step`
   * as `last_otp_step`, and replace every old recovery code digest.
   */
  enableOtp(userId: string, secret: string, step: number, recovery: string[]): Promise<void>;
  /** A nullable column reads back as `null`, not `undefined`. */
  getOtp(userId: string): Promise<{ secret: string; lastStep: number | null } | undefined>;
  /** Conditional write: `true` only when a row changed. */
  advanceStep(userId: string, step: number): Promise<boolean>;
  /** Atomic delete by value: `true` only when a row was deleted. */
  consumeRecoveryCode(userId: string, digest: string): Promise<boolean>;
}
