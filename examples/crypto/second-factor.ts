import { generateOTPSecret, otpauthURI, totpVerify } from "unsecure/otp";

export interface User {
  id: string;
  email: string;
}

// #region store
export interface OtpRow {
  secret: string;
  lastStep: number | null;
}

export interface OtpStore {
  setPendingSecret(userId: string, secret: string): Promise<void>;
  getPendingSecret(userId: string): Promise<string | undefined>;
  /** Activates the secret and records `step` as the last accepted code. */
  enableOtp(userId: string, secret: string, step: number): Promise<void>;
  /** A nullable column reads back as `null`, not `undefined`. */
  getOtp(userId: string): Promise<OtpRow | undefined>;
  /**
   * A conditional write that resolves `true` only when a row changed:
   *   UPDATE users SET last_otp_step = $2
   *   WHERE id = $1 AND (last_otp_step IS NULL OR last_otp_step < $2)
   */
  advanceStep(userId: string, step: number): Promise<boolean>;
}
// #endregion

// #region enrol
/** Step 1: render the returned URI as a QR code. Nothing is enabled yet. */
export async function beginEnrollment(store: OtpStore, user: User): Promise<string> {
  const secret = generateOTPSecret();
  await store.setPendingSecret(user.id, secret);
  const account = user.email;
  return otpauthURI({ type: "totp", secret, account, issuer: "Acme" });
}

/** Step 2: enable the factor once a code proves the app is set up. */
export async function confirmEnrollment(
  store: OtpStore,
  userId: string,
  code: string,
): Promise<boolean> {
  const secret = await store.getPendingSecret(userId);
  if (!secret) return false;
  const result = await totpVerify(secret, code);
  if (!result.valid) return false;
  // Saving the step means this code cannot also pass the next login.
  await store.enableOtp(userId, secret, result.step);
  return true;
}
// #endregion

// #region verify
/** At login, after the password: `true` only for a fresh, unused code. */
export async function verifySecondFactor(
  store: OtpStore,
  userId: string,
  code: string | null,
): Promise<boolean> {
  const otp = await store.getOtp(userId);
  if (!otp) return false;
  const result = await totpVerify(otp.secret, code, {
    lastAccepted: otp.lastStep ?? undefined,
  });
  if (!result.valid) return false;
  // Two requests carrying the same code can both get this far.
  // The conditional write lets exactly one of them through.
  return store.advanceStep(userId, result.step);
}
// #endregion

/** The table `OtpStore` stands for, kept in memory. */
export function memoryStore(): OtpStore & { rows: Map<string, Row> } {
  const rows = new Map<string, Row>();
  const row = (userId: string): Row => {
    const found = rows.get(userId) ?? { pending: null, secret: null, lastStep: null };
    rows.set(userId, found);
    return found;
  };
  return {
    rows,
    setPendingSecret: async (userId, secret) => {
      row(userId).pending = secret;
    },
    getPendingSecret: async (userId) => rows.get(userId)?.pending ?? undefined,
    enableOtp: async (userId, secret, step) => {
      Object.assign(row(userId), { pending: null, secret, lastStep: step });
    },
    getOtp: async (userId) => {
      const found = rows.get(userId);
      return found?.secret ? { secret: found.secret, lastStep: found.lastStep } : undefined;
    },
    advanceStep: async (userId, step) => {
      const found = rows.get(userId);
      if (!found?.secret || (found.lastStep !== null && found.lastStep >= step)) return false;
      found.lastStep = step;
      return true;
    },
  };
}

interface Row {
  pending: string | null;
  secret: string | null;
  lastStep: number | null;
}
