import { describe, expect, it, vi } from "vitest";
import { hash } from "unsecure/hash";
import { totp } from "unsecure/otp";
import type { TwoFactorStore } from "../../../examples/recipes/two-factor-auth.ts";

const PASSWORD = "correct horse battery staple";

interface Row {
  passwordHash: string;
  pending?: string;
  secret?: string;
  lastStep: number | null;
  recovery: Set<string>;
}

/** The tables `TwoFactorStore` stands for, kept in memory and keyed by email. */
function memoryStore(): TwoFactorStore & { rows: Map<string, Row> } {
  const rows = new Map<string, Row>();
  const row = (id: string) => rows.get(id)!;
  return {
    rows,
    findByEmail: async (email) => {
      const found = rows.get(email);
      return found && { id: email, passwordHash: found.passwordHash };
    },
    setPasswordHash: async (id, passwordHash) => {
      const found = rows.get(id);
      if (found) found.passwordHash = passwordHash;
      else rows.set(id, { passwordHash, lastStep: null, recovery: new Set() });
    },
    setPendingSecret: async (id, secret) => {
      row(id).pending = secret;
    },
    getPendingSecret: async (id) => rows.get(id)?.pending,
    enableOtp: async (id, secret, step, recovery) => {
      Object.assign(row(id), { pending: undefined, secret, lastStep: step });
      row(id).recovery = new Set(recovery);
    },
    getOtp: async (id) => {
      const found = rows.get(id);
      return found?.secret ? { secret: found.secret, lastStep: found.lastStep } : undefined;
    },
    // UPDATE … WHERE id = $1 AND (last_otp_step IS NULL OR last_otp_step < $2)
    advanceStep: async (id, step) => {
      const found = rows.get(id);
      if (!found || (found.lastStep !== null && found.lastStep >= step)) return false;
      found.lastStep = step;
      return true;
    },
    // DELETE FROM recovery_codes WHERE user_id = $1 AND digest = $2
    consumeRecoveryCode: async (id, digest) => rows.get(id)?.recovery.delete(digest) ?? false,
  };
}

async function setup() {
  vi.stubEnv("PASSWORD_PEPPER", "a-long-random-pepper-from-the-environment");
  const recipe = await import("../../../examples/recipes/two-factor-auth.ts");
  const { register } = await import("../../../examples/crypto/store-passwords.ts");
  const store = memoryStore();
  await register(store, "ada@example.com", PASSWORD);
  return { ...recipe, store };
}

/** Enroll ada and return her secret plus the recovery codes she was shown. */
async function enrolled() {
  const context = await setup();
  const { beginEnrollment, confirmEnrollment, store } = context;
  await beginEnrollment(store, { id: "ada@example.com", email: "ada@example.com" });
  const secret = store.rows.get("ada@example.com")!.pending!;
  const recovery = await confirmEnrollment(store, "ada@example.com", await totp(secret));
  return { ...context, secret, recovery: recovery! };
}

/** A code for the next time step: the current one was spent confirming enrollment. */
const nextCode = (secret: string) => totp(secret, { time: Date.now() / 1000 + 30 });

describe("examples/recipes/two-factor-auth", () => {
  it("enrolls only after a valid code, and issues ten recovery codes stored as digests", async () => {
    const { beginEnrollment, confirmEnrollment, store } = await setup();
    const uri = await beginEnrollment(store, { id: "ada@example.com", email: "ada@example.com" });
    expect(uri).toMatch(/^otpauth:\/\/totp\/Acme%20Notes:ada%40example\.com\?secret=/);
    expect(uri).toContain("issuer=Acme%20Notes");
    expect(await confirmEnrollment(store, "ada@example.com", "000000")).toBeNull();
    expect(store.rows.get("ada@example.com")!.secret).toBeUndefined();

    const secret = store.rows.get("ada@example.com")!.pending!;
    const recovery = await confirmEnrollment(store, "ada@example.com", await totp(secret));
    expect(recovery).toHaveLength(10);
    for (const code of recovery!) expect(code).toMatch(/^[a-z0-9]{16}$/);
    const stored = store.rows.get("ada@example.com")!.recovery;
    expect(stored.has(await hash(recovery![0]!))).toBe(true);
    expect(stored.has(recovery![0]!)).toBe(false);
  }, 30_000);

  it("asks for a code after the password, then refuses the same code a second time", async () => {
    const { signIn, store, secret } = await enrolled();
    expect(await signIn(store, "ada@example.com", "hunter2")).toEqual({ ok: false });
    expect(await signIn(store, "ada@example.com", PASSWORD)).toEqual({
      ok: false,
      needsCode: true,
    });
    // The code that confirmed enrollment is already spent
    expect(await signIn(store, "ada@example.com", PASSWORD, await totp(secret))).toEqual({
      ok: false,
    });
    const code = await nextCode(secret);
    expect(await signIn(store, "ada@example.com", PASSWORD, code)).toMatchObject({ ok: true });
    expect(await signIn(store, "ada@example.com", PASSWORD, code)).toEqual({ ok: false });
  }, 30_000);

  it("lets exactly one of two concurrent submissions of one code through", async () => {
    const { signIn, store, secret } = await enrolled();
    // Hold both requests until each has read the same `lastStep`, the worst interleaving
    const getOtp = store.getOtp.bind(store);
    let arrived = 0;
    let release!: () => void;
    const bothRead = new Promise<void>((resolve) => (release = resolve));
    store.getOtp = async (id) => {
      const otp = await getOtp(id);
      if (++arrived === 2) release();
      await bothRead;
      return otp;
    };
    const code = await nextCode(secret);
    const results = await Promise.all([
      signIn(store, "ada@example.com", PASSWORD, code),
      signIn(store, "ada@example.com", PASSWORD, code),
    ]);
    expect(results.filter((r) => r.ok)).toHaveLength(1);
  }, 30_000);

  it("accepts a recovery code once, and only behind the right password", async () => {
    const { signInWithRecoveryCode, store, recovery } = await enrolled();
    const [first] = recovery;
    expect(await signInWithRecoveryCode(store, "ada@example.com", "hunter2", first!)).toEqual({
      ok: false,
    });
    expect(
      await signInWithRecoveryCode(store, "ada@example.com", PASSWORD, ` ${first!.toUpperCase()} `),
    ).toMatchObject({ ok: true });
    expect(await signInWithRecoveryCode(store, "ada@example.com", PASSWORD, first!)).toEqual({
      ok: false,
    });
    expect(store.rows.get("ada@example.com")!.recovery.size).toBe(9);
  }, 30_000);
});
