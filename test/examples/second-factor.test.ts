import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { importHmacKey } from "unsecure/hmac";
import { otpauthURI, totp, totpVerify } from "unsecure/otp";
import { base32Parse } from "unsecure/utils";
import {
  beginEnrollment,
  confirmEnrollment,
  memoryStore,
  verifySecondFactor,
} from "../../examples/crypto/second-factor.ts";

const ada = { id: "usr_ada", email: "ada@example.com" };

/** The code an authenticator app shows `offset` steps from now. */
function codeAt(secret: string, offset = 0): Promise<string> {
  return totp(secret, { time: Date.now() / 1000 + offset * 30 });
}

async function enrolledUser() {
  const store = memoryStore();
  const uri = await beginEnrollment(store, ada);
  const secret = new URL(uri).searchParams.get("secret")!;
  expect(await confirmEnrollment(store, ada.id, await codeAt(secret))).toBe(true);
  return { store, secret, uri };
}

describe("examples/crypto/second-factor", () => {
  // Mid-step, so no call in a test crosses into the next 30-second step.
  beforeEach(() => {
    vi.useFakeTimers({ toFake: ["Date"] });
    vi.setSystemTime(new Date("2026-10-25T09:00:15Z"));
  });
  afterEach(() => {
    vi.useRealTimers();
  });

  it("enrolls only after a correct code, and names the issuer twice in the URI", async () => {
    const store = memoryStore();
    const uri = await beginEnrollment(store, ada);
    expect(uri).toMatch(/^otpauth:\/\/totp\/Acme:ada%40example\.com\?secret=[A-Z2-7]{32}&/);
    expect(uri).toContain("&issuer=Acme&");
    expect(await verifySecondFactor(store, ada.id, "123456")).toBe(false);

    const secret = new URL(uri).searchParams.get("secret")!;
    const accepted = await Promise.all([-1, 0, 1].map((offset) => codeAt(secret, offset)));
    const wrong = ["000000", "111111", "222222", "333333"].find((c) => !accepted.includes(c))!;
    expect(await confirmEnrollment(store, ada.id, wrong)).toBe(false);
    expect(store.rows.get(ada.id)!.secret).toBeNull();
    expect(await confirmEnrollment(store, ada.id, await codeAt(secret))).toBe(true);
    expect(store.rows.get(ada.id)!.secret).toBe(secret);
  });

  it("refuses the enrollment code at login, then accepts each newer code once", async () => {
    const { store, secret } = await enrolledUser();
    expect(await verifySecondFactor(store, ada.id, await codeAt(secret))).toBe(false);
    const next = await codeAt(secret, 1);
    expect(await verifySecondFactor(store, ada.id, next)).toBe(true);
    expect(await verifySecondFactor(store, ada.id, next)).toBe(false);
  });

  it("lets only one of two concurrent requests with the same code through", async () => {
    const { store, secret } = await enrolledUser();
    const next = await codeAt(secret, 1);
    const results = await Promise.all([
      verifySecondFactor(store, ada.id, next),
      verifySecondFactor(store, ada.id, next),
    ]);
    expect(results.toSorted()).toEqual([false, true]);
  });

  it("reads a NULL last step as nothing accepted yet", async () => {
    const { store, secret } = await enrolledUser();
    store.rows.get(ada.id)!.lastStep = null;
    expect(await verifySecondFactor(store, ada.id, await codeAt(secret))).toBe(true);
    await expect(
      totpVerify(secret, "123456", { lastAccepted: null as unknown as number }),
    ).rejects.toMatchObject({ code: "OUT_OF_RANGE" });
  });

  it("returns false for untrusted codes and throws for configuration", async () => {
    const { store, secret } = await enrolledUser();
    expect(await verifySecondFactor(store, ada.id, null)).toBe(false);
    expect(await totpVerify(secret, 123456 as unknown as string)).toEqual({
      valid: false,
      delta: 0,
    });
    expect(await verifySecondFactor(store, ada.id, await codeAt(secret, 3))).toBe(false);
    await expect(totpVerify("", "123456")).rejects.toMatchObject({ code: "OUT_OF_RANGE" });
    await expect(totpVerify(secret, "123456", { digits: 10 })).rejects.toMatchObject({
      code: "OUT_OF_RANGE",
    });
    expect(() => otpauthURI({ type: "totp", secret, account: "ada\ud800" })).toThrow(
      expect.objectContaining({ code: "MALFORMED" }),
    );
    expect(() => otpauthURI({ type: "totp", secret, account: "" })).toThrow(
      expect.objectContaining({ code: "OUT_OF_RANGE" }),
    );
  });

  it("accepts a key imported from the decoded secret, and refuses a mismatched hash", async () => {
    const { secret } = await enrolledUser();
    const key = await importHmacKey(base32Parse(secret, { returnAs: "bytes" }), {
      algorithm: "SHA-1",
    });
    const result = await totpVerify(key, await codeAt(secret, 1));
    expect(result).toMatchObject({ valid: true, delta: 1 });
    const utf8 = await importHmacKey(secret, { algorithm: "SHA-1" });
    expect((await totpVerify(utf8, await codeAt(secret, 1))).valid).toBe(false);
    await expect(totpVerify(key, "123456", { algorithm: "SHA-256" })).rejects.toMatchObject({
      code: "OUT_OF_RANGE",
    });
  });
});
