import { afterEach, describe, expect, it, vi } from "vitest";
import { hmac, hmacVerify } from "unsecure/hmac";
import { secureRandomBytes } from "unsecure/random";
import { base64Stringify } from "unsecure/utils";

const ROOT = base64Stringify(secureRandomBytes(32), { alphabet: "base64url" });

async function load(secret: string | undefined) {
  vi.resetModules();
  vi.stubEnv("APP_ROOT_SECRET", secret);
  return import("../../../examples/recipes/derive-keys.ts");
}

afterEach(() => {
  vi.unstubAllEnvs();
});

describe("examples/recipes/derive-keys", () => {
  it("derives a different key per label from one root secret", async () => {
    const { cookieKey, csrfKey, downloadKey } = await load(ROOT);
    const value = "session=s_8f14e45fceea167a";
    const macs = await Promise.all([cookieKey, csrfKey, downloadKey].map((k) => hmac(k, value)));
    expect(new Set(macs).size).toBe(3);
  });

  it("derives the same keys again in another process from the same secret", async () => {
    const first = await load(ROOT);
    const second = await load(ROOT);
    const value = "session=s_8f14e45fceea167a";
    expect(await hmac(second.cookieKey, value)).toBe(await hmac(first.cookieKey, value));
  });

  it("signs and verifies a download link with its own key", async () => {
    const { downloadKey } = await load(ROOT);
    const link = "/files/q3-report.pdf?expires=1767225600";
    const signature = await hmac(downloadKey, link, { returnAs: "base64url" });
    expect(await hmacVerify(downloadKey, link, signature, { returnAs: "base64url" })).toBe(true);
    expect(await hmacVerify(downloadKey, `${link}0`, signature, { returnAs: "base64url" })).toBe(
      false,
    );
  });

  it("refuses to start without a root secret, or with a short one", async () => {
    await expect(load(undefined)).rejects.toThrow("APP_ROOT_SECRET is not set");
    await expect(load("")).rejects.toThrow("APP_ROOT_SECRET is not set");
    const short = base64Stringify(secureRandomBytes(16), { alphabet: "base64url" });
    await expect(load(short)).rejects.toThrow("APP_ROOT_SECRET must hold 32 random bytes");
  });

  it("reports a secret that is not base64url as MALFORMED", async () => {
    await expect(load("not base64url!")).rejects.toMatchObject({ code: "MALFORMED" });
  });
});
