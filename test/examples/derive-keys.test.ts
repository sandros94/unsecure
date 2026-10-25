import { describe, expect, it, vi } from "vitest";
import { hkdf, importHkdfKey } from "unsecure/hkdf";
import { hmac, hmacVerify, importHmacKey } from "unsecure/hmac";

const ROOT_SECRET = "mk_3q9ZcV7tLw2pX8rN4bJ6hF1sD5gK0yMa";

async function load() {
  vi.stubEnv("APP_ROOT_SECRET", ROOT_SECRET);
  return import("../../examples/crypto/derive-keys.ts");
}

describe("examples/crypto/derive-keys", () => {
  it("derives a stable, separate key per label", async () => {
    const { derive } = await load();
    const cookies = await derive("session-cookie");
    expect(cookies).toBeInstanceOf(Uint8Array);
    expect(cookies.length).toBe(32);
    expect(await derive("session-cookie")).toEqual(cookies);
    expect(await derive("file-encryption")).not.toEqual(cookies);
    expect(cookies).toEqual(
      await hkdf(new TextEncoder().encode(ROOT_SECRET), {
        salt: "acme-app",
        info: "acme/session-cookie/v1",
      }),
    );
  });

  it("hands out keys Web Crypto uses directly", async () => {
    const { cookieKey, fileKey } = await load();
    const sig = await hmac(cookieKey, "sid=7f3c9a");
    expect(await hmacVerify(cookieKey, "sid=7f3c9a", sig)).toBe(true);

    const iv = crypto.getRandomValues(new Uint8Array(12));
    const plain = new TextEncoder().encode("quarterly-report.pdf");
    const sealed = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, fileKey, plain);
    const opened = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, fileKey, sealed);
    expect(new Uint8Array(opened)).toEqual(plain);
  });

  it("accepts an empty IKM, which with a public salt is a key anyone can compute", async () => {
    const options = { salt: "acme-app", info: "acme/session-cookie/v1" } as const;
    const fromEmpty = await hkdf(await importHkdfKey(""), options);
    expect(fromEmpty).toEqual(await hkdf(new Uint8Array(0), options));
  });

  it("throws for the failure rows of the page", async () => {
    await expect(hkdf("ikm", { length: 0 })).rejects.toMatchObject({ code: "OUT_OF_RANGE" });
    await expect(hkdf("ikm", { length: 8161 })).rejects.toMatchObject({ code: "OUT_OF_RANGE" });
    expect((await hkdf("ikm", { length: 8160, returnAs: "bytes" })).length).toBe(8160);
    await expect(hkdf(await importHmacKey("ikm"), {})).rejects.toMatchObject({
      code: "OUT_OF_RANGE",
    });
    await expect(hkdf("ikm", { info: 7 as unknown as string })).rejects.toMatchObject({
      code: "INVALID_TYPE",
    });
    await expect(hkdf("ikm", { algorithm: "SHA3-256" as "SHA-256" })).rejects.toMatchObject({
      code: "UNSUPPORTED",
    });
  });
});
