import { describe, expect, it } from "vitest";
import { argon2Verify } from "unsecure/argon2";
import { UnsecureError } from "unsecure/errors";
import { checkPassword, hashPassword } from "../../examples/getting-started/check-passwords.ts";

describe("examples/getting-started/check-passwords", () => {
  it("stores a PHC string and checks a later attempt against it", async () => {
    const stored = await hashPassword("correct horse battery staple");

    expect(stored.startsWith("$argon2id$v=19$m=19456,t=2,p=1$")).toBe(true);
    expect(await checkPassword(stored, "correct horse battery staple")).toBe(true);
    expect(await checkPassword(stored, "Tr0ub4dor&3")).toBe(false);
    expect(await checkPassword(stored, undefined)).toBe(false);
    expect(await checkPassword(stored, ["correct horse battery staple"])).toBe(false);
  }, 30_000);

  it("guards the type because argon2Verify throws INVALID_TYPE for non-text", async () => {
    const stored = await hashPassword("correct horse battery staple");
    const error = await argon2Verify(stored, undefined as unknown as string).catch((e) => e);

    expect(error).toBeInstanceOf(UnsecureError);
    expect(error.code).toBe("INVALID_TYPE");
  }, 30_000);

  it("throws for a stored value that is not a PHC string", async () => {
    await expect(
      checkPassword("5f4dcc3b5aa765d61d8327deb882cf99", "password"),
    ).rejects.toMatchObject({
      code: "MALFORMED",
    });
  });
});
