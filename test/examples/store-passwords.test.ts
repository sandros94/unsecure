import { describe, expect, it, vi } from "vitest";

/** In-memory stand-in for the application's account table. */
function memoryStore() {
  const rows = new Map<string, { id: string; passwordHash: string }>();
  return {
    rows,
    findByEmail: async (email: string) => rows.get(email),
    setPasswordHash: async (id: string, hash: string) => {
      rows.set(id, { id, passwordHash: hash });
    },
  };
}

describe("examples/crypto/store-passwords", () => {
  it("registers, logs in, refuses a wrong password and an unknown email alike", async () => {
    vi.stubEnv("PASSWORD_PEPPER", "a-long-random-pepper-from-the-environment");
    const { login, register } = await import("../../examples/crypto/store-passwords.ts");
    const store = memoryStore();
    await register(store, "ada@example.com", "correct horse battery staple");

    expect(store.rows.get("ada@example.com")!.passwordHash.startsWith("$argon2id$v=19$")).toBe(
      true,
    );
    expect(await login(store, "ada@example.com", "correct horse battery staple")).toMatchObject({
      id: "ada@example.com",
    });
    expect(await login(store, "ada@example.com", "hunter2")).toBeNull();
    // The absent-account branch costs a full derivation and never throws.
    expect(await login(store, "nobody@example.com", "hunter2")).toBeNull();
  }, 30_000);

  it("rewrites a hash made with a lower cost on the next login", async () => {
    vi.stubEnv("PASSWORD_PEPPER", "a-long-random-pepper-from-the-environment");
    const { argon2Hash } = await import("unsecure/argon2");
    const { login } = await import("../../examples/crypto/store-passwords.ts");
    const store = memoryStore();
    const old = await argon2Hash("pw", {
      m: 8,
      t: 1,
      p: 1,
      secret: "a-long-random-pepper-from-the-environment",
    });
    store.rows.set("old@example.com", { id: "old@example.com", passwordHash: old });

    expect(await login(store, "old@example.com", "pw")).not.toBeNull();
    expect(store.rows.get("old@example.com")!.passwordHash).not.toBe(old);
    expect(store.rows.get("old@example.com")!.passwordHash).toContain("m=19456,t=2,p=1");
  }, 30_000);
});
