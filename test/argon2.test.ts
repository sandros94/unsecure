import { describe, it, expect } from "vitest";
import { hash as nodeRsHash, verify as nodeRsVerify } from "@node-rs/argon2";
import { argon2, argon2Hash, argon2Verify } from "../src/argon2.ts";
import type { Argon2Variant } from "../src/argon2.ts";
import { base64Stringify, hexStringify } from "../src/utils/index.ts";

const filled = (length: number, value: number) => new Uint8Array(length).fill(value);

// RFC 9106 §5.1–5.3 share every input except the variant.
const RFC_INPUT = {
  password: filled(32, 1),
  salt: filled(16, 2),
  secret: filled(8, 3),
  data: filled(12, 4),
  m: 32,
  t: 3,
  p: 4,
  length: 32,
} as const;

const RFC_TAGS: Record<Argon2Variant, string> = {
  // §5.1
  argon2d: "512b391b6f1162975371d30919734294f868e3be3984f3c1a13a4db9fabe4acb",
  // §5.2
  argon2i: "c814d9d1dc7f37aa13f0d77f2494bda1c8de6b016dd388d29952a4c4672b6ce8",
  // §5.3
  argon2id: "0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659",
};

/** Cheap parameters. The defaults are deliberately expensive; correctness does not need them. */
const CHEAP = { m: 64, t: 2, p: 1 } as const;

describe.concurrent("argon2 (RFC 9106 vectors)", () => {
  for (const variant of ["argon2d", "argon2i", "argon2id"] as const) {
    it(`matches the ${variant} test vector`, async () => {
      const { password, salt, ...rest } = RFC_INPUT;
      const tag = await argon2(password, salt, { ...rest, variant });
      expect(hexStringify(tag)).toBe(RFC_TAGS[variant]);
    });
  }
});

describe.concurrent("argon2 API", () => {
  const password = "correct horse battery staple";
  const salt = filled(16, 9);

  it("defaults to argon2id", async () => {
    const implicit = await argon2(password, salt, CHEAP);
    const explicit = await argon2(password, salt, { ...CHEAP, variant: "argon2id" });
    expect(implicit).toBe(explicit);
  });

  it("mirrors string password -> hex and BufferSource password -> bytes", async () => {
    const hex = await argon2(password, salt, CHEAP);
    const bytes = await argon2(new TextEncoder().encode(password), salt, CHEAP);
    expect(hex).toBeTypeOf("string");
    expect(bytes).toBeInstanceOf(Uint8Array);
    expect(hex).toBe(hexStringify(bytes));
  });

  it("defaults to a 32-byte tag", async () => {
    expect((await argon2(password, salt, { ...CHEAP, returnAs: "bytes" })).length).toBe(32);
  });

  it("emits the same bytes regardless of returnAs encoding", async () => {
    const bytes = await argon2(password, salt, { ...CHEAP, returnAs: "uint8array" });
    expect(await argon2(password, salt, { ...CHEAP, returnAs: "hex" })).toBe(hexStringify(bytes));
    expect(await argon2(password, salt, { ...CHEAP, returnAs: "b64" })).toBe(
      base64Stringify(bytes),
    );
    expect(await argon2(password, salt, { ...CHEAP, returnAs: "bytes" })).toEqual(bytes);
  });

  it("treats a string salt as its UTF-8 bytes", async () => {
    const fromString = await argon2(password, "a-pinch-of-salt!", CHEAP);
    const fromBytes = await argon2(password, new TextEncoder().encode("a-pinch-of-salt!"), {
      ...CHEAP,
      returnAs: "hex",
    });
    expect(fromString).toBe(fromBytes);
  });

  it("binds secret and data into the tag", async () => {
    const plain = await argon2(password, salt, CHEAP);
    const peppered = await argon2(password, salt, { ...CHEAP, secret: "pepper" });
    const contextual = await argon2(password, salt, { ...CHEAP, data: "ctx" });
    expect(peppered).not.toBe(plain);
    expect(contextual).not.toBe(plain);
    expect(peppered).not.toBe(contextual);
  });

  it("throws on an unknown variant", async () => {
    await expect(
      argon2(password, salt, { ...CHEAP, variant: "argon2x" as Argon2Variant }),
    ).rejects.toThrow('Unsupported argon2 variant: "argon2x".');
  });

  it("throws on out-of-range cost parameters", async () => {
    await expect(argon2(password, salt, { ...CHEAP, m: 7 })).rejects.toThrow(RangeError);
    await expect(argon2(password, salt, { m: 32, t: 2, p: 8 })).rejects.toThrow(/at least 8 \* p/);
    await expect(argon2(password, salt, { ...CHEAP, t: 0 })).rejects.toThrow(RangeError);
    await expect(argon2(password, salt, { ...CHEAP, p: 0 })).rejects.toThrow(RangeError);
    await expect(argon2(password, salt, { ...CHEAP, length: 3 })).rejects.toThrow(RangeError);
    await expect(argon2(password, salt, { ...CHEAP, m: 64.5 })).rejects.toThrow(RangeError);
  });

  it("throws on a salt shorter than 8 bytes", async () => {
    await expect(argon2(password, filled(7, 1), CHEAP)).rejects.toThrow(
      "argon2: salt must be at least 8 bytes.",
    );
  });

  it("throws on unsupported returnAs", async () => {
    await expect(
      argon2(password, salt, { ...CHEAP, returnAs: "unsupported" as any }),
    ).rejects.toThrow('Unsupported argon2 "returnAs" option: unsupported');
  });
});

describe.concurrent("argon2Hash / argon2Verify", () => {
  const password = "correct horse battery staple";

  it("round-trips through the PHC string", async () => {
    const phc = await argon2Hash(password, CHEAP);
    expect(phc).toMatch(/^\$argon2id\$v=19\$m=64,t=2,p=1\$[A-Za-z0-9+/]{22}\$[A-Za-z0-9+/]{43}$/);
    expect(await argon2Verify(phc, password)).toBe(true);
  });

  it("uses OWASP's parameters, a 16-byte salt, and a 32-byte tag by default", async () => {
    const phc = await argon2Hash(password);
    // 16 bytes -> 22 unpadded base64 characters, 32 bytes -> 43.
    expect(phc).toMatch(
      /^\$argon2id\$v=19\$m=19456,t=2,p=1\$[A-Za-z0-9+/]{22}\$[A-Za-z0-9+/]{43}$/,
    );
  });

  it("salts each call independently", async () => {
    const [first, second] = await Promise.all([
      argon2Hash(password, CHEAP),
      argon2Hash(password, CHEAP),
    ]);
    expect(first).not.toBe(second);
  });

  it("accepts an explicit salt so a tag can be reproduced", async () => {
    const options = { ...CHEAP, salt: filled(16, 9) };
    expect(await argon2Hash(password, options)).toBe(await argon2Hash(password, options));
  });

  it("returns false for a wrong password", async () => {
    const phc = await argon2Hash(password, CHEAP);
    expect(await argon2Verify(phc, "wrong horse battery staple")).toBe(false);
    expect(await argon2Verify(phc, "")).toBe(false);
  });

  it("verifies at the parameters embedded in the string, not the current defaults", async () => {
    const phc = await argon2Hash(password, { m: 128, t: 1, p: 2 });
    expect(phc).toContain("$m=128,t=1,p=2$");
    expect(await argon2Verify(phc, password)).toBe(true);
  });

  it("round-trips every variant", async () => {
    for (const variant of ["argon2id", "argon2i", "argon2d"] as const) {
      const phc = await argon2Hash(password, { ...CHEAP, variant });
      expect(phc.startsWith(`$${variant}$`)).toBe(true);
      expect(await argon2Verify(phc, password)).toBe(true);
    }
  });

  it("round-trips a non-default tag length", async () => {
    const phc = await argon2Hash(password, { ...CHEAP, length: 64 });
    expect(await argon2Verify(phc, password)).toBe(true);
  });

  it("requires the same secret and data to verify", async () => {
    const phc = await argon2Hash(password, { ...CHEAP, secret: "pepper", data: "ctx" });
    expect(await argon2Verify(phc, password, { secret: "pepper", data: "ctx" })).toBe(true);
    expect(await argon2Verify(phc, password, { secret: "pepper" })).toBe(false);
    expect(await argon2Verify(phc, password)).toBe(false);
  });

  it("throws on a malformed PHC string", async () => {
    const valid = await argon2Hash(password, CHEAP);
    const malformed = [
      "",
      "not-a-phc-string",
      valid.slice(1),
      valid.replace("$v=19$", "$"),
      valid.replace("m=64,t=2,p=1", "m=64,p=1"),
      // PHC forbids base64 padding.
      `${valid}=`,
      // A `$` inside a field cannot be part of the base64 alphabet.
      valid.replace(/.$/, "$"),
    ];
    for (const phc of malformed) {
      await expect(argon2Verify(phc, password)).rejects.toThrow(SyntaxError);
    }
  });

  it("refuses an unsupported variant by name", async () => {
    const phc = (await argon2Hash(password, CHEAP)).replace("$argon2id$", "$argon2z$");
    await expect(argon2Verify(phc, password)).rejects.toThrow(
      'Unsupported argon2 variant: "argon2z".',
    );
  });

  it("refuses the pre-RFC 0x10 version rather than emulating it", async () => {
    const phc = (await argon2Hash(password, CHEAP)).replace("$v=19$", "$v=16$");
    await expect(argon2Verify(phc, password)).rejects.toThrow(
      "Unsupported argon2 version: 16. Only 19 (0x13) is supported.",
    );
  });
});

describe.concurrent("argon2 interoperability", () => {
  const parameters = { memoryCost: 64, timeCost: 2, parallelism: 1, outputLen: 32, algorithm: 2 };

  it("accepts hashes produced by @node-rs/argon2", async () => {
    for (let i = 0; i < 5; i++) {
      const password = `password-${i}-${Math.random()}`;
      const phc = await nodeRsHash(password, parameters);
      expect(await argon2Verify(phc, password)).toBe(true);
      expect(await argon2Verify(phc, `${password}!`)).toBe(false);
    }
  });

  it("produces hashes @node-rs/argon2 accepts", async () => {
    for (let i = 0; i < 5; i++) {
      const password = `password-${i}-${Math.random()}`;
      const phc = await argon2Hash(password, { m: 64, t: 2, p: 1 });
      expect(await nodeRsVerify(phc, password)).toBe(true);
      expect(await nodeRsVerify(phc, `${password}!`)).toBe(false);
    }
  });

  it("derives the same raw tag as @node-rs/argon2 across parameter sets", async () => {
    const cases = [
      { m: 32, t: 1, p: 1, length: 16 },
      { m: 256, t: 3, p: 2, length: 32 },
      { m: 1024, t: 2, p: 4, length: 64 },
    ];
    for (const { m, t, p, length } of cases) {
      const salt = filled(16, m & 0xff);
      const phc = await nodeRsHash("shared-secret", {
        memoryCost: m,
        timeCost: t,
        parallelism: p,
        outputLen: length,
        algorithm: 2,
        salt,
      });
      const ours = await argon2("shared-secret", salt, { m, t, p, length, returnAs: "b64" });
      expect(phc.endsWith(ours.replace(/=+$/, ""))).toBe(true);
    }
  });
});
