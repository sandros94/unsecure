import { describe, it, expect } from "vitest";
import { hash as nodeRsHash, verify as nodeRsVerify } from "@node-rs/argon2";
import { argon2, argon2Hash, argon2Verify } from "../src/argon2.ts";
import type { Argon2Variant } from "../src/argon2.ts";
import { base64Stringify, hexStringify } from "../src/utils/index.ts";
import { UnsecureError } from "../src/errors.ts";
import { expectUnsecureError } from "./_helpers.ts";

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

const BASE64_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

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

  it("mirrors string password -> hex and BytesSource password -> bytes", async () => {
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
    await expectUnsecureError(
      argon2(password, salt, { ...CHEAP, variant: "argon2x" as Argon2Variant }),
      "UNSUPPORTED",
      'argon2: unsupported argon2 variant "argon2x".',
    );
  });

  it("throws on out-of-range cost parameters", async () => {
    await expectUnsecureError(argon2(password, salt, { ...CHEAP, m: 7 }), "OUT_OF_RANGE");
    await expectUnsecureError(
      argon2(password, salt, { m: 32, t: 2, p: 8 }),
      "OUT_OF_RANGE",
      "argon2: m (memory, KiB) must be an integer between 64 and 4294967295, got 32.",
    );
    await expectUnsecureError(argon2(password, salt, { ...CHEAP, t: 0 }), "OUT_OF_RANGE");
    await expectUnsecureError(argon2(password, salt, { ...CHEAP, p: 0 }), "OUT_OF_RANGE");
    await expectUnsecureError(argon2(password, salt, { ...CHEAP, length: 3 }), "OUT_OF_RANGE");
    await expectUnsecureError(argon2(password, salt, { ...CHEAP, m: 64.5 }), "OUT_OF_RANGE");
  });

  it("throws on cost parameters and tag lengths beyond their RFC 9106 word size", async () => {
    // Checked by message: without the cap these would be caught late by an allocation failure,
    // run for hours, or be silently truncated into H_0.
    await expectUnsecureError(
      argon2(password, salt, { ...CHEAP, m: 2 ** 32 }),
      "OUT_OF_RANGE",
      /m \(memory, KiB\) must be an integer between 8 and 4294967295/,
    );
    await expectUnsecureError(
      argon2(password, salt, { ...CHEAP, t: 2 ** 32 }),
      "OUT_OF_RANGE",
      /t \(iterations\) must be an integer between 1 and 4294967295/,
    );
    await expectUnsecureError(
      argon2(password, salt, { ...CHEAP, length: 2 ** 32 }),
      "OUT_OF_RANGE",
      /length must be an integer between 4 and 4294967295/,
    );
    await expectUnsecureError(
      argon2(password, salt, { ...CHEAP, p: 2 ** 24 }),
      "OUT_OF_RANGE",
      /p \(parallelism\) must be an integer between 1 and 16777215/,
    );
  });

  it("throws on a salt shorter than 8 bytes", async () => {
    await expectUnsecureError(
      argon2(password, filled(7, 1), CHEAP),
      "OUT_OF_RANGE",
      "argon2: salt length must be an integer between 8 and 4294967295, got 7.",
    );
  });

  it("throws on a password, salt, secret or data that is neither text nor bytes", async () => {
    await expectUnsecureError(argon2(42 as any, salt, CHEAP), "INVALID_TYPE");
    await expectUnsecureError(argon2(password, null as any, CHEAP), "INVALID_TYPE");
    await expectUnsecureError(
      argon2(password, salt, { ...CHEAP, secret: [1, 2] as any }),
      "INVALID_TYPE",
    );
    await expectUnsecureError(
      argon2(password, salt, { ...CHEAP, data: {} as any }),
      "INVALID_TYPE",
    );
  });

  it("throws on unsupported returnAs", async () => {
    await expectUnsecureError(
      argon2(password, salt, { ...CHEAP, returnAs: "unsupported" as any }),
      "UNSUPPORTED",
      'Unsupported argon2 "returnAs" option: unsupported',
    );
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
      valid.replace("m=64,t=2,p=1", "m=64,p=1"),
      // PHC forbids base64 padding.
      `${valid}=`,
      // A `$` inside a field cannot be part of the base64 alphabet.
      valid.replace(/.$/, "$"),
    ];
    for (const phc of malformed) {
      await expectUnsecureError(
        argon2Verify(phc, password),
        "MALFORMED",
        "argon2Verify: malformed PHC string.",
      );
    }
  });

  it("refuses a phc that is not a string before reading it as one", async () => {
    // A value that is not a string never claimed to be a PHC string, so it is the caller's
    // mistake rather than a stored value in an unexpected format.
    await expectUnsecureError(
      argon2Verify(123 as any, password),
      "INVALID_TYPE",
      "argon2Verify: expected a PHC string, got number.",
    );
    await expectUnsecureError(
      argon2Verify(null as any, password),
      "INVALID_TYPE",
      "argon2Verify: expected a PHC string, got null.",
    );
    await expectUnsecureError(
      argon2Verify(undefined as any, password),
      "INVALID_TYPE",
      "argon2Verify: expected a PHC string, got undefined.",
    );
    await expectUnsecureError(
      argon2Verify({} as any, password),
      "INVALID_TYPE",
      "argon2Verify: expected a PHC string, got Object.",
    );
  });

  it("refuses a tag whose trailing bits are not canonical base64", async () => {
    // The last character of a 43-character tag carries two bits past the 32nd byte, which a
    // canonical encoder leaves zero. Flipping one keeps the alphabet and the length intact, so
    // only a strict decode can tell that this string is not one this module wrote.
    const valid = await argon2Hash(password, CHEAP);
    const last = valid.slice(-1);
    const flipped = valid.slice(0, -1) + BASE64_ALPHABET[BASE64_ALPHABET.indexOf(last) ^ 1];
    expect(flipped).not.toBe(valid);
    const error = await expectUnsecureError(
      argon2Verify(flipped, password),
      "MALFORMED",
      "argon2Verify: malformed PHC string.",
    );
    // The codec said which character and why; the module keeps that as the cause.
    expect(error.cause).toBeInstanceOf(UnsecureError);
  });

  it("refuses a tag field that is not a whole number of base64 groups", async () => {
    // 41 characters encode 30 bytes plus a dangling symbol. A loose decode drops it and
    // compares a 30-byte tag; strict decoding says the string is malformed.
    const valid = await argon2Hash(password, CHEAP);
    const truncated = valid.slice(0, -2);
    expect(truncated.split("$")[5]).toHaveLength(41);
    await expectUnsecureError(
      argon2Verify(truncated, password),
      "MALFORMED",
      "argon2Verify: malformed PHC string.",
    );
  });

  it("refuses a salt shorter than the minimum once decoded", async () => {
    // A fixed salt so the truncation is deterministic: 16 bytes of 0x09 print as "CQkJ…", and
    // the first seven characters happen to be canonical base64 for five bytes. So this one
    // reaches the salt-length check rather than the decoder, and fails at 5 < 8.
    const valid = await argon2Hash(password, { ...CHEAP, salt: filled(16, 9) });
    const fields = valid.split("$");
    expect(fields[4]).toBe("CQkJCQkJCQkJCQkJCQkJCQ");
    fields[4] = fields[4].slice(0, 7);
    await expectUnsecureError(
      argon2Verify(fields.join("$"), password),
      "OUT_OF_RANGE",
      "argon2: salt length must be an integer between 8 and 4294967295, got 5.",
    );
  });

  it("refuses an unsupported variant by name", async () => {
    const phc = (await argon2Hash(password, CHEAP)).replace("$argon2id$", "$argon2z$");
    await expectUnsecureError(
      argon2Verify(phc, password),
      "UNSUPPORTED",
      'argon2Verify: unsupported argon2 variant "argon2z".',
    );
  });

  it("refuses the pre-RFC 0x10 version rather than emulating it", async () => {
    const phc = (await argon2Hash(password, CHEAP)).replace("$v=19$", "$v=16$");
    await expectUnsecureError(
      argon2Verify(phc, password),
      "UNSUPPORTED",
      "argon2Verify: unsupported argon2 version 16; only 19 (0x13) is supported.",
    );
  });

  it("reads a PHC string with no version field as 0x10 and refuses it by version", async () => {
    const phc = (await argon2Hash(password, CHEAP)).replace("$v=19$", "$");
    await expectUnsecureError(
      argon2Verify(phc, password),
      "UNSUPPORTED",
      "argon2Verify: unsupported argon2 version 16 (no v= field); only 19 (0x13) is supported.",
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
    const algorithm: Record<Argon2Variant, number> = { argon2d: 0, argon2i: 1, argon2id: 2 };
    const cases: Array<{
      variant: Argon2Variant;
      m: number;
      t: number;
      p: number;
      length: number;
    }> = [
      { variant: "argon2id", m: 32, t: 1, p: 1, length: 16 },
      { variant: "argon2id", m: 256, t: 3, p: 2, length: 32 },
      { variant: "argon2id", m: 1024, t: 2, p: 4, length: 64 },
      // A segment longer than 128 blocks makes the data-independent path refresh its address
      // block mid-segment; the RFC vectors (m=32, p=4) and the sets above never get there.
      { variant: "argon2i", m: 1024, t: 1, p: 1, length: 32 },
      { variant: "argon2id", m: 1024, t: 2, p: 1, length: 32 },
      { variant: "argon2d", m: 1024, t: 1, p: 1, length: 32 },
      // H' tails that are neither 64 bytes nor a multiple of 32.
      { variant: "argon2id", m: 64, t: 1, p: 1, length: 65 },
      { variant: "argon2id", m: 64, t: 1, p: 1, length: 100 },
    ];
    for (const { variant, m, t, p, length } of cases) {
      const salt = filled(16, m & 0xff);
      const phc = await nodeRsHash("shared-secret", {
        memoryCost: m,
        timeCost: t,
        parallelism: p,
        outputLen: length,
        algorithm: algorithm[variant],
        salt,
      });
      const ours = await argon2("shared-secret", salt, {
        variant,
        m,
        t,
        p,
        length,
        returnAs: "b64",
      });
      expect(phc.endsWith(ours.replace(/=+$/, ""))).toBe(true);
    }
  });
});
