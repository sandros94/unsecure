import { bench, describe } from "vitest";
import { argon2id as nobleArgon2id } from "@noble/hashes/argon2.js";
import { argon2 } from "../src/argon2.ts";

/**
 * OWASP's argon2id recommendation, which is what `argon2Hash()` uses by default and the only
 * cost that says anything about whether this is usable for logging people in.
 */
const OWASP = { m: 19_456, t: 2, p: 1, length: 32 } as const;

const PASSWORD = "correct horse battery staple";
const SALT = new Uint8Array(16).fill(7);

describe("bench argon2id at OWASP parameters (m=19456, t=2, p=1, 32-byte tag)", () => {
  bench("unsecure", async () => {
    await argon2(PASSWORD, SALT, { ...OWASP, returnAs: "uint8array" });
  });

  bench("@noble/hashes", () => {
    nobleArgon2id(PASSWORD, SALT, { m: OWASP.m, t: OWASP.t, p: OWASP.p, dkLen: OWASP.length });
  });
});

describe("bench argon2id at a light cost (m=4096, t=1, p=1)", () => {
  const light = { m: 4096, t: 1, p: 1, length: 32 } as const;

  bench("unsecure", async () => {
    await argon2(PASSWORD, SALT, { ...light, returnAs: "uint8array" });
  });

  bench("@noble/hashes", () => {
    nobleArgon2id(PASSWORD, SALT, { m: light.m, t: light.t, p: light.p, dkLen: light.length });
  });
});
