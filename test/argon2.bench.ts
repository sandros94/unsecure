import { describe, test } from "vitest";
import { argon2id as nobleArgon2id } from "@noble/hashes/argon2.js";
import { argon2 } from "../src/argon2.ts";

const PASSWORD = "correct horse battery staple";
const SALT = new Uint8Array(16).fill(7);

const COSTS = [
  {
    /**
     * OWASP's argon2id recommendation, which is what `argon2Hash()` uses by default and the
     * only cost that says anything about whether this is usable for logging people in.
     */
    name: "OWASP parameters (m=19456, t=2, p=1, 32-byte tag)",
    cost: { m: 19_456, t: 2, p: 1, length: 32 },
  },
  {
    name: "a light cost (m=4096, t=1, p=1)",
    cost: { m: 4096, t: 1, p: 1, length: 32 },
  },
] as const;

describe("argon2id against @noble/hashes", () => {
  test.for(COSTS)("at $name", async ({ cost }, { bench }) => {
    await bench.compare(
      bench("unsecure", async () => {
        await argon2(PASSWORD, SALT, { ...cost, returnAs: "uint8array" });
      }),
      bench("@noble/hashes", () => {
        nobleArgon2id(PASSWORD, SALT, { m: cost.m, t: cost.t, p: cost.p, dkLen: cost.length });
      }),
    );
  });
});
