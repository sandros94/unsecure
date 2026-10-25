import { describe, it, expect } from "vitest";
import { argon2Hash, argon2NeedsRehash, argon2Verify } from "../src/argon2.ts";
import { secureGenerate } from "../src/generate.ts";
import { hash } from "../src/hash.ts";
import { hkdf } from "../src/hkdf.ts";
import { hmac, hmacVerify } from "../src/hmac.ts";
import { hotp, totp, totpVerify } from "../src/otp.ts";
import { secureCompare } from "../src/compare.ts";
import { sanitizeObjectCopy } from "../src/sanitize.ts";
import { base32Parse, base64Parse, hexParse } from "../src/utils/index.ts";
import { uuidv7Timestamp } from "../src/uuid.ts";
import { expectUnsecureError } from "./_helpers.ts";

/**
 * Run `fn` with `keys` set on `Object.prototype`, as a pollution primitive
 * elsewhere in a process would leave them, and clean up whatever happens.
 * The keys are chosen so nothing but the library reads them: `window` or
 * `length` would reach the test runner through `globalThis` and arrays.
 */
async function polluted<T>(keys: Record<string, unknown>, fn: () => T | Promise<T>): Promise<T> {
  const proto = Object.prototype as unknown as Record<string, unknown>;
  for (const [key, value] of Object.entries(keys)) proto[key] = value;
  try {
    return await fn();
  } finally {
    for (const key of Object.keys(keys)) delete proto[key];
  }
}

const FAST = { m: 8, t: 1, p: 1 } as const;
const SECRET = "JBSWY3DPEHPK3PXP";

describe("option bags read own properties only", () => {
  it("argon2Hash keeps a fresh salt and the default cost under a polluted prototype", async () => {
    const [a, b] = await polluted({ salt: "fixedsalt", m: 8, t: 1 }, () =>
      Promise.all([argon2Hash("pw", FAST), argon2Hash("pw", FAST)]),
    );
    expect(a.split("$")[4]).not.toBe(b.split("$")[4]);
    expect(a).not.toContain("Zml4ZWRzYWx0");
    // Resolved defaults, not the polluted ones.
    expect(await polluted({ m: 8, t: 1, p: 1 }, () => argon2NeedsRehash(a))).toBe(true);
  });

  it("argon2Verify ignores an inherited secret, data and limits", async () => {
    const stored = await argon2Hash("pw", FAST);
    expect(
      await polluted({ secret: "pepper", limits: { t: 0 } }, () => argon2Verify(stored, "pw")),
    ).toBe(true);
  });

  it("secureGenerate keeps its charset and length", async () => {
    const token = await polluted(
      { uppercase: "A", lowercase: false, numbers: false, specials: false, timestamp: true },
      () => secureGenerate({ length: 32 }),
    );
    expect(token).toHaveLength(32);
    expect(token).not.toMatch(/^A+$/);
  });

  it("totpVerify keeps its window, period and time", async () => {
    const time = 1_700_000_000;
    const code = await totp(SECRET, { time });
    const result = await polluted({ period: 1e9, time, lastAccepted: 0 }, () =>
      totpVerify(SECRET, code, { time: time + 120 }),
    );
    expect(result.valid).toBe(false);
  });

  it("a string OTP secret decodes with the standard alphabet", async () => {
    const expected = await hotp(SECRET, 0);
    const actual = await polluted(
      { alphabet: "Aabcdefghijklmnopqrstuvwxyz!#$%&", loose: false },
      () => hotp(SECRET, 0),
    );
    expect(actual).toBe(expected);
  });

  it("hash, hmac and hkdf keep SHA-256 and their lengths", async () => {
    const [digest, mac, key] = await polluted(
      { algorithm: "SHA-1", length: 1, returnAs: "base64" },
      () =>
        Promise.all([
          hash("a"),
          hmac("k", "a", { returnAs: "uint8array" }),
          hkdf("ikm", { returnAs: "uint8array" }),
        ]),
    );
    expect(digest).toBe(await hash("a"));
    // Web Crypto's own dictionaries read inherited members too: an inherited
    // `length` would have truncated the imported HMAC key.
    expect(mac).toEqual(await hmac("k", "a", { returnAs: "uint8array" }));
    expect(key).toEqual(await hkdf("ikm", { returnAs: "uint8array" }));
    expect(await polluted({ algorithm: "SHA-1", length: 1 }, () => hmacVerify("k", "a", mac))).toBe(
      true,
    );
  });

  it("codecs keep strict decoding and their alphabets", async () => {
    await polluted({ loose: true, alphabet: "base64url", padding: true }, () => {
      expectUnsecureError(() => hexParse("zz"), "MALFORMED");
      expectUnsecureError(() => base64Parse("++//"), "MALFORMED", undefined);
      expect(base64Parse("aGk=")).toBe("hi");
      expect(base32Parse("NBUQ")).toBe("hi");
    });
  });

  it("secureCompare and sanitizeObjectCopy read strict and allowlist as own properties", async () => {
    await polluted({ strict: true, allowlist: [Map] }, () => {
      expect(secureCompare(undefined, "x")).toBe(false);
      expectUnsecureError(() => sanitizeObjectCopy({ m: new Map() } as any), "INVALID_TYPE");
    });
  });
});

describe("untrusted values in error messages", () => {
  const nameObject = JSON.parse('{"constructor":{"name":{"toString":0}}}') as object;
  const nameText = JSON.parse('{"constructor":{"name":"x.\\n[INFO] admin login ok"}}') as object;

  it("a constructor.name that is not a string renders as a type, never a native throw", async () => {
    const stored = await argon2Hash("pw", FAST);
    await expectUnsecureError(
      argon2Verify(stored, nameObject as never),
      "INVALID_TYPE",
      "got object.",
    );
    await expectUnsecureError(hmac("k", nameObject as never), "INVALID_TYPE", "got object.");
    expectUnsecureError(() => base64Parse(nameObject as never), "INVALID_TYPE", "got object.");
    expect(secureCompare("x", nameObject as never)).toBe(false);
  });

  it("a constructor.name that is text is not copied into the message", () => {
    const error = expectUnsecureError(() => hexParse(nameText as never), "INVALID_TYPE");
    expect(error.message).not.toContain("\n");
    expect(error.message).toContain("got object.");
  });

  it("uuidv7Timestamp quotes text and names other types", () => {
    const error = expectUnsecureError(() => uuidv7Timestamp("x\n[INFO] forged"), "MALFORMED");
    expect(error.message).not.toContain("\n[INFO]");
    expectUnsecureError(() => uuidv7Timestamp({ toString: 0 } as never), "INVALID_TYPE", "Object");
    expectUnsecureError(() => uuidv7Timestamp(Object.create(null) as never), "INVALID_TYPE");
  });
});
