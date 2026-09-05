import { describe, it, expect, vi } from "vitest";
import { hotp, hotpVerify, totp, totpVerify, generateOTPSecret, otpauthURI } from "../src/otp.ts";
import { base32Stringify, base32Parse } from "../src/utils/index.ts";

// RFC 4226 test secret: ASCII "12345678901234567890" (20 bytes)
const RFC4226_SECRET = new TextEncoder().encode("12345678901234567890");

// RFC 6238 test secrets (raw ASCII bytes, different lengths per algorithm)
const RFC6238_SHA1_SECRET = new TextEncoder().encode("12345678901234567890");
const RFC6238_SHA256_SECRET = new TextEncoder().encode("12345678901234567890123456789012");
const RFC6238_SHA512_SECRET = new TextEncoder().encode(
  "1234567890123456789012345678901234567890123456789012345678901234",
);

describe("HOTP (RFC 4226)", () => {
  // RFC 4226 Appendix D test values
  const rfcVectors: Array<[number, string]> = [
    [0, "755224"],
    [1, "287082"],
    [2, "359152"],
    [3, "969429"],
    [4, "338314"],
    [5, "254676"],
    [6, "287922"],
    [7, "162583"],
    [8, "399871"],
    [9, "520489"],
  ];

  describe("hotp()", () => {
    for (const [counter, expected] of rfcVectors) {
      it(`counter=${counter} → ${expected}`, async () => {
        const code = await hotp(RFC4226_SECRET, counter);
        expect(code).toBe(expected);
      });
    }

    it("should support 8-digit codes", async () => {
      const code = await hotp(RFC4226_SECRET, 0, { digits: 8 });
      expect(code).toHaveLength(8);
    });

    it("should accept base32 string secret", async () => {
      const b32 = base32Stringify(RFC4226_SECRET);
      const code = await hotp(b32, 0);
      expect(code).toBe("755224");
    });

    it("should accept SharedArrayBuffer-backed Uint8Array secret", async () => {
      const sab = new SharedArrayBuffer(RFC4226_SECRET.length);
      const view = new Uint8Array(sab);
      view.set(RFC4226_SECRET);
      const code = await hotp(view, 0);
      expect(code).toBe("755224");
    });
  });

  describe("hotpVerify()", () => {
    it("should return valid for correct OTP", async () => {
      const result = await hotpVerify(RFC4226_SECRET, "755224", 0);
      expect(result).toEqual({ valid: true, delta: 0 });
    });

    it("should return invalid for wrong OTP", async () => {
      const result = await hotpVerify(RFC4226_SECRET, "000000", 0);
      expect(result).toEqual({ valid: false, delta: 0 });
    });

    it("should find OTP within window", async () => {
      // OTP for counter=3 is "969429"
      const result = await hotpVerify(RFC4226_SECRET, "969429", 0, { window: 5 });
      expect(result).toEqual({ valid: true, delta: 3 });
    });

    it("should fail when OTP is outside window", async () => {
      // OTP for counter=5 is "254676", window of 2 checks 0,1,2 only
      const result = await hotpVerify(RFC4226_SECRET, "254676", 0, { window: 2 });
      expect(result).toEqual({ valid: false, delta: 0 });
    });
  });
});

describe("TOTP (RFC 6238)", () => {
  // RFC 6238 Appendix B test values (8 digits, period 30)
  const rfcVectors: Array<{
    time: number;
    sha1: string;
    sha256: string;
    sha512: string;
  }> = [
    { time: 59, sha1: "94287082", sha256: "46119246", sha512: "90693936" },
    { time: 1111111109, sha1: "07081804", sha256: "68084774", sha512: "25091201" },
    { time: 1111111111, sha1: "14050471", sha256: "67062674", sha512: "99943326" },
    { time: 1234567890, sha1: "89005924", sha256: "91819424", sha512: "93441116" },
    { time: 2000000000, sha1: "69279037", sha256: "90698825", sha512: "38618901" },
    { time: 20000000000, sha1: "65353130", sha256: "77737706", sha512: "47863826" },
  ];

  describe("totp() — SHA-1", () => {
    for (const v of rfcVectors) {
      it(`time=${v.time} → ${v.sha1}`, async () => {
        const code = await totp(RFC6238_SHA1_SECRET, {
          time: v.time,
          digits: 8,
        });
        expect(code).toBe(v.sha1);
      });
    }
  });

  describe("totp() — SHA-256", () => {
    for (const v of rfcVectors) {
      it(`time=${v.time} → ${v.sha256}`, async () => {
        const code = await totp(RFC6238_SHA256_SECRET, {
          time: v.time,
          digits: 8,
          algorithm: "SHA-256",
        });
        expect(code).toBe(v.sha256);
      });
    }
  });

  describe("totp() — SHA-512", () => {
    for (const v of rfcVectors) {
      it(`time=${v.time} → ${v.sha512}`, async () => {
        const code = await totp(RFC6238_SHA512_SECRET, {
          time: v.time,
          digits: 8,
          algorithm: "SHA-512",
        });
        expect(code).toBe(v.sha512);
      });
    }
  });

  describe("totp() defaults", () => {
    it("should default to 6 digits", async () => {
      const code = await totp(RFC6238_SHA1_SECRET, { time: 59 });
      expect(code).toHaveLength(6);
    });

    it("should accept base32 string secret", async () => {
      const b32 = base32Stringify(RFC6238_SHA1_SECRET);
      const code = await totp(b32, { time: 59, digits: 8 });
      expect(code).toBe("94287082");
    });

    it("should support custom period", async () => {
      // time=60, period=60 → counter=1; time=60, period=30 → counter=2
      const code60 = await totp(RFC6238_SHA1_SECRET, { time: 60, period: 60 });
      const code30 = await totp(RFC6238_SHA1_SECRET, { time: 60, period: 30 });
      expect(code60).not.toBe(code30);
    });

    it("should use Date.now() when time is not provided", async () => {
      const fakeNow = 59 * 1000; // 59 seconds in ms
      vi.spyOn(Date, "now").mockReturnValue(fakeNow);
      const code = await totp(RFC6238_SHA1_SECRET, { digits: 8 });
      vi.restoreAllMocks();
      // Should match the explicit time=59 result
      const expected = await totp(RFC6238_SHA1_SECRET, { time: 59, digits: 8 });
      expect(code).toBe(expected);
    });
  });

  describe("totpVerify()", () => {
    it("should verify current time step", async () => {
      const code = await totp(RFC6238_SHA1_SECRET, { time: 59, digits: 8 });
      const result = await totpVerify(RFC6238_SHA1_SECRET, code, {
        time: 59,
        digits: 8,
      });
      expect(result).toEqual({ valid: true, delta: 0 });
    });

    it("should verify within window (previous step)", async () => {
      // Code at time=29 (counter=0) should still verify at time=59 (counter=1) with window=1
      const code = await totp(RFC6238_SHA1_SECRET, { time: 29, digits: 8 });
      const result = await totpVerify(RFC6238_SHA1_SECRET, code, {
        time: 59,
        digits: 8,
        window: 1,
      });
      expect(result).toEqual({ valid: true, delta: -1 });
    });

    it("should verify within window (next step)", async () => {
      // Code at time=59 (counter=1) should verify at time=29 (counter=0) with window=1
      const code = await totp(RFC6238_SHA1_SECRET, { time: 59, digits: 8 });
      const result = await totpVerify(RFC6238_SHA1_SECRET, code, {
        time: 29,
        digits: 8,
        window: 1,
      });
      expect(result).toEqual({ valid: true, delta: 1 });
    });

    it("should fail outside window", async () => {
      // Code at time=0 (counter=0) should NOT verify at time=90 (counter=3) with window=1
      const code = await totp(RFC6238_SHA1_SECRET, { time: 0, digits: 8 });
      const result = await totpVerify(RFC6238_SHA1_SECRET, code, {
        time: 90,
        digits: 8,
        window: 1,
      });
      expect(result).toEqual({ valid: false, delta: 0 });
    });

    it("should fail for wrong OTP", async () => {
      const result = await totpVerify(RFC6238_SHA1_SECRET, "00000000", {
        time: 59,
        digits: 8,
      });
      expect(result).toEqual({ valid: false, delta: 0 });
    });

    it("should use Date.now() when time is not provided", async () => {
      const fakeNow = 59 * 1000;
      vi.spyOn(Date, "now").mockReturnValue(fakeNow);
      const code = await totp(RFC6238_SHA1_SECRET, { digits: 8 });
      const result = await totpVerify(RFC6238_SHA1_SECRET, code, { digits: 8 });
      vi.restoreAllMocks();
      expect(result).toEqual({ valid: true, delta: 0 });
    });
  });
});

describe("generateOTPSecret()", () => {
  it("should return a base32 string without padding", () => {
    const secret = generateOTPSecret();
    expect(secret).not.toContain("=");
    expect(secret).toMatch(/^[A-Z2-7]+$/);
  });

  it("should default to 20 bytes (32 base32 chars)", () => {
    const secret = generateOTPSecret();
    // 20 bytes → 32 base32 chars (no padding)
    expect(secret).toHaveLength(32);
  });

  it("should support custom length", () => {
    const secret = generateOTPSecret(32);
    // 32 bytes → ceil(32 * 8 / 5) = 52 chars (with 4 padding chars stripped)
    // Actually: 32 bytes = 256 bits, 256/5 = 51.2, so 52 base32 chars, padded to 56, minus padding
    const decoded = base32Parse(secret, { loose: true, returnAs: "uint8array" });
    expect(decoded).toHaveLength(32);
  });

  it("should produce different values each call", () => {
    const a = generateOTPSecret();
    const b = generateOTPSecret();
    expect(a).not.toBe(b);
  });

  it("should roundtrip through base32 decode", () => {
    const secret = generateOTPSecret();
    const bytes = base32Parse(secret, { loose: true, returnAs: "uint8array" });
    expect(bytes).toHaveLength(20);
  });
});

describe("otpauthURI()", () => {
  const secret = new TextEncoder().encode("12345678901234567890");
  const secretB32 = base32Stringify(secret).replace(/=+$/, "");

  it("should generate a valid TOTP URI", () => {
    const uri = otpauthURI({
      type: "totp",
      secret,
      account: "user@example.com",
      issuer: "MyApp",
    });
    expect(uri).toContain("otpauth://totp/");
    expect(uri).toContain(`secret=${secretB32}`);
    expect(uri).toContain("issuer=MyApp");
    expect(uri).toContain("algorithm=SHA1");
    expect(uri).toContain("digits=6");
    expect(uri).toContain("period=30");
  });

  it("should generate a valid HOTP URI with counter", () => {
    const uri = otpauthURI({
      type: "hotp",
      secret,
      account: "user@example.com",
      counter: 0,
    });
    expect(uri).toContain("otpauth://hotp/");
    expect(uri).toContain("counter=0");
    expect(uri).not.toContain("period=");
  });

  it("should throw when HOTP URI is missing counter", () => {
    expect(() =>
      otpauthURI({
        type: "hotp",
        secret,
        account: "user@example.com",
      }),
    ).toThrow("counter is required for HOTP URIs.");
  });

  it("should encode issuer and account in label", () => {
    const uri = otpauthURI({
      type: "totp",
      secret,
      account: "user@example.com",
      issuer: "My App",
    });
    expect(uri).toContain("My%20App:user%40example.com");
  });

  it("should accept base32 string secret", () => {
    const uri = otpauthURI({
      type: "totp",
      secret: secretB32,
      account: "test",
    });
    expect(uri).toContain(`secret=${secretB32}`);
  });

  it("should use custom algorithm and digits", () => {
    const uri = otpauthURI({
      type: "totp",
      secret,
      account: "test",
      algorithm: "SHA-256",
      digits: 8,
    });
    expect(uri).toContain("algorithm=SHA256");
    expect(uri).toContain("digits=8");
  });

  it("should use custom period", () => {
    const uri = otpauthURI({
      type: "totp",
      secret,
      account: "test",
      period: 60,
    });
    expect(uri).toContain("period=60");
  });

  it("should omit issuer from label when not provided", () => {
    const uri = otpauthURI({
      type: "totp",
      secret,
      account: "test",
    });
    expect(uri).toMatch(/otpauth:\/\/totp\/test\?/);
    expect(uri).not.toContain("issuer=");
  });
});

describe("OTP algorithm names", () => {
  it("accepts a lowercase algorithm name", async () => {
    expect(await hotp(RFC4226_SECRET, 0, { algorithm: "sha-1" as any })).toBe("755224");
    expect(
      await totp(RFC6238_SHA256_SECRET, { time: 59, digits: 8, algorithm: "sha-256" as any }),
    ).toBe("46119246");
  });

  it("rejects an unknown algorithm with a RangeError naming the function", async () => {
    await expect(hotp(RFC4226_SECRET, 0, { algorithm: "SHA-2" as any })).rejects.toThrow(
      'hotp: unsupported algorithm "SHA-2"; expected one of SHA-1, SHA-256, SHA-384, SHA-512.',
    );
    await expect(totp(RFC4226_SECRET, { algorithm: "SHA-2" as any })).rejects.toThrow(
      'totp: unsupported algorithm "SHA-2"',
    );
  });
});

describe("OTP input validation", () => {
  it("rejects a counter that is not a safe non-negative integer", async () => {
    await expect(hotp(RFC4226_SECRET, Number.NaN)).rejects.toThrow(
      "hotp: counter must be an integer >= 0, got NaN.",
    );
    await expect(hotp(RFC4226_SECRET, undefined as any)).rejects.toThrow(
      "hotp: counter must be an integer >= 0, got undefined.",
    );
    await expect(hotp(RFC4226_SECRET, Number.POSITIVE_INFINITY)).rejects.toBeInstanceOf(RangeError);
    await expect(hotp(RFC4226_SECRET, -1)).rejects.toBeInstanceOf(RangeError);
    await expect(hotp(RFC4226_SECRET, 1.5)).rejects.toBeInstanceOf(RangeError);
    await expect(hotp(RFC4226_SECRET, 2 ** 53)).rejects.toBeInstanceOf(RangeError);
  });

  it("rejects a missing counter in hotpVerify instead of verifying against 0", async () => {
    await expect(hotpVerify(RFC4226_SECRET, "755224", undefined as any)).rejects.toThrow(
      "hotpVerify: counter must be an integer >= 0, got undefined.",
    );
  });

  it("rejects digits outside the 6..8 range", async () => {
    await expect(hotp(RFC4226_SECRET, 0, { digits: 1.5 })).rejects.toThrow(
      "hotp: digits must be an integer between 6 and 8, got 1.5.",
    );
    await expect(hotp(RFC4226_SECRET, 0, { digits: -1 })).rejects.toBeInstanceOf(RangeError);
    await expect(hotp(RFC4226_SECRET, 0, { digits: 12 })).rejects.toBeInstanceOf(RangeError);
    await expect(totp(RFC4226_SECRET, { digits: 5 })).rejects.toThrow(
      "totp: digits must be an integer between 6 and 8, got 5.",
    );
    await expect(hotpVerify(RFC4226_SECRET, "755224", 0, { digits: 9 })).rejects.toBeInstanceOf(
      RangeError,
    );
    await expect(totpVerify(RFC4226_SECRET, "755224", { digits: 0 })).rejects.toBeInstanceOf(
      RangeError,
    );
  });

  it("rejects a period below 1", async () => {
    await expect(totp(RFC4226_SECRET, { period: 0 })).rejects.toThrow(
      "totp: period must be an integer >= 1, got 0.",
    );
    await expect(totp(RFC4226_SECRET, { period: -30 })).rejects.toBeInstanceOf(RangeError);
    await expect(totp(RFC4226_SECRET, { period: 2.5 })).rejects.toBeInstanceOf(RangeError);
    await expect(totpVerify(RFC4226_SECRET, "000000", { period: 0 })).rejects.toBeInstanceOf(
      RangeError,
    );
  });

  it("rejects a non-finite time", async () => {
    await expect(totp(RFC4226_SECRET, { time: Number.NaN })).rejects.toThrow(
      "totp: time must be a finite number of seconds, got NaN.",
    );
    await expect(totp(RFC4226_SECRET, { time: Number.POSITIVE_INFINITY })).rejects.toBeInstanceOf(
      RangeError,
    );
    await expect(totpVerify(RFC4226_SECRET, "000000", { time: Number.NaN })).rejects.toBeInstanceOf(
      RangeError,
    );
  });

  it("accepts a fractional time by flooring it", async () => {
    expect(await totp(RFC6238_SHA1_SECRET, { time: 59.9, digits: 8 })).toBe(
      await totp(RFC6238_SHA1_SECRET, { time: 59, digits: 8 }),
    );
  });

  it("rejects a negative window instead of never matching", async () => {
    await expect(hotpVerify(RFC4226_SECRET, "755224", 0, { window: -1 })).rejects.toThrow(
      "hotpVerify: window must be an integer >= 0, got -1.",
    );
    await expect(totpVerify(RFC4226_SECRET, "755224", { window: -1 })).rejects.toThrow(
      "totpVerify: window must be an integer >= 0, got -1.",
    );
  });

  it("rejects an empty secret", async () => {
    await expect(hotp("", 0)).rejects.toThrow("otp: secret must not be empty.");
    await expect(hotp(new Uint8Array(0), 0)).rejects.toBeInstanceOf(RangeError);
    await expect(totp("")).rejects.toThrow("otp: secret must not be empty.");
    await expect(hotpVerify("", "755224", 0)).rejects.toThrow("otp: secret must not be empty.");
    await expect(totpVerify("", "755224")).rejects.toThrow("otp: secret must not be empty.");
  });

  it("rejects a secret that is neither text nor bytes", async () => {
    await expect(hotp([1, 2, 3] as any, 0)).rejects.toThrow(
      "otp: expected a string, ArrayBuffer or ArrayBuffer view, got Array.",
    );
  });

  it("accepts every BytesSource shape as a secret", async () => {
    const buffer = RFC4226_SECRET.buffer as ArrayBuffer;
    expect(await hotp(buffer, 0)).toBe("755224");
    expect(await hotp(new DataView(buffer), 0)).toBe("755224");
  });

  it("treats a missing OTP as invalid rather than throwing", async () => {
    expect(await hotpVerify(RFC4226_SECRET, null, 0)).toEqual({ valid: false, delta: 0 });
    expect(await hotpVerify(RFC4226_SECRET, undefined, 0)).toEqual({ valid: false, delta: 0 });
    expect(await totpVerify(RFC4226_SECRET, null, { time: 59 })).toEqual({
      valid: false,
      delta: 0,
    });
  });

  it("rejects a generateOTPSecret length below 1", () => {
    expect(() => generateOTPSecret(0)).toThrow(
      "generateOTPSecret: length must be an integer >= 1, got 0.",
    );
    expect(() => generateOTPSecret(-1)).toThrow(RangeError);
    expect(() => generateOTPSecret(1.5)).toThrow(RangeError);
  });
});

describe("OTP boundary edges", () => {
  it("rejects a counter whose window would leave the safe-integer range", async () => {
    await expect(
      hotpVerify(RFC4226_SECRET, "000000", Number.MAX_SAFE_INTEGER, { window: 1 }),
    ).rejects.toThrow(
      `hotpVerify: counter must be an integer between 0 and ${Number.MAX_SAFE_INTEGER - 1}, got ${Number.MAX_SAFE_INTEGER}.`,
    );
    await expect(
      hotpVerify(RFC4226_SECRET, "000000", Number.MAX_SAFE_INTEGER - 1, { window: 1 }),
    ).resolves.toEqual({ valid: false, delta: 0 });
  });
});
