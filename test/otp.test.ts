import { describe, it, expect, vi } from "vitest";
import { hotp, hotpVerify, totp, totpVerify, generateOTPSecret, otpauthURI } from "../src/otp.ts";
import { base32Encode, base32Decode } from "../src/utils/index.ts";

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
      const b32 = base32Encode(RFC4226_SECRET);
      const code = await hotp(b32, 0);
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
      const b32 = base32Encode(RFC6238_SHA1_SECRET);
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
    const decoded = base32Decode(secret, { returnAs: "uint8array" });
    expect(decoded).toHaveLength(32);
  });

  it("should produce different values each call", () => {
    const a = generateOTPSecret();
    const b = generateOTPSecret();
    expect(a).not.toBe(b);
  });

  it("should roundtrip through base32 decode", () => {
    const secret = generateOTPSecret();
    const bytes = base32Decode(secret, { returnAs: "uint8array" });
    expect(bytes).toHaveLength(20);
  });
});

describe("otpauthURI()", () => {
  const secret = new TextEncoder().encode("12345678901234567890");
  const secretB32 = base32Encode(secret).replace(/=+$/, "");

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
