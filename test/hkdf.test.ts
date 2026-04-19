import { describe, it, expect } from "vitest";
import { hkdf } from "../src/hkdf.ts";
import { hexDecode, hexEncode, base64Encode, base64UrlEncode } from "../src/utils.ts";

// RFC 5869 Appendix A test vectors.
// Each vector's IKM / salt / info / expected OKM are given as hex strings.
const VECTORS = {
  // A.1 — Basic test case with SHA-256
  a1: {
    algorithm: "SHA-256" as const,
    ikm: "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
    salt: "000102030405060708090a0b0c",
    info: "f0f1f2f3f4f5f6f7f8f9",
    length: 42,
    okm:
      "3cb25f25faacd57a90434f64d0362f2a" +
      "2d2d0a90cf1a5a4c5db02d56ecc4c5bf" +
      "34007208d5b887185865",
  },
  // A.2 — SHA-256 with longer inputs / outputs
  a2: {
    algorithm: "SHA-256" as const,
    ikm:
      "000102030405060708090a0b0c0d0e0f" +
      "101112131415161718191a1b1c1d1e1f" +
      "202122232425262728292a2b2c2d2e2f" +
      "303132333435363738393a3b3c3d3e3f" +
      "404142434445464748494a4b4c4d4e4f",
    salt:
      "606162636465666768696a6b6c6d6e6f" +
      "707172737475767778797a7b7c7d7e7f" +
      "808182838485868788898a8b8c8d8e8f" +
      "909192939495969798999a9b9c9d9e9f" +
      "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf",
    info:
      "b0b1b2b3b4b5b6b7b8b9babbbcbdbebf" +
      "c0c1c2c3c4c5c6c7c8c9cacbcccdcecf" +
      "d0d1d2d3d4d5d6d7d8d9dadbdcdddedf" +
      "e0e1e2e3e4e5e6e7e8e9eaebecedeeef" +
      "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
    length: 82,
    okm:
      "b11e398dc80327a1c8e7f78c596a4934" +
      "4f012eda2d4efad8a050cc4c19afa97c" +
      "59045a99cac7827271cb41c65e590e09" +
      "da3275600c2f09b8367793a9aca3db71" +
      "cc30c58179ec3e87c14c01d5c1f3434f" +
      "1d87",
  },
  // A.3 — SHA-256 with zero-length salt and info
  a3: {
    algorithm: "SHA-256" as const,
    ikm: "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
    salt: "",
    info: "",
    length: 42,
    okm:
      "8da4e775a563c18f715f802a063c5a31" +
      "b8a11f5c5ee1879ec3454e5f3c738d2d" +
      "9d201395faa4b61a96c8",
  },
  // A.4 — SHA-1
  a4: {
    algorithm: "SHA-1" as const,
    ikm: "0b0b0b0b0b0b0b0b0b0b0b",
    salt: "000102030405060708090a0b0c",
    info: "f0f1f2f3f4f5f6f7f8f9",
    length: 42,
    okm:
      "085a01ea1b10f36933068b56efa5ad81" +
      "a4f14b822f5b091568a9cdd4f155fda2" +
      "c22e422478d305f3f896",
  },
};

describe.concurrent("hkdf (RFC 5869 vectors)", () => {
  for (const [name, v] of Object.entries(VECTORS)) {
    it(`matches vector ${name.toUpperCase()} (${v.algorithm}, L=${v.length})`, async () => {
      const out = await hkdf(hexDecode(v.ikm, { returnAs: "uint8array" }), {
        algorithm: v.algorithm,
        length: v.length,
        salt: hexDecode(v.salt, { returnAs: "uint8array" }),
        info: hexDecode(v.info, { returnAs: "uint8array" }),
      });
      expect(hexEncode(out)).toBe(v.okm);
    });
  }
});

describe("hkdf API", () => {
  const ikm = hexDecode(VECTORS.a1.ikm, { returnAs: "uint8array" });
  const salt = hexDecode(VECTORS.a1.salt, { returnAs: "uint8array" });
  const info = hexDecode(VECTORS.a1.info, { returnAs: "uint8array" });
  const expected = VECTORS.a1.okm;

  it("defaults to uint8array output", async () => {
    const out = await hkdf(ikm, { length: VECTORS.a1.length, salt, info });
    expect(out).toBeInstanceOf(Uint8Array);
    expect(hexEncode(out)).toBe(expected);
  });

  it("defaults to 32-byte length when length is omitted", async () => {
    const out = await hkdf(ikm, { salt, info });
    expect(out.length).toBe(32);
  });

  it("defaults to SHA-256 when algorithm is omitted", async () => {
    const explicit = await hkdf(ikm, { algorithm: "SHA-256", length: 16, salt, info });
    const implicit = await hkdf(ikm, { length: 16, salt, info });
    expect(hexEncode(implicit)).toBe(hexEncode(explicit));
  });

  it("accepts string ikm / salt / info via UTF-8 encoding", async () => {
    const stringRun = await hkdf("my-secret", {
      salt: "a-pinch-of-salt",
      info: "ctx",
    });
    const bytesRun = await hkdf(new TextEncoder().encode("my-secret"), {
      salt: new TextEncoder().encode("a-pinch-of-salt"),
      info: new TextEncoder().encode("ctx"),
    });
    expect(hexEncode(stringRun)).toBe(hexEncode(bytesRun));
  });

  it("treats omitted salt as empty (matches RFC 5869 A.3)", async () => {
    const ikm3 = hexDecode(VECTORS.a3.ikm, { returnAs: "uint8array" });
    const out = await hkdf(ikm3, { length: VECTORS.a3.length });
    expect(hexEncode(out)).toBe(VECTORS.a3.okm);
  });

  it("emits the same bytes regardless of returnAs encoding", async () => {
    const bytes = await hkdf(ikm, {
      length: VECTORS.a1.length,
      salt,
      info,
      returnAs: "uint8array",
    });
    const hex = await hkdf(ikm, { length: VECTORS.a1.length, salt, info, returnAs: "hex" });
    const b64 = await hkdf(ikm, { length: VECTORS.a1.length, salt, info, returnAs: "base64" });
    const b64url = await hkdf(ikm, {
      length: VECTORS.a1.length,
      salt,
      info,
      returnAs: "base64url",
    });
    expect(hex).toBe(hexEncode(bytes));
    expect(b64).toBe(base64Encode(bytes));
    expect(b64url).toBe(base64UrlEncode(bytes));
  });

  it("supports bytes alias and b64 / b64url aliases", async () => {
    const viaBytes = await hkdf(ikm, { length: 16, salt, info, returnAs: "bytes" });
    const viaUint8 = await hkdf(ikm, { length: 16, salt, info, returnAs: "uint8array" });
    expect(hexEncode(viaBytes)).toBe(hexEncode(viaUint8));

    const b64 = await hkdf(ikm, { length: 16, salt, info, returnAs: "b64" });
    const base64 = await hkdf(ikm, { length: 16, salt, info, returnAs: "base64" });
    expect(b64).toBe(base64);

    const b64u = await hkdf(ikm, { length: 16, salt, info, returnAs: "b64url" });
    const base64url = await hkdf(ikm, { length: 16, salt, info, returnAs: "base64url" });
    expect(b64u).toBe(base64url);
  });

  it("different info values produce independent keys (domain separation)", async () => {
    const encKey = await hkdf(ikm, { salt, info: "enc", returnAs: "hex" });
    const macKey = await hkdf(ikm, { salt, info: "mac", returnAs: "hex" });
    expect(encKey).not.toBe(macKey);
  });

  it("throws on non-positive or non-integer length", async () => {
    await expect(hkdf(ikm, { length: 0, salt })).rejects.toThrow(RangeError);
    await expect(hkdf(ikm, { length: -1, salt })).rejects.toThrow(RangeError);
    await expect(hkdf(ikm, { length: 2.5, salt })).rejects.toThrow(RangeError);
  });

  it("throws when length exceeds 255 * HashLen", async () => {
    // SHA-256: max 255 * 32 = 8160
    await expect(hkdf(ikm, { algorithm: "SHA-256", length: 8161, salt })).rejects.toThrow(
      /at most 8160/,
    );
    // SHA-1: max 255 * 20 = 5100
    await expect(hkdf(ikm, { algorithm: "SHA-1", length: 5101, salt })).rejects.toThrow(
      /at most 5100/,
    );
  });

  it("throws on unsupported returnAs", async () => {
    await expect(hkdf(ikm, { length: 16, returnAs: "unsupported" as any })).rejects.toThrow(
      'Unsupported hkdf "returnAs" option: unsupported',
    );
  });
});
