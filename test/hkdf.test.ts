import { describe, it, expect, afterEach, vi } from "vitest";
import { hkdf, importHkdfKey } from "../src/hkdf.ts";
import { hexParse, hexStringify, base64Stringify } from "../src/utils/index.ts";
import { expectUnsecureError } from "./_helpers.ts";

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
      const out = await hkdf(hexParse(v.ikm, { loose: true, returnAs: "uint8array" }), {
        algorithm: v.algorithm,
        length: v.length,
        salt: hexParse(v.salt, { loose: true, returnAs: "uint8array" }),
        info: hexParse(v.info, { loose: true, returnAs: "uint8array" }),
      });
      expect(hexStringify(out)).toBe(v.okm);
    });
  }
});

describe("hkdf API", () => {
  const ikm = hexParse(VECTORS.a1.ikm, { loose: true, returnAs: "uint8array" });
  const salt = hexParse(VECTORS.a1.salt, { loose: true, returnAs: "uint8array" });
  const info = hexParse(VECTORS.a1.info, { loose: true, returnAs: "uint8array" });
  const expected = VECTORS.a1.okm;

  it("defaults to uint8array output", async () => {
    const out = await hkdf(ikm, { length: VECTORS.a1.length, salt, info });
    expect(out).toBeInstanceOf(Uint8Array);
    expect(hexStringify(out)).toBe(expected);
  });

  it("defaults to 32-byte length when length is omitted", async () => {
    const out = await hkdf(ikm, { salt, info });
    expect(out.length).toBe(32);
  });

  it("defaults to SHA-256 when algorithm is omitted", async () => {
    const explicit = await hkdf(ikm, { algorithm: "SHA-256", length: 16, salt, info });
    const implicit = await hkdf(ikm, { length: 16, salt, info });
    expect(hexStringify(implicit)).toBe(hexStringify(explicit));
  });

  it("accepts string ikm / salt / info via UTF-8 encoding", async () => {
    const stringRun = await hkdf("my-secret", {
      salt: "a-pinch-of-salt",
      info: "ctx",
      returnAs: "uint8array",
    });
    const bytesRun = await hkdf(new TextEncoder().encode("my-secret"), {
      salt: new TextEncoder().encode("a-pinch-of-salt"),
      info: new TextEncoder().encode("ctx"),
    });
    expect(hexStringify(stringRun)).toBe(hexStringify(bytesRun));
  });

  it("mirrors string ikm -> hex output when returnAs is omitted", async () => {
    const hexOut = await hkdf("my-secret", { salt: "a-pinch-of-salt", info: "ctx" });
    const bytesOut = await hkdf(new TextEncoder().encode("my-secret"), {
      salt: "a-pinch-of-salt",
      info: "ctx",
    });
    expect(typeof hexOut).toBe("string");
    expect(hexOut).toBe(hexStringify(bytesOut));
  });

  it("treats omitted salt as empty (matches RFC 5869 A.3)", async () => {
    const ikm3 = hexParse(VECTORS.a3.ikm, { loose: true, returnAs: "uint8array" });
    const out = await hkdf(ikm3, { length: VECTORS.a3.length });
    expect(hexStringify(out)).toBe(VECTORS.a3.okm);
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
    expect(hex).toBe(hexStringify(bytes));
    expect(b64).toBe(base64Stringify(bytes));
    expect(b64url).toBe(base64Stringify(bytes, { alphabet: "base64url" }));
  });

  it("supports bytes alias and b64 / b64url aliases", async () => {
    const viaBytes = await hkdf(ikm, { length: 16, salt, info, returnAs: "bytes" });
    const viaUint8 = await hkdf(ikm, { length: 16, salt, info, returnAs: "uint8array" });
    expect(hexStringify(viaBytes)).toBe(hexStringify(viaUint8));

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
    await expectUnsecureError(hkdf(ikm, { length: 0, salt }), "OUT_OF_RANGE");
    await expect(hkdf(ikm, { length: 0, salt })).rejects.toThrow(
      "hkdf: length must be an integer between 1 and 8160, got 0.",
    );
    await expectUnsecureError(hkdf(ikm, { length: -1, salt }), "OUT_OF_RANGE");
    await expect(hkdf(ikm, { length: 2.5, salt })).rejects.toThrow(
      "hkdf: length must be an integer between 1 and 8160, got 2.5.",
    );
  });

  it("throws when length exceeds 255 * HashLen", async () => {
    // SHA-256: max 255 * 32 = 8160
    await expect(hkdf(ikm, { algorithm: "SHA-256", length: 8161, salt })).rejects.toThrow(
      "hkdf: length must be an integer between 1 and 8160, got 8161.",
    );
    // SHA-1: max 255 * 20 = 5100
    await expect(hkdf(ikm, { algorithm: "SHA-1", length: 5101, salt })).rejects.toThrow(
      "hkdf: length must be an integer between 1 and 5100, got 5101.",
    );
  });

  it("throws on unsupported returnAs", async () => {
    await expect(hkdf(ikm, { length: 16, returnAs: "unsupported" as any })).rejects.toThrow(
      'Unsupported hkdf "returnAs" option: unsupported',
    );
    await expectUnsecureError(
      hkdf(ikm, { length: 16, returnAs: "unsupported" as any }),
      "UNSUPPORTED",
    );
  });

  it("returns ArrayBuffer-backed Uint8Array", async () => {
    const out = await hkdf(ikm, { length: 16, salt, info, returnAs: "uint8array" });
    expect(out.buffer).toBeInstanceOf(ArrayBuffer);
  });
});

describe("hkdf algorithm names", () => {
  const ikm = hexParse(VECTORS.a1.ikm, { loose: true, returnAs: "uint8array" });

  it("accepts a lowercase algorithm name", async () => {
    const lower = await hkdf(ikm, { algorithm: "sha-256" as any, length: 16, returnAs: "hex" });
    const canonical = await hkdf(ikm, { algorithm: "SHA-256", length: 16, returnAs: "hex" });
    expect(lower).toBe(canonical);
  });

  it("enforces 255 * HashLen for a lowercase algorithm name", async () => {
    await expect(hkdf(ikm, { algorithm: "sha-256" as any, length: 9000 })).rejects.toThrow(
      "hkdf: length must be an integer between 1 and 8160, got 9000.",
    );
  });

  it("rejects an unknown algorithm as UNSUPPORTED", async () => {
    await expect(hkdf(ikm, { algorithm: "SHA-224" as any, length: 16 })).rejects.toThrow(
      'hkdf: unsupported algorithm "SHA-224"; expected one of SHA-1, SHA-256, SHA-384, SHA-512.',
    );
    await expectUnsecureError(
      hkdf(ikm, { algorithm: "SHA-224" as any, length: 16 }),
      "UNSUPPORTED",
    );
  });
});

describe("hkdf input contract", () => {
  const ikm = hexParse(VECTORS.a1.ikm, { loose: true, returnAs: "uint8array" });
  const salt = hexParse(VECTORS.a1.salt, { loose: true, returnAs: "uint8array" });
  const info = hexParse(VECTORS.a1.info, { loose: true, returnAs: "uint8array" });

  const toShared = (bytes: Uint8Array) => {
    const view = new Uint8Array(new SharedArrayBuffer(bytes.byteLength));
    view.set(bytes);
    return view;
  };

  it("derives the same bytes from SharedArrayBuffer-backed ikm, salt and info", async () => {
    const expected = VECTORS.a1.okm;
    const length = VECTORS.a1.length;
    expect(
      hexStringify(await hkdf(toShared(ikm), { length, salt, info, returnAs: "uint8array" })),
    ).toBe(expected);
    expect(
      hexStringify(await hkdf(ikm, { length, salt: toShared(salt), info, returnAs: "uint8array" })),
    ).toBe(expected);
    expect(
      hexStringify(await hkdf(ikm, { length, salt, info: toShared(info), returnAs: "uint8array" })),
    ).toBe(expected);
  });

  it("rejects ikm that is neither text nor bytes", async () => {
    await expect(hkdf([1, 2, 3] as any, { length: 16 })).rejects.toThrow(
      "hkdf: expected a string, ArrayBuffer or ArrayBuffer view, got Array.",
    );
  });
});

describe("hkdf web crypto failures", () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("reports a refused importKey as PLATFORM, carrying the platform error", async () => {
    const refusal = new DOMException("key import refused", "NotSupportedError");
    vi.spyOn(crypto.subtle, "importKey").mockRejectedValue(refusal);
    const error = await expectUnsecureError(
      hkdf("ikm", { length: 16 }),
      "PLATFORM",
      "hkdf: the runtime's Web Crypto refused importKey.",
    );
    expect(error.cause).toBe(refusal);
  });

  it("reports a refused deriveBits as PLATFORM, carrying the platform error", async () => {
    const refusal = new DOMException("derive refused", "OperationError");
    vi.spyOn(crypto.subtle, "deriveBits").mockRejectedValue(refusal);
    const error = await expectUnsecureError(
      hkdf("ikm", { length: 16 }),
      "PLATFORM",
      "hkdf: the runtime's Web Crypto refused deriveBits.",
    );
    expect(error.cause).toBe(refusal);
  });
});

describe("hkdf CryptoKey ikm", () => {
  const ikm = hexParse(VECTORS.a1.ikm, { loose: true, returnAs: "uint8array" });
  const salt = hexParse(VECTORS.a1.salt, { loose: true, returnAs: "uint8array" });
  const info = hexParse(VECTORS.a1.info, { loose: true, returnAs: "uint8array" });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("imports a non-extractable HKDF deriveBits key", async () => {
    const key = await importHkdfKey(ikm);
    expect(key).toBeInstanceOf(CryptoKey);
    expect(key.extractable).toBe(false);
    expect(key.usages).toEqual(["deriveBits"]);
    expect(key.algorithm.name).toBe("HKDF");
  });

  it("derives identically to the bytes path, for every algorithm", async () => {
    for (const [, v] of Object.entries(VECTORS)) {
      const bytes = hexParse(v.ikm, { loose: true, returnAs: "uint8array" });
      const options = {
        algorithm: v.algorithm,
        length: v.length,
        salt: hexParse(v.salt, { loose: true, returnAs: "uint8array" }),
        info: hexParse(v.info, { loose: true, returnAs: "uint8array" }),
      } as const;
      const fromKey = await hkdf(await importHkdfKey(bytes), options);
      expect(hexStringify(fromKey)).toBe(v.okm);
    }
  });

  it("accepts text as well as bytes", async () => {
    const key = await importHkdfKey("shared-secret-string");
    expect(await hkdf(key, { salt, info, returnAs: "hex" })).toBe(
      await hkdf("shared-secret-string", { salt, info }),
    );
  });

  it("rejects an ikm that is neither text nor bytes", async () => {
    await expectUnsecureError(importHkdfKey(42 as any), "INVALID_TYPE");
  });

  it("imports nothing when it is handed a key", async () => {
    const key = await importHkdfKey(ikm);
    const importKey = vi.spyOn(crypto.subtle, "importKey");
    const deriveBits = vi.spyOn(crypto.subtle, "deriveBits");
    await hkdf(key, { salt, info });
    expect(importKey).not.toHaveBeenCalled();
    expect(deriveBits).toHaveBeenCalledTimes(1);
  });

  it("refuses a key of another algorithm, naming what it was given", async () => {
    const key = await crypto.subtle.importKey(
      "raw",
      ikm,
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign"],
    );
    const error = await expectUnsecureError(hkdf(key, { salt, info }), "OUT_OF_RANGE");
    expect(error.message).toContain('hkdf: key must be an HKDF key with the "deriveBits" usage');
    expect(error.message).toContain("HMAC");
    expect(error.message).toContain("sign");
  });

  it("still range-checks length before it looks at the key", async () => {
    const key = await importHkdfKey(ikm);
    await expectUnsecureError(hkdf(key, { length: 0 }), "OUT_OF_RANGE", "hkdf: length");
  });

  it("defaults returnAs to bytes, as for any non-string ikm", async () => {
    const key = await importHkdfKey(ikm);
    expect(await hkdf(key, { salt, info })).toBeInstanceOf(Uint8Array);
  });
});
