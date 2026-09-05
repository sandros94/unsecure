import { describe, it, expect } from "vitest";
import { hmac, hmacVerify } from "../src/hmac.ts";

describe("hmac", () => {
  const secret = "my-secret-key";
  const secretBytes = new TextEncoder().encode(secret);
  const message = "hello world";
  const messageBytes = new TextEncoder().encode(message);

  describe("hmac()", () => {
    it("should return a hex string by default for string data", async () => {
      const result = await hmac(secret, message);
      expect(result).toBeTypeOf("string");
      // SHA-256 HMAC produces 32 bytes = 64 hex chars
      expect(result.length).toBe(64);
    });

    it("should return a Uint8Array by default for BufferSource data", async () => {
      const result = await hmac(secret, messageBytes);
      expect(result).toBeInstanceOf(Uint8Array);
      expect(result.length).toBe(32); // SHA-256 = 32 bytes
    });

    it("should produce the same signature for string and Uint8Array data", async () => {
      const fromString = await hmac(secret, message);
      const fromBytes = await hmac(secret, messageBytes, { returnAs: "hex" });
      expect(fromString).toBe(fromBytes);
    });

    it("should produce the same signature for string and Uint8Array secret", async () => {
      const fromStringSecret = await hmac(secret, message);
      const fromBytesSecret = await hmac(secretBytes, message);
      expect(fromStringSecret).toBe(fromBytesSecret);
    });

    it("should return hex when returnAs is 'hex'", async () => {
      const result = await hmac(secret, message, { returnAs: "hex" });
      expect(result).toBeTypeOf("string");
      expect(result.length).toBe(64);
    });

    it("should return base64 when returnAs is 'base64'", async () => {
      const result = await hmac(secret, message, { returnAs: "base64" });
      expect(result).toBeTypeOf("string");
      // Base64 of 32 bytes = 44 chars (with padding)
      expect(result.length).toBe(44);
    });

    it("should return base64url when returnAs is 'base64url'", async () => {
      const result = await hmac(secret, message, { returnAs: "base64url" });
      expect(result).toBeTypeOf("string");
      // base64url omits padding, so length varies but should not contain +, /, =
      expect(result).not.toMatch(/[+/=]/);
    });

    it("should return Uint8Array when returnAs is 'uint8array'", async () => {
      const result = await hmac(secret, message, { returnAs: "uint8array" });
      expect(result).toBeInstanceOf(Uint8Array);
      expect(result.length).toBe(32);
    });

    it("should return Uint8Array when returnAs is 'bytes' alias", async () => {
      const result = await hmac(secret, message, { returnAs: "bytes" });
      expect(result).toBeInstanceOf(Uint8Array);
    });

    it("should return base64 when returnAs is 'b64' alias", async () => {
      const base64Result = await hmac(secret, message, { returnAs: "base64" });
      const b64Result = await hmac(secret, message, { returnAs: "b64" });
      expect(b64Result).toBe(base64Result);
    });

    it("should return base64url when returnAs is 'b64url' alias", async () => {
      const base64urlResult = await hmac(secret, message, { returnAs: "base64url" });
      const b64urlResult = await hmac(secret, message, { returnAs: "b64url" });
      expect(b64urlResult).toBe(base64urlResult);
    });

    it("should use SHA-256 by default", async () => {
      const defaultResult = await hmac(secret, message);
      const sha256Result = await hmac(secret, message, { algorithm: "SHA-256" });
      expect(defaultResult).toBe(sha256Result);
    });

    it("should support SHA-384", async () => {
      const result = await hmac(secret, message, { algorithm: "SHA-384" });
      expect(result).toBeTypeOf("string");
      // SHA-384 = 48 bytes = 96 hex chars
      expect(result.length).toBe(96);
    });

    it("should support SHA-512", async () => {
      const result = await hmac(secret, message, { algorithm: "SHA-512" });
      expect(result).toBeTypeOf("string");
      // SHA-512 = 64 bytes = 128 hex chars
      expect(result.length).toBe(128);
    });

    it("should produce different signatures for different messages", async () => {
      const sig1 = await hmac(secret, "message 1");
      const sig2 = await hmac(secret, "message 2");
      expect(sig1).not.toBe(sig2);
    });

    it("should produce different signatures for different secrets", async () => {
      const sig1 = await hmac("secret-1", message);
      const sig2 = await hmac("secret-2", message);
      expect(sig1).not.toBe(sig2);
    });

    it("should produce deterministic results", async () => {
      const sig1 = await hmac(secret, message);
      const sig2 = await hmac(secret, message);
      expect(sig1).toBe(sig2);
    });

    it("should handle empty message", async () => {
      const result = await hmac(secret, "");
      expect(result).toBeTypeOf("string");
      expect(result.length).toBe(64);
    });

    it("should override mirroring with explicit returnAs for buffer data", async () => {
      const result = await hmac(secret, messageBytes, { returnAs: "hex" });
      expect(result).toBeTypeOf("string");
    });

    it("should throw for unsupported returnAs", async () => {
      await expect(hmac(secret, message, { returnAs: "unsupported" as any })).rejects.toThrow(
        'Unsupported hmac "returnAs" option: unsupported',
      );
    });
  });

  describe("hmacVerify()", () => {
    it("should return true for a valid hex signature", async () => {
      const sig = await hmac(secret, message);
      const valid = await hmacVerify(secret, message, sig);
      expect(valid).toBe(true);
    });

    it("should return false for an invalid hex signature", async () => {
      const valid = await hmacVerify(secret, message, "0".repeat(64));
      expect(valid).toBe(false);
    });

    it("should return true for a valid Uint8Array signature", async () => {
      const sig = await hmac(secret, messageBytes);
      const valid = await hmacVerify(secret, messageBytes, sig);
      expect(valid).toBe(true);
    });

    it("should return false for an invalid Uint8Array signature", async () => {
      const valid = await hmacVerify(secret, messageBytes, new Uint8Array(32));
      expect(valid).toBe(false);
    });

    it("should verify base64 signatures when returnAs matches", async () => {
      const sig = await hmac(secret, message, { returnAs: "base64" });
      const valid = await hmacVerify(secret, message, sig, { returnAs: "base64" });
      expect(valid).toBe(true);
    });

    it("should verify base64url signatures when returnAs matches", async () => {
      const sig = await hmac(secret, message, { returnAs: "base64url" });
      const valid = await hmacVerify(secret, message, sig, { returnAs: "base64url" });
      expect(valid).toBe(true);
    });

    it("should fail when signature format does not match", async () => {
      const hexSig = await hmac(secret, message, { returnAs: "hex" });
      // Verify as base64 — format mismatch, should fail
      const valid = await hmacVerify(secret, message, hexSig, { returnAs: "base64" });
      expect(valid).toBe(false);
    });

    it("should verify with different algorithms", async () => {
      const sig = await hmac(secret, message, { algorithm: "SHA-512" });
      const valid = await hmacVerify(secret, message, sig, { algorithm: "SHA-512" });
      expect(valid).toBe(true);
    });

    it("should fail when algorithm does not match", async () => {
      const sig256 = await hmac(secret, message, { algorithm: "SHA-256" });
      const valid = await hmacVerify(secret, message, sig256, { algorithm: "SHA-512" });
      expect(valid).toBe(false);
    });

    it("should fail when message differs", async () => {
      const sig = await hmac(secret, "original");
      const valid = await hmacVerify(secret, "tampered", sig);
      expect(valid).toBe(false);
    });

    it("should fail when secret differs", async () => {
      const sig = await hmac("correct-secret", message);
      const valid = await hmacVerify("wrong-secret", message, sig);
      expect(valid).toBe(false);
    });

    it("should verify with Uint8Array secret", async () => {
      const sig = await hmac(secretBytes, message);
      const valid = await hmacVerify(secretBytes, message, sig);
      expect(valid).toBe(true);
    });

    it("should return ArrayBuffer-backed Uint8Array", async () => {
      const sig = await hmac(secret, message, { returnAs: "uint8array" });
      expect(sig.buffer).toBeInstanceOf(ArrayBuffer);
    });
  });
});

describe("hmac algorithm names", () => {
  it("accepts a lowercase algorithm name", async () => {
    const lower = await hmac("k", "d", { algorithm: "sha-512" as any });
    const canonical = await hmac("k", "d", { algorithm: "SHA-512" });
    expect(lower).toBe(canonical);
  });

  it("rejects an unknown algorithm with a RangeError", async () => {
    await expect(hmac("k", "d", { algorithm: "md5" as any })).rejects.toThrow(
      'hmac: unsupported algorithm "md5"; expected one of SHA-1, SHA-256, SHA-384, SHA-512.',
    );
  });

  it("rejects an unknown algorithm in hmacVerify too", async () => {
    await expect(hmacVerify("k", "d", "00", { algorithm: "md5" as any })).rejects.toBeInstanceOf(
      RangeError,
    );
  });
});

describe("hmac input contract", () => {
  const secret = "my-secret-key";
  const message = "hello world";
  const messageBytes = new TextEncoder().encode(message);

  it("rejects an empty secret before reaching Web Crypto", async () => {
    await expect(hmac("", message)).rejects.toThrow("hmac: secret must not be empty.");
    await expect(hmac("", message)).rejects.toBeInstanceOf(RangeError);
    await expect(hmac(new Uint8Array(0), message)).rejects.toThrow(
      "hmac: secret must not be empty.",
    );
    await expect(hmacVerify("", message, "00")).rejects.toThrow("hmac: secret must not be empty.");
  });

  it("accepts a SharedArrayBuffer-backed secret and data", async () => {
    const toShared = (bytes: Uint8Array) => {
      const view = new Uint8Array(new SharedArrayBuffer(bytes.byteLength));
      view.set(bytes);
      return view;
    };
    const secretBytes = new TextEncoder().encode(secret);
    const plain = await hmac(secretBytes, messageBytes, { returnAs: "hex" });

    expect(await hmac(toShared(secretBytes), messageBytes, { returnAs: "hex" })).toBe(plain);
    expect(await hmac(secretBytes, toShared(messageBytes), { returnAs: "hex" })).toBe(plain);
  });

  it("accepts an ArrayBuffer, a DataView and an offset view as data", async () => {
    const plain = await hmac(secret, messageBytes, { returnAs: "hex" });
    const padded = new Uint8Array(messageBytes.byteLength + 3);
    padded.set(messageBytes, 3);
    const offset = new Uint8Array(padded.buffer, 3, messageBytes.byteLength);

    expect(await hmac(secret, messageBytes.buffer as ArrayBuffer, { returnAs: "hex" })).toBe(plain);
    expect(
      await hmac(secret, new DataView(messageBytes.buffer as ArrayBuffer), { returnAs: "hex" }),
    ).toBe(plain);
    expect(await hmac(secret, offset, { returnAs: "hex" })).toBe(plain);
  });
});

describe("hmacVerify signature formats", () => {
  const secret = "my-secret-key";
  const message = "hello world";
  const messageBytes = new TextEncoder().encode(message);

  it("verifies a hex string signature against byte data", async () => {
    const sig = await hmac(secret, messageBytes, { returnAs: "hex" });
    expect(await hmacVerify(secret, messageBytes, sig)).toBe(true);
  });

  it("verifies an uppercase hex signature", async () => {
    const sig = await hmac(secret, message);
    expect(await hmacVerify(secret, message, sig.toUpperCase())).toBe(true);
  });

  it("decodes a string signature as hex when returnAs asks for bytes", async () => {
    const sig = await hmac(secret, message, { returnAs: "hex" });
    expect(await hmacVerify(secret, message, sig, { returnAs: "uint8array" })).toBe(true);
    expect(await hmacVerify(secret, message, sig, { returnAs: "bytes" })).toBe(true);
  });

  it("verifies base64 and base64url signatures under their aliases", async () => {
    const b64 = await hmac(secret, message, { returnAs: "base64" });
    const b64url = await hmac(secret, message, { returnAs: "base64url" });
    expect(await hmacVerify(secret, message, b64, { returnAs: "b64" })).toBe(true);
    expect(await hmacVerify(secret, message, b64url, { returnAs: "b64url" })).toBe(true);
  });

  it("returns false for a missing or malformed signature instead of throwing", async () => {
    expect(await hmacVerify(secret, message, null)).toBe(false);
    expect(await hmacVerify(secret, message, undefined)).toBe(false);
    expect(await hmacVerify(secret, message, "not-hex-at-all")).toBe(false);
    expect(await hmacVerify(secret, message, "zz", { returnAs: "base64" })).toBe(false);
    expect(await hmacVerify(secret, message, 12_345 as any)).toBe(false);
  });

  it("treats a signature that only inherits Uint8Array.prototype as a mismatch", async () => {
    const fake = Object.create(Uint8Array.prototype) as Uint8Array;
    expect(await hmacVerify(secret, message, fake)).toBe(false);
  });

  it("verifies a raw byte signature whatever returnAs says", async () => {
    const sig = await hmac(secret, message, { returnAs: "uint8array" });
    expect(await hmacVerify(secret, message, sig, { returnAs: "base64" })).toBe(true);
    expect(await hmacVerify(secret, message, sig.buffer as ArrayBuffer)).toBe(true);
  });
});
