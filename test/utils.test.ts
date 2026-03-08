import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import {
  base64Decode,
  base64Encode,
  base64UrlDecode,
  base64UrlEncode,
  hexDecode,
  hexEncode,
  randomJitter,
} from "../src/utils.ts";

describe.concurrent("Utility Functions", () => {
  describe("Base64 Encoding/Decoding", () => {
    const testString =
      "Hello, Vitest! 👋 This is a test string with some special characters: Ā 𐀀 文 +/=";
    const testUint8Array = new TextEncoder().encode(testString);

    describe("base64Encode(data)", () => {
      it("should encode a string to standard Base64", () => {
        const encoded = base64Encode(testString);
        expect(encoded).toBe(b64Encode(testString));
      });

      it("should encode a Uint8Array to standard Base64", () => {
        const encoded = base64Encode(testUint8Array);
        expect(encoded).toBe(b64Encode(testUint8Array));
      });

      it("should handle empty string", () => {
        expect(base64Encode("")).toBe("");
      });
    });

    describe("base64UrlEncode(data)", () => {
      it("should encode a string to Base64 URL-safe", () => {
        const encoded = base64UrlEncode(testString);
        const expected = b64Encode(testString)
          .replace(/\+/g, "-")
          .replace(/\//g, "_")
          .replace(/=/g, "");
        expect(encoded).toBe(expected);
      });

      it("should encode a Uint8Array to Base64 URL-safe", () => {
        const encoded = base64UrlEncode(testUint8Array);
        const expected = b64Encode(testUint8Array)
          .replace(/\+/g, "-")
          .replace(/\//g, "_")
          .replace(/=/g, "");
        expect(encoded).toBe(expected);
      });

      it("should handle empty string", () => {
        expect(base64UrlEncode("")).toBe("");
      });
    });

    describe("base64Decode(data, options)", () => {
      const encodedString = b64Encode(testString);
      const encodedUint8Array = new TextEncoder().encode(encodedString);

      it("should decode a Base64 string to string by default", () => {
        const decoded = base64Decode(encodedString);
        expect(decoded).toBe(testString);
      });

      it("should decode a Base64 string to string with returnAs 'string'", () => {
        const decoded = base64Decode(encodedString, { returnAs: "string" });
        expect(decoded).toBe(testString);
      });

      it("should decode a Base64 string to Uint8Array with returnAs 'uint8array'", () => {
        const decoded = base64Decode(encodedString, { returnAs: "uint8array" });
        expect(decoded).toEqual(testUint8Array);
      });

      it("should decode a Base64 string to Uint8Array with returnAs 'bytes' alias", () => {
        const decoded = base64Decode(encodedString, { returnAs: "bytes" });
        expect(decoded).toEqual(testUint8Array);
      });

      it("should mirror input type: Uint8Array in → Uint8Array out", () => {
        const decoded = base64Decode(encodedUint8Array);
        expect(decoded).toBeInstanceOf(Uint8Array);
        expect(decoded).toEqual(testUint8Array);
      });

      it("should override mirroring with explicit returnAs", () => {
        const decoded = base64Decode(encodedUint8Array, { returnAs: "string" });
        expect(decoded).toBe(testString);
      });

      it("should handle empty string input", () => {
        expect(base64Decode("")).toBe("");
        expect(base64Decode("", { returnAs: "uint8array" })).toEqual(new Uint8Array(0));
      });

      it("should handle undefined input", () => {
        expect(base64Decode(undefined)).toBe("");
      });
    });

    describe("base64UrlDecode(data, options)", () => {
      const originalBase64 = b64Encode(testString);
      const encodedUrlSafeString = originalBase64
        .replace(/\+/g, "-")
        .replace(/\//g, "_")
        .replace(/=/g, "");
      const encodedUrlSafeUint8Array = new TextEncoder().encode(encodedUrlSafeString);

      it("should decode a Base64 URL-safe string to string by default", () => {
        const decoded = base64UrlDecode(encodedUrlSafeString);
        expect(decoded).toBe(testString);
      });

      it("should decode a Base64 URL-safe string to string with returnAs 'string'", () => {
        const decoded = base64UrlDecode(encodedUrlSafeString, { returnAs: "string" });
        expect(decoded).toBe(testString);
      });

      it("should decode a Base64 URL-safe string to Uint8Array with returnAs 'uint8array'", () => {
        const decoded = base64UrlDecode(encodedUrlSafeString, { returnAs: "uint8array" });
        expect(decoded).toEqual(testUint8Array);
      });

      it("should decode a Base64 URL-safe string to Uint8Array with returnAs 'bytes' alias", () => {
        const decoded = base64UrlDecode(encodedUrlSafeString, { returnAs: "bytes" });
        expect(decoded).toEqual(testUint8Array);
      });

      it("should mirror input type: Uint8Array in → Uint8Array out", () => {
        const decoded = base64UrlDecode(encodedUrlSafeUint8Array);
        expect(decoded).toBeInstanceOf(Uint8Array);
        expect(decoded).toEqual(testUint8Array);
      });

      it("should override mirroring with explicit returnAs", () => {
        const decoded = base64UrlDecode(encodedUrlSafeUint8Array, { returnAs: "string" });
        expect(decoded).toBe(testString);
      });

      it("should handle empty string input", () => {
        expect(base64UrlDecode("")).toBe("");
        expect(base64UrlDecode("", { returnAs: "uint8array" })).toEqual(new Uint8Array(0));
      });

      it("should handle undefined input", () => {
        expect(base64UrlDecode(undefined)).toBe("");
      });

      it("should correctly pad and decode URL-safe strings without padding", () => {
        expect(base64UrlDecode("")).toBe("");
        expect(base64UrlDecode("Zg")).toBe("f");
        expect(base64UrlDecode("Zm8")).toBe("fo");
        expect(base64UrlDecode("Zm9v")).toBe("foo");
        expect(base64UrlDecode("Zm9vYg")).toBe("foob");
        expect(base64UrlDecode("Zm9vYmE")).toBe("fooba");
        expect(base64UrlDecode("Zm9vYmFy")).toBe("foobar");
      });
    });
  });

  describe("Hex Encoding/Decoding", () => {
    const testString =
      "Hello, Vitest! 👋 This is a test string with some special characters: Ā 𐀀 文 +/=";
    const testUint8Array = new TextEncoder().encode(testString);
    const expectedHex = [...testUint8Array].map((x) => x.toString(16).padStart(2, "0")).join("");

    describe("hexEncode(data)", () => {
      it("should encode a string to hex", () => {
        const encoded = hexEncode(testString);
        expect(encoded).toBe(expectedHex);
      });

      it("should encode a Uint8Array to hex", () => {
        const encoded = hexEncode(testUint8Array);
        expect(encoded).toBe(expectedHex);
      });

      it("should handle empty string", () => {
        expect(hexEncode("")).toBe("");
      });
    });

    describe("hexDecode(data, options)", () => {
      const encodedHexUint8Array = new TextEncoder().encode(expectedHex);

      it("should decode a hex string to string by default", () => {
        const decoded = hexDecode(expectedHex);
        expect(decoded).toBe(testString);
      });

      it("should decode a hex string to string with returnAs 'string'", () => {
        const decoded = hexDecode(expectedHex, { returnAs: "string" });
        expect(decoded).toBe(testString);
      });

      it("should decode a hex string to Uint8Array with returnAs 'uint8array'", () => {
        const decoded = hexDecode(expectedHex, { returnAs: "uint8array" });
        expect(decoded).toEqual(testUint8Array);
      });

      it("should decode a hex string to Uint8Array with returnAs 'bytes' alias", () => {
        const decoded = hexDecode(expectedHex, { returnAs: "bytes" });
        expect(decoded).toEqual(testUint8Array);
      });

      it("should mirror input type: Uint8Array in → Uint8Array out", () => {
        const decoded = hexDecode(encodedHexUint8Array);
        expect(decoded).toBeInstanceOf(Uint8Array);
        expect(decoded).toEqual(testUint8Array);
      });

      it("should override mirroring with explicit returnAs", () => {
        const decoded = hexDecode(encodedHexUint8Array, { returnAs: "string" });
        expect(decoded).toBe(testString);
      });

      it("should handle empty string input", () => {
        expect(hexDecode("")).toBe("");
        expect(hexDecode("", { returnAs: "uint8array" })).toEqual(new Uint8Array(0));
      });

      it("should handle undefined input", () => {
        expect(hexDecode(undefined)).toBe("");
      });

      it("should decode hex strings with mixed case characters", () => {
        const mixedCaseHex = "48656c6c6f"; // "Hello"
        const expected = "Hello";
        expect(hexDecode(mixedCaseHex)).toBe(expected);
        expect(hexDecode(mixedCaseHex.toUpperCase())).toBe(expected);
      });

      it("should handle odd length hex strings gracefully", () => {
        // Only complete byte pairs are decoded; trailing nibble is ignored.
        const decoded = hexDecode("abc", { returnAs: "uint8array" });
        expect(decoded).toEqual(Uint8Array.from([0xab]));
      });

      it("should handle invalid hex characters gracefully", () => {
        // Invalid hex characters result in an empty buffer.
        const decoded = hexDecode("zz", { returnAs: "uint8array" });
        expect(decoded).toEqual(new Uint8Array(0));
      });
    });
  });
});

describe("randomJitter", () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });
  afterEach(() => {
    vi.useRealTimers();
  });

  it("should resolve after a random delay within default range", async () => {
    const spy = vi.spyOn(crypto, "getRandomValues").mockImplementation((arr) => {
      (arr as Uint32Array)[0] = 42;
      return arr;
    });

    const promise = randomJitter();
    // 42 % 100 = 42ms
    vi.advanceTimersByTime(41);
    await expect(Promise.race([promise, Promise.resolve("pending")])).resolves.toBe("pending");
    vi.advanceTimersByTime(1);
    await expect(promise).resolves.toBeUndefined();

    spy.mockRestore();
  });

  it("should respect custom maxMs", async () => {
    const spy = vi.spyOn(crypto, "getRandomValues").mockImplementation((arr) => {
      (arr as Uint32Array)[0] = 250;
      return arr;
    });

    const promise = randomJitter(50);
    // 250 % 50 = 0ms
    vi.advanceTimersByTime(0);
    await expect(promise).resolves.toBeUndefined();

    spy.mockRestore();
  });

  it("should handle maxMs of 1 (always 0ms delay)", async () => {
    const promise = randomJitter(1);
    vi.advanceTimersByTime(0);
    await expect(promise).resolves.toBeUndefined();
  });

  it("should respect minMs and maxMs range", async () => {
    const spy = vi.spyOn(crypto, "getRandomValues").mockImplementation((arr) => {
      (arr as Uint32Array)[0] = 7;
      return arr;
    });

    const promise = randomJitter(50, 100);
    // min=50, range=50, 7 % 50 = 7, delay = 50 + 7 = 57ms
    vi.advanceTimersByTime(56);
    await expect(Promise.race([promise, Promise.resolve("pending")])).resolves.toBe("pending");
    vi.advanceTimersByTime(1);
    await expect(promise).resolves.toBeUndefined();

    spy.mockRestore();
  });

  it("should resolve with minMs delay when range is 1", async () => {
    const promise = randomJitter(30, 31);
    // range=1, any value % 1 = 0, delay = 30 + 0 = 30ms
    vi.advanceTimersByTime(29);
    await expect(Promise.race([promise, Promise.resolve("pending")])).resolves.toBe("pending");
    vi.advanceTimersByTime(1);
    await expect(promise).resolves.toBeUndefined();
  });
});

function b64Encode(data: string | Uint8Array): string {
  return Buffer.from(data).toString("base64");
}
