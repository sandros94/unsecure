import { describe, it, expect } from "vitest";
import {
  base32Decode,
  base32Encode,
  base64Decode,
  base64Encode,
  base64UrlDecode,
  base64UrlEncode,
  hexDecode,
  hexEncode,
} from "../src/utils.ts";

describe.concurrent("Utility Functions", () => {
  describe("Base32 Encoding/Decoding", () => {
    // RFC 4648 test vectors
    const vectors: Array<[string, string]> = [
      ["", ""],
      ["f", "MY======"],
      ["fo", "MZXQ===="],
      ["foo", "MZXW6==="],
      ["foob", "MZXW6YQ="],
      ["fooba", "MZXW6YTB"],
      ["foobar", "MZXW6YTBOI======"],
    ];

    describe("base32Encode(data)", () => {
      for (const [input, expected] of vectors) {
        it(`should encode "${input}" to "${expected}"`, () => {
          expect(base32Encode(input)).toBe(expected);
        });
      }

      it("should encode a Uint8Array to Base32", () => {
        const bytes = new TextEncoder().encode("foobar");
        expect(base32Encode(bytes)).toBe("MZXW6YTBOI======");
      });

      it("should handle empty string", () => {
        expect(base32Encode("")).toBe("");
      });

      it("should handle single byte values", () => {
        // 0x00 = AAAAAAAA
        expect(base32Encode(new Uint8Array([0]))).toBe("AA======");
        // 0xFF = 76======
        expect(base32Encode(new Uint8Array([255]))).toBe("74======");
      });
    });

    describe("base32Decode(data)", () => {
      for (const [expected, input] of vectors) {
        if (!input) continue; // skip empty → empty case, tested separately
        it(`should decode "${input}" to "${expected}"`, () => {
          const decoded = new TextDecoder().decode(base32Decode(input));
          expect(decoded).toBe(expected);
        });
      }

      it("should handle unpadded input", () => {
        const decoded = new TextDecoder().decode(base32Decode("MZXW6YTBOI"));
        expect(decoded).toBe("foobar");
      });

      it("should be case-insensitive", () => {
        const decoded = new TextDecoder().decode(base32Decode("mzxw6ytboi"));
        expect(decoded).toBe("foobar");
      });

      it("should handle mixed case", () => {
        const decoded = new TextDecoder().decode(base32Decode("MzXw6YtBoI"));
        expect(decoded).toBe("foobar");
      });

      it("should return empty Uint8Array for undefined", () => {
        expect(base32Decode(undefined)).toEqual(new Uint8Array(0));
      });

      it("should return empty Uint8Array for empty string", () => {
        expect(base32Decode("")).toEqual(new Uint8Array(0));
      });

      it("should skip whitespace and invalid characters", () => {
        const decoded = new TextDecoder().decode(base32Decode("MZXW 6YTB OI==\n===="));
        expect(decoded).toBe("foobar");
      });

      it("should roundtrip binary data through encode/decode", () => {
        const original = new Uint8Array([0, 1, 127, 128, 255]);
        const encoded = base32Encode(original);
        expect(base32Decode(encoded)).toEqual(original);
      });

      it("should roundtrip all single-byte values", () => {
        for (let i = 0; i < 256; i++) {
          const original = new Uint8Array([i]);
          const encoded = base32Encode(original);
          expect(base32Decode(encoded)).toEqual(original);
        }
      });
    });
  });

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

function b64Encode(data: string | Uint8Array): string {
  return Buffer.from(data).toString("base64");
}
