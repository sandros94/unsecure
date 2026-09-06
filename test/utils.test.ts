import { describe, it, expect } from "vitest";
import { expectUnsecureError } from "./_helpers.ts";
import {
  base32Parse,
  base32Stringify,
  base64Parse,
  base64Stringify,
  hexParse,
  hexStringify,
} from "../src/utils/index.ts";

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

    describe("base32Stringify(data)", () => {
      for (const [input, expected] of vectors) {
        it(`should encode "${input}" to "${expected}"`, () => {
          expect(base32Stringify(input)).toBe(expected);
        });
      }

      it("should encode a Uint8Array to Base32", () => {
        const bytes = new TextEncoder().encode("foobar");
        expect(base32Stringify(bytes)).toBe("MZXW6YTBOI======");
      });

      it("should handle empty string", () => {
        expect(base32Stringify("")).toBe("");
      });

      it("should throw INVALID_TYPE on null or undefined", () => {
        expectUnsecureError(() => base32Stringify(undefined as any), "INVALID_TYPE");
        expectUnsecureError(() => base32Stringify(null as any), "INVALID_TYPE");
      });

      it("should handle single byte values", () => {
        // 0x00 = AAAAAAAA
        expect(base32Stringify(new Uint8Array([0]))).toBe("AA======");
        // 0xFF = 76======
        expect(base32Stringify(new Uint8Array([255]))).toBe("74======");
      });
    });

    describe("base32Parse(data, options)", () => {
      for (const [expected, input] of vectors) {
        if (!input) continue; // skip empty → empty case, tested separately
        it(`should decode "${input}" to "${expected}" (default: string)`, () => {
          expect(base32Parse(input, { loose: true })).toBe(expected);
        });
      }

      it("should decode to string by default (string input mirrors)", () => {
        expect(base32Parse("MZXW6YTBOI", { loose: true })).toBe("foobar");
      });

      it("should decode to Uint8Array with returnAs 'uint8array'", () => {
        const decoded = base32Parse("MZXW6YTBOI", { loose: true, returnAs: "uint8array" });
        expect(decoded).toEqual(new TextEncoder().encode("foobar"));
      });

      it("should decode to Uint8Array with returnAs 'bytes' alias", () => {
        const decoded = base32Parse("MZXW6YTBOI", { loose: true, returnAs: "bytes" });
        expect(decoded).toEqual(new TextEncoder().encode("foobar"));
      });

      it("should mirror input type: Uint8Array in → Uint8Array out", () => {
        const encodedBytes = new TextEncoder().encode("MZXW6YTBOI");
        const decoded = base32Parse(encodedBytes, { loose: true });
        expect(decoded).toBeInstanceOf(Uint8Array);
        expect(decoded).toEqual(new TextEncoder().encode("foobar"));
      });

      it("should override mirroring with explicit returnAs", () => {
        const encodedBytes = new TextEncoder().encode("MZXW6YTBOI");
        expect(base32Parse(encodedBytes, { loose: true, returnAs: "string" })).toBe("foobar");
      });

      it("should handle unpadded input", () => {
        expect(base32Parse("MZXW6YTBOI", { loose: true })).toBe("foobar");
      });

      it("should be case-insensitive", () => {
        expect(base32Parse("mzxw6ytboi", { loose: true })).toBe("foobar");
      });

      it("should handle mixed case", () => {
        expect(base32Parse("MzXw6YtBoI", { loose: true })).toBe("foobar");
      });

      it("should throw INVALID_TYPE on null or undefined", () => {
        expectUnsecureError(() => base32Parse(undefined as any, { loose: true }), "INVALID_TYPE");
        expectUnsecureError(() => base32Parse(null as any, { loose: true }), "INVALID_TYPE");
        expectUnsecureError(
          () => base32Parse(undefined as any, { loose: true, returnAs: "uint8array" }),
          "INVALID_TYPE",
        );
      });

      it("should handle empty string input", () => {
        expect(base32Parse("", { loose: true })).toBe("");
        expect(base32Parse("", { loose: true, returnAs: "uint8array" })).toEqual(new Uint8Array(0));
      });

      it("should skip whitespace and invalid characters", () => {
        expect(base32Parse("MZXW 6YTB OI==\n====", { loose: true })).toBe("foobar");
      });

      it("should roundtrip binary data through encode/decode", () => {
        const original = new Uint8Array([0, 1, 127, 128, 255]);
        const encoded = base32Stringify(original);
        expect(base32Parse(encoded, { loose: true, returnAs: "uint8array" })).toEqual(original);
      });

      it("should roundtrip all single-byte values", () => {
        for (let i = 0; i < 256; i++) {
          const original = new Uint8Array([i]);
          const encoded = base32Stringify(original);
          expect(base32Parse(encoded, { loose: true, returnAs: "uint8array" })).toEqual(original);
        }
      });
    });
  });

  describe("Base64 Encoding/Decoding", () => {
    const testString =
      "Hello, Vitest! 👋 This is a test string with some special characters: Ā 𐀀 文 +/=";
    const testUint8Array = new TextEncoder().encode(testString);

    describe("base64Stringify(data)", () => {
      it("should encode a string to standard Base64", () => {
        const encoded = base64Stringify(testString);
        expect(encoded).toBe(b64Encode(testString));
      });

      it("should encode a Uint8Array to standard Base64", () => {
        const encoded = base64Stringify(testUint8Array);
        expect(encoded).toBe(b64Encode(testUint8Array));
      });

      it("should handle empty string", () => {
        expect(base64Stringify("")).toBe("");
      });

      it("should throw INVALID_TYPE on null or undefined", () => {
        expectUnsecureError(() => base64Stringify(undefined as any), "INVALID_TYPE");
        expectUnsecureError(() => base64Stringify(null as any), "INVALID_TYPE");
      });
    });

    describe("base64Stringify(data, base64url)", () => {
      it("should encode a string to Base64 URL-safe", () => {
        const encoded = base64Stringify(testString, { alphabet: "base64url" });
        const expected = b64Encode(testString)
          .replace(/\+/g, "-")
          .replace(/\//g, "_")
          .replace(/=/g, "");
        expect(encoded).toBe(expected);
      });

      it("should encode a Uint8Array to Base64 URL-safe", () => {
        const encoded = base64Stringify(testUint8Array, { alphabet: "base64url" });
        const expected = b64Encode(testUint8Array)
          .replace(/\+/g, "-")
          .replace(/\//g, "_")
          .replace(/=/g, "");
        expect(encoded).toBe(expected);
      });

      it("should handle empty string", () => {
        expect(base64Stringify("", { alphabet: "base64url" })).toBe("");
      });

      it("should throw INVALID_TYPE on null or undefined", () => {
        expectUnsecureError(
          () => base64Stringify(undefined as any, { alphabet: "base64url" }),
          "INVALID_TYPE",
        );
        expectUnsecureError(
          () => base64Stringify(null as any, { alphabet: "base64url" }),
          "INVALID_TYPE",
        );
      });
    });

    describe("base64Parse(data, options)", () => {
      const encodedString = b64Encode(testString);
      const encodedUint8Array = new TextEncoder().encode(encodedString);

      it("should decode a Base64 string to string by default", () => {
        const decoded = base64Parse(encodedString, { loose: true });
        expect(decoded).toBe(testString);
      });

      it("should decode a Base64 string to string with returnAs 'string'", () => {
        const decoded = base64Parse(encodedString, { loose: true, returnAs: "string" });
        expect(decoded).toBe(testString);
      });

      it("should decode a Base64 string to Uint8Array with returnAs 'uint8array'", () => {
        const decoded = base64Parse(encodedString, { loose: true, returnAs: "uint8array" });
        expect(decoded).toEqual(testUint8Array);
      });

      it("should decode a Base64 string to Uint8Array with returnAs 'bytes' alias", () => {
        const decoded = base64Parse(encodedString, { loose: true, returnAs: "bytes" });
        expect(decoded).toEqual(testUint8Array);
      });

      it("should mirror input type: Uint8Array in → Uint8Array out", () => {
        const decoded = base64Parse(encodedUint8Array, { loose: true });
        expect(decoded).toBeInstanceOf(Uint8Array);
        expect(decoded).toEqual(testUint8Array);
      });

      it("should override mirroring with explicit returnAs", () => {
        const decoded = base64Parse(encodedUint8Array, { loose: true, returnAs: "string" });
        expect(decoded).toBe(testString);
      });

      it("should handle empty string input", () => {
        expect(base64Parse("", { loose: true })).toBe("");
        expect(base64Parse("", { loose: true, returnAs: "uint8array" })).toEqual(new Uint8Array(0));
      });

      it("should throw INVALID_TYPE on null or undefined", () => {
        expectUnsecureError(() => base64Parse(undefined as any, { loose: true }), "INVALID_TYPE");
        expectUnsecureError(() => base64Parse(null as any, { loose: true }), "INVALID_TYPE");
      });
    });

    describe("base64Parse(data, base64url)", () => {
      const originalBase64 = b64Encode(testString);
      const encodedUrlSafeString = originalBase64
        .replace(/\+/g, "-")
        .replace(/\//g, "_")
        .replace(/=/g, "");
      const encodedUrlSafeUint8Array = new TextEncoder().encode(encodedUrlSafeString);

      it("should decode a Base64 URL-safe string to string by default", () => {
        const decoded = base64Parse(encodedUrlSafeString, { loose: true });
        expect(decoded).toBe(testString);
      });

      it("should decode a Base64 URL-safe string to string with returnAs 'string'", () => {
        const decoded = base64Parse(encodedUrlSafeString, { loose: true, returnAs: "string" });
        expect(decoded).toBe(testString);
      });

      it("should decode a Base64 URL-safe string to Uint8Array with returnAs 'uint8array'", () => {
        const decoded = base64Parse(encodedUrlSafeString, { loose: true, returnAs: "uint8array" });
        expect(decoded).toEqual(testUint8Array);
      });

      it("should decode a Base64 URL-safe string to Uint8Array with returnAs 'bytes' alias", () => {
        const decoded = base64Parse(encodedUrlSafeString, { loose: true, returnAs: "bytes" });
        expect(decoded).toEqual(testUint8Array);
      });

      it("should mirror input type: Uint8Array in → Uint8Array out", () => {
        const decoded = base64Parse(encodedUrlSafeUint8Array, { loose: true });
        expect(decoded).toBeInstanceOf(Uint8Array);
        expect(decoded).toEqual(testUint8Array);
      });

      it("should override mirroring with explicit returnAs", () => {
        const decoded = base64Parse(encodedUrlSafeUint8Array, { loose: true, returnAs: "string" });
        expect(decoded).toBe(testString);
      });

      it("should handle empty string input", () => {
        expect(base64Parse("", { loose: true })).toBe("");
        expect(base64Parse("", { loose: true, returnAs: "uint8array" })).toEqual(new Uint8Array(0));
      });

      it("should throw INVALID_TYPE on null or undefined", () => {
        expectUnsecureError(() => base64Parse(undefined as any, { loose: true }), "INVALID_TYPE");
        expectUnsecureError(() => base64Parse(null as any, { loose: true }), "INVALID_TYPE");
      });

      it("should correctly pad and decode URL-safe strings without padding", () => {
        expect(base64Parse("", { loose: true })).toBe("");
        expect(base64Parse("Zg", { loose: true })).toBe("f");
        expect(base64Parse("Zm8", { loose: true })).toBe("fo");
        expect(base64Parse("Zm9v", { loose: true })).toBe("foo");
        expect(base64Parse("Zm9vYg", { loose: true })).toBe("foob");
        expect(base64Parse("Zm9vYmE", { loose: true })).toBe("fooba");
        expect(base64Parse("Zm9vYmFy", { loose: true })).toBe("foobar");
      });
    });
  });

  describe("Hex Encoding/Decoding", () => {
    const testString =
      "Hello, Vitest! 👋 This is a test string with some special characters: Ā 𐀀 文 +/=";
    const testUint8Array = new TextEncoder().encode(testString);
    const expectedHex = [...testUint8Array].map((x) => x.toString(16).padStart(2, "0")).join("");

    describe("hexStringify(data)", () => {
      it("should encode a string to hex", () => {
        const encoded = hexStringify(testString);
        expect(encoded).toBe(expectedHex);
      });

      it("should encode a Uint8Array to hex", () => {
        const encoded = hexStringify(testUint8Array);
        expect(encoded).toBe(expectedHex);
      });

      it("should handle empty string", () => {
        expect(hexStringify("")).toBe("");
      });

      it("should throw INVALID_TYPE on null or undefined", () => {
        expectUnsecureError(() => hexStringify(undefined as any), "INVALID_TYPE");
        expectUnsecureError(() => hexStringify(null as any), "INVALID_TYPE");
      });
    });

    describe("hexParse(data, options)", () => {
      const encodedHexUint8Array = new TextEncoder().encode(expectedHex);

      it("should decode a hex string to string by default", () => {
        const decoded = hexParse(expectedHex, { loose: true });
        expect(decoded).toBe(testString);
      });

      it("should decode a hex string to string with returnAs 'string'", () => {
        const decoded = hexParse(expectedHex, { loose: true, returnAs: "string" });
        expect(decoded).toBe(testString);
      });

      it("should decode a hex string to Uint8Array with returnAs 'uint8array'", () => {
        const decoded = hexParse(expectedHex, { loose: true, returnAs: "uint8array" });
        expect(decoded).toEqual(testUint8Array);
      });

      it("should decode a hex string to Uint8Array with returnAs 'bytes' alias", () => {
        const decoded = hexParse(expectedHex, { loose: true, returnAs: "bytes" });
        expect(decoded).toEqual(testUint8Array);
      });

      it("should mirror input type: Uint8Array in → Uint8Array out", () => {
        const decoded = hexParse(encodedHexUint8Array, { loose: true });
        expect(decoded).toBeInstanceOf(Uint8Array);
        expect(decoded).toEqual(testUint8Array);
      });

      it("should override mirroring with explicit returnAs", () => {
        const decoded = hexParse(encodedHexUint8Array, { loose: true, returnAs: "string" });
        expect(decoded).toBe(testString);
      });

      it("should handle empty string input", () => {
        expect(hexParse("", { loose: true })).toBe("");
        expect(hexParse("", { loose: true, returnAs: "uint8array" })).toEqual(new Uint8Array(0));
      });

      it("should throw INVALID_TYPE on null or undefined", () => {
        expectUnsecureError(() => hexParse(undefined as any, { loose: true }), "INVALID_TYPE");
        expectUnsecureError(() => hexParse(null as any, { loose: true }), "INVALID_TYPE");
      });

      it("should decode hex strings with mixed case characters", () => {
        const mixedCaseHex = "48656c6c6f"; // "Hello"
        const expected = "Hello";
        expect(hexParse(mixedCaseHex, { loose: true })).toBe(expected);
        expect(hexParse(mixedCaseHex.toUpperCase(), { loose: true })).toBe(expected);
      });

      it("should handle odd length hex strings gracefully", () => {
        // Only complete byte pairs are decoded; trailing nibble is ignored.
        const decoded = hexParse("abc", { loose: true, returnAs: "uint8array" });
        expect(decoded).toEqual(Uint8Array.from([0xab]));
      });

      it("should handle invalid hex characters gracefully", () => {
        // Invalid hex characters result in an empty buffer.
        const decoded = hexParse("zz", { loose: true, returnAs: "uint8array" });
        expect(decoded).toEqual(new Uint8Array(0));
      });
    });
  });
});

describe.concurrent("Liberal inputs / tight outputs", () => {
  // A Uint8Array<SharedArrayBuffer> containing "foobar".
  function makeSharedView(): Uint8Array<SharedArrayBuffer> {
    const sab = new SharedArrayBuffer(6);
    const view = new Uint8Array(sab);
    view.set([102, 111, 111, 98, 97, 114]); // "foobar"
    return view;
  }

  describe("encoders accept SharedArrayBuffer-backed Uint8Array", () => {
    it("hexStringify", () => {
      expect(hexStringify(makeSharedView())).toBe("666f6f626172");
    });

    it("base64Stringify", () => {
      expect(base64Stringify(makeSharedView())).toBe("Zm9vYmFy");
    });

    it("base64Stringify (base64url)", () => {
      expect(base64Stringify(makeSharedView(), { alphabet: "base64url" })).toBe("Zm9vYmFy");
    });

    it("base32Stringify", () => {
      expect(base32Stringify(makeSharedView())).toBe("MZXW6YTBOI======");
    });
  });

  describe("decoders return ArrayBuffer-backed Uint8Array", () => {
    it("hexParse", () => {
      const out = hexParse("666f6f", { loose: true, returnAs: "uint8array" });
      expect(out.buffer).toBeInstanceOf(ArrayBuffer);
    });

    it("base64Parse", () => {
      const out = base64Parse("Zm9v", { loose: true, returnAs: "uint8array" });
      expect(out.buffer).toBeInstanceOf(ArrayBuffer);
    });

    it("base64Parse (base64url)", () => {
      const out = base64Parse("Zm9v", { loose: true, returnAs: "uint8array" });
      expect(out.buffer).toBeInstanceOf(ArrayBuffer);
    });

    it("base32Parse", () => {
      const out = base32Parse("MZXW6===", { loose: true, returnAs: "uint8array" });
      expect(out.buffer).toBeInstanceOf(ArrayBuffer);
    });
  });

  // Regression guard: Node's `Buffer.from(str, 'hex'|'base64'|'base64url')`
  // allocates from an internal 8KB pool for small inputs. The naive pattern
  // `new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength)` returns a
  // view into that shared pool, pinning it alive and sharing its ArrayBuffer
  // with unrelated Buffer allocations. Our decoders copy out with
  // `new Uint8Array(buf)`; this asserts the copy landed in a fresh,
  // exactly-sized ArrayBuffer rather than a pool view.
  describe("decoders copy out of the Node Buffer pool", () => {
    it("hexParse", () => {
      const out = hexParse("deadbeef", { loose: true, returnAs: "uint8array" });
      expect(out.byteOffset).toBe(0);
      expect(out.buffer.byteLength).toBe(out.byteLength);
    });

    it("base64Parse", () => {
      const out = base64Parse("Zm9vYmFy", { loose: true, returnAs: "uint8array" });
      expect(out.byteOffset).toBe(0);
      expect(out.buffer.byteLength).toBe(out.byteLength);
    });

    it("base64Parse (base64url)", () => {
      const out = base64Parse("Zm9vYmFy", { loose: true, returnAs: "uint8array" });
      expect(out.byteOffset).toBe(0);
      expect(out.buffer.byteLength).toBe(out.byteLength);
    });
  });
});

function b64Encode(data: string | Uint8Array): string {
  // @ts-ignore
  return Buffer.from(data).toString("base64");
}
