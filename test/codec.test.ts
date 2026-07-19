import { describe, it, expect } from "vitest";
import {
  Base32,
  Base64,
  Hex,
  base32Encode,
  base64Encode,
  base64UrlEncode,
  hexEncode,
} from "../src/utils/index.ts";

const enc = new TextEncoder();
const allBytes = Uint8Array.from({ length: 256 }, (_, i) => i);

describe.concurrent("Unified codec API", () => {
  describe("Hex", () => {
    it("stringify matches the legacy hexEncode", () => {
      expect(Hex.stringify(allBytes)).toBe(hexEncode(allBytes));
      expect(Hex.stringify("héllo")).toBe(hexEncode("héllo"));
    });

    it("round-trips bytes", () => {
      expect(Hex.parse(Hex.stringify(allBytes), { returnAs: "bytes" })).toEqual(allBytes);
    });

    it("mirrors input type / honors returnAs", () => {
      expect(Hex.parse("68690a")).toBe("hi\n");
      expect(Hex.parse(enc.encode("68690a"))).toEqual(enc.encode("hi\n"));
      expect(Hex.parse("68690a", { returnAs: "uint8array" })).toEqual(enc.encode("hi\n"));
    });

    it("is strict by default", () => {
      expect(() => Hex.parse("zz")).toThrow(SyntaxError);
      expect(() => Hex.parse("abc")).toThrow(SyntaxError); // odd length
      expect(() => Hex.parse("de ad")).toThrow(SyntaxError); // whitespace
    });

    it("loose tolerates malformed input like the legacy decoder", () => {
      expect(Hex.parse("abc", { loose: true, returnAs: "bytes" })).toEqual(Uint8Array.of(0xab));
      expect(Hex.parse("zz", { loose: true, returnAs: "bytes" })).toEqual(new Uint8Array(0));
    });

    it("handles empty + rejects nullish", () => {
      expect(Hex.stringify("")).toBe("");
      expect(Hex.parse("")).toBe("");
      expect(Hex.parse("", { returnAs: "bytes" })).toEqual(new Uint8Array(0));
      // @ts-expect-error nullish
      expect(() => Hex.stringify(null)).toThrow(TypeError);
      // @ts-expect-error nullish
      expect(() => Hex.parse(undefined)).toThrow(TypeError);
    });
  });

  describe("Base64", () => {
    it("stringify matches the legacy base64Encode / base64UrlEncode", () => {
      expect(Base64.stringify(allBytes)).toBe(base64Encode(allBytes));
      expect(Base64.stringify(allBytes, { alphabet: "base64url" })).toBe(base64UrlEncode(allBytes));
    });

    it("padding option + base64url defaults unpadded", () => {
      expect(Base64.stringify(enc.encode("f"))).toBe("Zg==");
      expect(Base64.stringify(enc.encode("f"), { padding: false })).toBe("Zg");
      expect(Base64.stringify(enc.encode("foob"), { alphabet: "base64url" })).toBe("Zm9vYg");
    });

    it("round-trips (standard + url alphabet)", () => {
      expect(Base64.parse(Base64.stringify(allBytes), { returnAs: "bytes" })).toEqual(allBytes);
      const url = Base64.stringify(allBytes, { alphabet: "base64url" });
      expect(Base64.parse(url, { alphabet: "base64url", returnAs: "bytes" })).toEqual(allBytes);
    });

    it("is strict by default, loose tolerant", () => {
      expect(() => Base64.parse("Zg=@")).toThrow(SyntaxError);
      expect(() => Base64.parse("Zm9v-A")).toThrow(SyntaxError); // url char under base64 alphabet
      expect(Base64.parse("Zm9v_", { loose: true, returnAs: "bytes" })).toEqual(enc.encode("foo"));
    });

    it("strict tolerates ASCII whitespace (like native fromBase64)", () => {
      expect(Base64.parse("Zm 9v\nYg==", { returnAs: "bytes" })).toEqual(enc.encode("foob"));
    });

    it("url alphabet parse is strict too", () => {
      expect(Base64.parse("Zm9vYg", { alphabet: "base64url" })).toBe("foob");
      expect(() => Base64.parse("Zm9v+A", { alphabet: "base64url" })).toThrow(SyntaxError);
    });
  });

  describe("Base32", () => {
    const rfc: Array<[string, string]> = [
      ["", ""],
      ["f", "MY======"],
      ["fo", "MZXQ===="],
      ["foo", "MZXW6==="],
      ["foob", "MZXW6YQ="],
      ["fooba", "MZXW6YTB"],
      ["foobar", "MZXW6YTBOI======"],
    ];

    it("encodes RFC 4648 vectors", () => {
      for (const [input, expected] of rfc) {
        expect(Base32.stringify(enc.encode(input))).toBe(expected);
      }
    });

    it("padding option drops the '=' fill", () => {
      expect(Base32.stringify(enc.encode("f"), { padding: false })).toBe("MY");
    });

    it("base32hex RFC 4648 vector", () => {
      expect(Base32.stringify(enc.encode("foobar"), { alphabet: "base32hex" })).toBe(
        "CPNMUOJ1E8======",
      );
    });

    it("crockford: unpadded by default, case-insensitive with I/L/O aliases", () => {
      const encoded = Base32.stringify(enc.encode("foobar"), { alphabet: "crockford" });
      expect(encoded).not.toContain("=");
      expect(Base32.parse(encoded, { alphabet: "crockford" })).toBe("foobar");
      const round = Base32.stringify(Uint8Array.of(0, 1, 255), { alphabet: "crockford" });
      expect(
        Base32.parse(round.toLowerCase(), { alphabet: "crockford", returnAs: "bytes" }),
      ).toEqual(Uint8Array.of(0, 1, 255));
    });

    it("custom alphabet round-trips and rejects wrong length", () => {
      const custom = "abcdefghijklmnopqrstuvwxyz234567";
      const encoded = Base32.stringify(allBytes, { alphabet: custom });
      expect(Base32.parse(encoded, { alphabet: custom, returnAs: "bytes" })).toEqual(allBytes);
      expect(() => Base32.stringify(enc.encode("x"), { alphabet: "tooshort" })).toThrow(
        SyntaxError,
      );
    });

    it("is strict by default, loose skips invalid", () => {
      expect(() => Base32.parse("MZXW 6YTB")).toThrow(SyntaxError);
      expect(Base32.parse("MZXW 6YTB OI==\n====", { loose: true })).toBe("foobar");
    });

    it("round-trips every single byte (all variants)", () => {
      for (const alphabet of ["base32", "base32hex", "crockford"] as const) {
        for (let i = 0; i < 256; i++) {
          const b = Uint8Array.of(i);
          const s = Base32.stringify(b, { alphabet });
          expect(Base32.parse(s, { alphabet, returnAs: "bytes" })).toEqual(b);
        }
      }
    });

    it("matches the legacy base32Encode for the default alphabet", () => {
      expect(Base32.stringify(allBytes)).toBe(base32Encode(allBytes));
    });
  });
});
