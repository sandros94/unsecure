import { describe, it, expect } from "vitest";
import { toBytes, toCryptoBytes } from "../src/_internal/bytes.ts";
import {
  Base32,
  Base64,
  Hex,
  base32Parse,
  base32Stringify,
  base64Parse,
  base64Stringify,
  hexParse,
  hexStringify,
} from "../src/utils/index.ts";

const enc = new TextEncoder();
const allBytes = Uint8Array.from({ length: 256 }, (_, i) => i);

describe.concurrent("Unified codec API", () => {
  describe("Hex", () => {
    it("the codec object is the flat functions", () => {
      expect(Hex.stringify).toBe(hexStringify);
      expect(Hex.parse).toBe(hexParse);
      expect(hexStringify("héllo")).toBe("68c3a96c6c6f");
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

    it("loose drops what it cannot use instead of stopping at it", () => {
      expect(hexParse("abc", { loose: true, returnAs: "bytes" })).toEqual(Uint8Array.of(0xab));
      expect(hexParse("zz", { loose: true, returnAs: "bytes" })).toEqual(new Uint8Array(0));
      expect(hexParse("zzab", { loose: true, returnAs: "bytes" })).toEqual(Uint8Array.of(0xab));
      expect(hexParse("de ad", { loose: true, returnAs: "bytes" })).toEqual(
        Uint8Array.of(0xde, 0xad),
      );
      expect(hexParse("d-e-a-d-b", { loose: true, returnAs: "bytes" })).toEqual(
        Uint8Array.of(0xde, 0xad),
      );
    });

    it("strict errors are the library's, naming what it found", () => {
      expect(() => hexParse("de ad")).toThrow(
        /^Hex\.parse: invalid hexadecimal character " " at index 2\.$/,
      );
      expect(() => hexParse("zz")).toThrow(
        /^Hex\.parse: invalid hexadecimal character "z" at index 0\.$/,
      );
      expect(() => hexParse("abc")).toThrow(
        /^Hex\.parse: 3 hexadecimal characters cannot encode whole bytes\.$/,
      );
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
    it("the codec object is the flat functions", () => {
      expect(Base64.stringify).toBe(base64Stringify);
      expect(Base64.parse).toBe(base64Parse);
      expect(base64Stringify("foobar")).toBe("Zm9vYmFy");
      expect(base64Stringify(Uint8Array.of(0xfb, 0xff))).toBe("+/8=");
      expect(base64Stringify(Uint8Array.of(0xfb, 0xff), { alphabet: "base64url" })).toBe("-_8");
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

    it("strict rejects ASCII whitespace", () => {
      expect(() => base64Parse("Zm 9v\nYg==")).toThrow(SyntaxError);
      expect(() => base64Parse("Zm9vYg== ")).toThrow(SyntaxError);
    });

    it("strict accepts unpadded canonical input on both alphabets", () => {
      expect(base64Parse("Zg")).toBe("f");
      expect(base64Parse("Zm9vYg")).toBe("foob");
      expect(
        base64Parse(base64Stringify(allBytes, { padding: false }), { returnAs: "bytes" }),
      ).toEqual(allBytes);
      const url = base64Stringify(allBytes, { alphabet: "base64url" });
      expect(base64Parse(url, { alphabet: "base64url", returnAs: "bytes" })).toEqual(allBytes);
    });

    it("strict rejects mis-padding, stray padding and impossible lengths", () => {
      expect(() => base64Parse("Zm9vYg=")).toThrow(SyntaxError);
      expect(() => base64Parse("Zm9vYmFy=")).toThrow(SyntaxError);
      expect(() => base64Parse("Zg===")).toThrow(SyntaxError);
      expect(() => base64Parse("Zm9vY")).toThrow(SyntaxError);
      expect(() => base64Parse("Zg=Zg==")).toThrow(SyntaxError);
    });

    it("strict rejects set bits past the last byte", () => {
      expect(base64Parse("Zg==")).toBe("f");
      expect(() => base64Parse("Zh==")).toThrow(SyntaxError);
      expect(() => base64Parse("Zh")).toThrow(SyntaxError);
      expect(base64Parse("Zm8=")).toBe("fo");
      expect(() => base64Parse("Zm9=")).toThrow(SyntaxError);
    });

    it("loose drops what it cannot use and never throws on shape", () => {
      expect(base64Parse("Z m\t9v!", { loose: true })).toBe("foo");
      expect(base64Parse("Zm9vY", { loose: true })).toBe("foo");
      expect(base64Parse("Zm9vYg=", { loose: true })).toBe("foob");
      expect(base64Parse("Zh==", { loose: true, returnAs: "bytes" })).toEqual(Uint8Array.of(0x66));
      expect(base64Parse("!!!", { loose: true, returnAs: "bytes" })).toEqual(new Uint8Array(0));
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

    it("strict accepts only the canonical encoding", () => {
      expect(base32Parse("MZXW6===")).toBe("foo");
      expect(base32Parse("MZXW6")).toBe("foo");
      expect(() => base32Parse("MZXW7===")).toThrow(SyntaxError); // bits past the last byte
      expect(() => base32Parse("MZ=XW6===")).toThrow(SyntaxError); // padding inside the body
      expect(() => base32Parse("MZXW6=")).toThrow(SyntaxError); // 5 symbols need 3 pads
      expect(() => base32Parse("M")).toThrow(SyntaxError); // cannot encode a byte
      expect(base32Parse("MZXW6YQ")).toBe("foob"); // 7 symbols can
      expect(() => base32Parse("MZXW6YTBO")).toThrow(SyntaxError); // 1 past a block
    });

    it("strict is uppercase-only for the RFC alphabets; loose folds case", () => {
      expect(() => base32Parse("mzxw6===")).toThrow(SyntaxError);
      expect(base32Parse("mzxw6===", { loose: true })).toBe("foo");
      expect(() => base32Parse("cpnmu===", { alphabet: "base32hex" })).toThrow(SyntaxError);
      expect(base32Parse("cpnmu===", { alphabet: "base32hex", loose: true })).toBe("foo");
    });

    it("crockford decodes case-insensitively with O/I/L aliases in strict mode", () => {
      const text = base32Stringify("foobar", { alphabet: "crockford" });
      expect(base32Parse(text.toLowerCase(), { alphabet: "crockford" })).toBe("foobar");
      // 0 and O, 1 and I/L are the same symbol by Crockford's own spec.
      expect(base32Parse("0", { alphabet: "crockford", loose: true, returnAs: "bytes" })).toEqual(
        base32Parse("O", { alphabet: "crockford", loose: true, returnAs: "bytes" }),
      );
      expect(base32Parse("1G", { alphabet: "crockford", returnAs: "bytes" })).toEqual(
        base32Parse("LG", { alphabet: "crockford", returnAs: "bytes" }),
      );
    });

    it("rejects unusable custom alphabets", () => {
      const bad: Array<[string, string]> = [
        ["repeats a character", "AABCDEFGHIJKLMNOPQRSTUVWXYZ23456"],
        ["contains the padding character", "ABCDEFGHIJKLMNOPQRSTUVWXYZ23456="],
        ["contains whitespace", "ABCDEFGHIJKLMNOPQRSTUVWXYZ23456 "],
        ["contains a non-ASCII character", "ABCDEFGHIJKLMNOPQRSTUVWXYZ23456é"],
      ];
      for (const [, alphabet] of bad) {
        expect(alphabet.length).toBe(32);
        expect(() => base32Stringify("x", { alphabet })).toThrow(SyntaxError);
        expect(() => base32Parse("AA", { alphabet })).toThrow(SyntaxError);
      }
      expect(() => base32Parse("", { alphabet: "tooshort" })).toThrow(SyntaxError);
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

    it("the codec object is the flat functions", () => {
      expect(Base32.stringify).toBe(base32Stringify);
      expect(Base32.parse).toBe(base32Parse);
      expect(base32Stringify("foobar")).toBe("MZXW6YTBOI======");
    });
  });

  describe("byte coercion", () => {
    const deadbeef = Uint8Array.of(0xde, 0xad, 0xbe, 0xef);
    const notBytes: Array<[string, unknown]> = [
      ["a number", 123],
      ["a plain object", {}],
      ["an array", []],
      ["a boolean", true],
      ["null", null],
      ["undefined", undefined],
    ];

    it("stringify accepts any BytesSource", () => {
      expect(Hex.stringify(deadbeef.buffer)).toBe("deadbeef");
      expect(Hex.stringify(new DataView(deadbeef.buffer, 1, 2))).toBe("adbe");
      expect(Base64.stringify(deadbeef.buffer)).toBe("3q2+7w==");
      expect(Base32.stringify(new Uint16Array(deadbeef.buffer), { padding: false })).toBe(
        "32W353Y",
      );
    });

    const stringifiers = [
      ["Hex.stringify", Hex.stringify],
      ["Base64.stringify", Base64.stringify],
      ["Base32.stringify", Base32.stringify],
    ] as const;
    const parsers = [
      ["Hex.parse", Hex.parse],
      ["Base64.parse", Base64.parse],
      ["Base32.parse", Base32.parse],
    ] as const;

    it("rejects a value that only inherits Uint8Array.prototype", () => {
      const fake = Object.create(Uint8Array.prototype) as Uint8Array;
      expect(() => toBytes(fake, "t")).toThrow(
        "t: expected a string, ArrayBuffer or ArrayBuffer view, got Uint8Array.",
      );
      expect(() => hexStringify(fake)).toThrow(
        "Hex.stringify: expected a string, ArrayBuffer or ArrayBuffer view, got Uint8Array.",
      );
      expect(() => base64Stringify(fake)).toThrow(
        "Base64.stringify: expected a string, ArrayBuffer or ArrayBuffer view, got Uint8Array.",
      );
      expect(() => base32Stringify(fake)).toThrow(
        "Base32.stringify: expected a string, ArrayBuffer or ArrayBuffer view, got Uint8Array.",
      );
      expect(() => hexParse(fake as unknown as string)).toThrow(
        "Hex.parse: expected a string or Uint8Array, got Uint8Array.",
      );
      expect(() => base64Parse(fake as unknown as string)).toThrow(
        "Base64.parse: expected a string or Uint8Array, got Uint8Array.",
      );
      expect(() => base32Parse(fake as unknown as string)).toThrow(
        "Base32.parse: expected a string or Uint8Array, got Uint8Array.",
      );
    });

    for (const [what, value] of notBytes) {
      it(`stringify rejects ${what}`, () => {
        for (const [name, stringify] of stringifiers) {
          expect(() => stringify(value as string)).toThrow(TypeError);
          expect(() => stringify(value as string)).toThrow(
            `${name}: expected a string, ArrayBuffer or ArrayBuffer view, got `,
          );
        }
      });
    }

    const notText: Array<[string, unknown]> = [
      ...notBytes,
      ["an ArrayBuffer", deadbeef.buffer],
      ["a DataView", new DataView(deadbeef.buffer)],
    ];

    for (const [what, value] of notText) {
      it(`parse rejects ${what}`, () => {
        for (const [name, parse] of parsers) {
          expect(() => parse(value as string)).toThrow(TypeError);
          expect(() => parse(value as string)).toThrow(
            `${name}: expected a string or Uint8Array, got `,
          );
        }
      });
    }

    it("the message names what it got", () => {
      expect(() => Hex.stringify(123 as unknown as string)).toThrow(
        "Hex.stringify: expected a string, ArrayBuffer or ArrayBuffer view, got number.",
      );
      expect(() => Base32.parse({} as unknown as string)).toThrow(
        "Base32.parse: expected a string or Uint8Array, got Object.",
      );
      expect(() => Base64.parse(null as unknown as string)).toThrow(
        "Base64.parse: expected a string or Uint8Array, got null.",
      );
    });

    it("toBytes aliases the caller memory; toCryptoBytes unshares it", () => {
      expect(toBytes(deadbeef, "t")).toBe(deadbeef);
      expect(toBytes("hi", "t")).toEqual(Uint8Array.of(104, 105));
      expect(toBytes(deadbeef.buffer, "t")).toEqual(deadbeef);
      expect(toBytes(new DataView(deadbeef.buffer, 1, 2), "t")).toEqual(Uint8Array.of(0xad, 0xbe));
      const shared = new Uint8Array(new SharedArrayBuffer(2));
      expect(toBytes(shared, "t")).toBe(shared);
      const copy = toCryptoBytes(shared, "t");
      expect(copy.buffer).toBeInstanceOf(ArrayBuffer);
      expect(copy).toEqual(shared);
      expect(toCryptoBytes(deadbeef, "t")).toBe(deadbeef);
    });

    for (const [what, value] of notBytes) {
      it(`toBytes and toCryptoBytes reject ${what}`, () => {
        expect(() => toBytes(value as string, "t")).toThrow(TypeError);
        expect(() => toCryptoBytes(value as string, "t")).toThrow(
          /^t: expected a string, ArrayBuffer or ArrayBuffer view, got /,
        );
      });
    }
  });
});

describe.concurrent("RFC 4648 §10 test vectors decode in strict mode", () => {
  const inputs = ["", "f", "fo", "foo", "foob", "fooba", "foobar"];
  const table = {
    base16: ["", "66", "666F", "666F6F", "666F6F62", "666F6F6261", "666F6F626172"],
    base32: ["", "MY======", "MZXQ====", "MZXW6===", "MZXW6YQ=", "MZXW6YTB", "MZXW6YTBOI======"],
    base32hex: ["", "CO======", "CPNG====", "CPNMU===", "CPNMUOG=", "CPNMUOJ1", "CPNMUOJ1E8======"],
    base64: ["", "Zg==", "Zm8=", "Zm9v", "Zm9vYg==", "Zm9vYmE=", "Zm9vYmFy"],
  } as const;

  it("base16", () => {
    table.base16.forEach((text, i) => expect(hexParse(text)).toBe(inputs[i]));
  });

  it("base32 / base32hex", () => {
    table.base32.forEach((text, i) => expect(base32Parse(text)).toBe(inputs[i]));
    table.base32hex.forEach((text, i) =>
      expect(base32Parse(text, { alphabet: "base32hex" })).toBe(inputs[i]),
    );
  });

  it("base64", () => {
    table.base64.forEach((text, i) => expect(base64Parse(text)).toBe(inputs[i]));
  });
});

describe.concurrent("Text handling is byte-faithful", () => {
  it("a BOM in the payload is payload", () => {
    expect(hexParse("efbbbf68")).toBe("\uFEFFh");
    expect(base64Parse("77u/aA==")).toBe("\uFEFFh");
  });

  it("strict rejects decoded bytes that are not valid UTF-8", () => {
    expect(base64Parse("//8=", { returnAs: "bytes" })).toEqual(Uint8Array.of(0xff, 0xff));
    expect(() => base64Parse("//8=")).toThrow(
      /^Base64\.parse: decoded bytes are not valid UTF-8\.$/,
    );
    expect(() => hexParse("ffff")).toThrow(/^Hex\.parse: decoded bytes are not valid UTF-8\.$/);
    expect(base64Parse("//8=", { loose: true })).toBe("\uFFFD\uFFFD");
  });

  it("Uint8Array input is the encoded text, one character per byte", () => {
    const bomZg = Uint8Array.of(0xef, 0xbb, 0xbf, 0x5a, 0x67, 0x3d, 0x3d); // BOM + "Zg=="
    expect(() => base64Parse(bomZg)).toThrow(/invalid base64 character "ï" at index 0\./);
    expect(base64Parse(bomZg, { loose: true })).toEqual(Uint8Array.of(0x66));
    expect(() => base64Parse(Uint8Array.of(0x5a, 0x67, 0xc3, 0xa9))).toThrow(
      /invalid base64 character "Ã" at index 2\./,
    );
    expect(base64Parse(enc.encode("Zg=="))).toEqual(Uint8Array.of(0x66));
  });

  it("byte output owns a buffer exactly its own length", () => {
    const outputs = [
      hexParse("deadbeef", { returnAs: "bytes" }),
      hexParse("dead beef", { loose: true, returnAs: "bytes" }),
      base64Parse("Zm9vYmFy", { returnAs: "bytes" }),
      base64Parse("Zm9v YmFy", { loose: true, returnAs: "bytes" }),
      base32Parse("MZXW6===", { returnAs: "bytes" }),
      base32Parse("MZXW 6", { loose: true, returnAs: "bytes" }),
    ];
    for (const out of outputs) {
      expect(out.byteOffset).toBe(0);
      expect(out.buffer.byteLength).toBe(out.byteLength);
    }
  });
});
