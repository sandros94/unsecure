import { describe, it, expect, beforeAll, afterAll, vi } from "vitest";

// Exercise the pure `btoa`/`atob`/manual fallback branches by importing the
// codecs with `Buffer` stubbed out (this Node build also lacks the TC39
// `Uint8Array.toBase64`/`fromBase64`/`toHex`/`fromHex` methods, so removing
// Buffer forces the lowest-common-denominator path used by minimal runtimes).

let codec: typeof import("../src/utils/index.ts");
const allBytes = Uint8Array.from({ length: 256 }, (_, i) => i);
const enc = new TextEncoder();

describe("codec fallback paths (no Buffer, no TC39)", () => {
  beforeAll(async () => {
    vi.stubGlobal("Buffer", undefined);
    vi.resetModules();
    codec = await import("../src/utils/index.ts");
  });

  afterAll(() => {
    vi.unstubAllGlobals();
    vi.resetModules();
  });

  it("Hex: round-trips and stays strict", () => {
    const { Hex } = codec;
    expect(Hex.parse(Hex.stringify(allBytes), { returnAs: "bytes" })).toEqual(allBytes);
    expect(() => Hex.parse("zz")).toThrow(SyntaxError);
    expect(Hex.parse("abc", { loose: true, returnAs: "bytes" })).toEqual(Uint8Array.of(0xab));
  });

  it("Base64: round-trip, padding, strict/loose", () => {
    const { Base64 } = codec;
    expect(Base64.parse(Base64.stringify(allBytes), { returnAs: "bytes" })).toEqual(allBytes);
    const url = Base64.stringify(allBytes, { alphabet: "base64url" });
    expect(Base64.parse(url, { alphabet: "base64url", returnAs: "bytes" })).toEqual(allBytes);
    expect(Base64.stringify(enc.encode("f"))).toBe("Zg==");
    expect(Base64.stringify(enc.encode("f"), { padding: false })).toBe("Zg");
    expect(() => Base64.parse("Zg=@")).toThrow(SyntaxError);
    expect(Base64.parse("Zm9v_", { loose: true, returnAs: "bytes" })).toEqual(enc.encode("foo"));
  });

  it("legacy encoders still work without Buffer", () => {
    expect(codec.base64Encode(enc.encode("foobar"))).toBe("Zm9vYmFy");
    expect(codec.base64UrlEncode(enc.encode("foobar"))).toBe("Zm9vYmFy");
    expect(codec.hexEncode(enc.encode("hi"))).toBe("6869");
  });
});
