import { describe, it, expect, beforeAll, afterAll, vi } from "vitest";

// The codecs pick a bulk decoder from what the runtime offers: Node's
// `Buffer`, the TC39 `Uint8Array` methods, or a hand-rolled loop. Which one
// runs must be invisible, so the same table is asserted against literal bytes
// with `Buffer` stubbed out and left in place. The `native-base64` project
// runs this file again with the TC39 methods enabled, covering the four
// combinations between them.

type Expectation = readonly number[] | "throws";

interface Vector {
  readonly text: string;
  readonly alphabet?: "base64" | "base64url";
  readonly strict: Expectation;
  readonly loose: readonly number[];
}

const FOOBAR = [102, 111, 111, 98, 97, 114] as const;

const BASE64_VECTORS: readonly Vector[] = [
  { text: "", strict: [], loose: [] },
  { text: "AQID", strict: [1, 2, 3], loose: [1, 2, 3] },
  { text: "Zm9vYmFy", strict: FOOBAR, loose: FOOBAR },
  { text: "Zm9vYmE=", strict: [102, 111, 111, 98, 97], loose: [102, 111, 111, 98, 97] },
  { text: "Zm9vYmE", strict: [102, 111, 111, 98, 97], loose: [102, 111, 111, 98, 97] },
  { text: "Zg==", strict: [102], loose: [102] },
  { text: "Zg", strict: [102], loose: [102] },
  // Set bits past the final byte: two texts for one byte string.
  { text: "Zh==", strict: "throws", loose: [102] },
  { text: "Zh", strict: "throws", loose: [102] },
  // Padding present but not the count the length calls for.
  { text: "Zm9vYg=", strict: "throws", loose: [102, 111, 111, 98] },
  { text: "Zm9vYmFy=", strict: "throws", loose: FOOBAR },
  { text: "====", strict: "throws", loose: [] },
  { text: "Zg=Zg==", strict: "throws", loose: [102, 6, 96] },
  // A trailing symbol that cannot start a byte.
  { text: "Zm9vY", strict: "throws", loose: [102, 111, 111] },
  { text: "Zm 9v", strict: "throws", loose: [102, 111, 111] },
  { text: "Zg=@", strict: "throws", loose: [102] },
  { text: "!!!", strict: "throws", loose: [] },
  // Alphabets are enforced in strict, folded in loose.
  { text: "Zm9v-A", strict: "throws", loose: [102, 111, 111, 248] },
  { text: "+/8=", strict: [0xfb, 0xff], loose: [0xfb, 0xff] },
  { text: "-_8", alphabet: "base64url", strict: [0xfb, 0xff], loose: [0xfb, 0xff] },
  { text: "+/8=", alphabet: "base64url", strict: "throws", loose: [0xfb, 0xff] },
];

for (const withBuffer of [true, false]) {
  describe(`codec backends — Buffer ${withBuffer ? "present" : "absent"}`, () => {
    let codec: typeof import("../src/utils/index.ts");

    beforeAll(async () => {
      if (!withBuffer) vi.stubGlobal("Buffer", undefined);
      vi.resetModules();
      codec = await import("../src/utils/index.ts");
    });

    afterAll(() => {
      vi.unstubAllGlobals();
      vi.resetModules();
    });

    for (const vector of BASE64_VECTORS) {
      const alphabet = vector.alphabet ?? "base64";
      it(`base64 ${alphabet} ${JSON.stringify(vector.text)}`, () => {
        const parse = codec.base64Parse;
        if (vector.strict === "throws") {
          expect(() => parse(vector.text, { alphabet, returnAs: "bytes" })).toThrow(SyntaxError);
          expect(() => parse(vector.text, { alphabet, returnAs: "bytes" })).toThrow(
            /^Base64\.parse: /,
          );
        } else {
          expect(parse(vector.text, { alphabet, returnAs: "bytes" })).toEqual(
            Uint8Array.from(vector.strict),
          );
        }
        expect(parse(vector.text, { alphabet, loose: true, returnAs: "bytes" })).toEqual(
          Uint8Array.from(vector.loose),
        );
      });
    }

    it("Hex: round-trips and stays strict", () => {
      const { Hex } = codec;
      const allBytes = Uint8Array.from({ length: 256 }, (_, i) => i);
      expect(Hex.parse(Hex.stringify(allBytes), { returnAs: "bytes" })).toEqual(allBytes);
      expect(() => Hex.parse("zz")).toThrow(SyntaxError);
      expect(Hex.parse("abc", { loose: true, returnAs: "bytes" })).toEqual(Uint8Array.of(0xab));
    });

    it("encoders round-trip every byte", () => {
      const allBytes = Uint8Array.from({ length: 256 }, (_, i) => i);
      const { base64Parse, base64Stringify, hexStringify } = codec;
      expect(base64Parse(base64Stringify(allBytes), { returnAs: "bytes" })).toEqual(allBytes);
      const url = base64Stringify(allBytes, { alphabet: "base64url" });
      expect(base64Parse(url, { alphabet: "base64url", returnAs: "bytes" })).toEqual(allBytes);
      expect(base64Stringify(Uint8Array.of(102))).toBe("Zg==");
      expect(base64Stringify(Uint8Array.of(102), { padding: false })).toBe("Zg");
      expect(base64Stringify(Uint8Array.from(FOOBAR), { alphabet: "base64url" })).toBe("Zm9vYmFy");
      expect(hexStringify(Uint8Array.of(104, 105))).toBe("6869");
    });
  });
}
