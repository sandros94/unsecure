import { describe, it, expect, beforeAll, afterAll, vi } from "vitest";
import type { Base32Alphabet, Base64Alphabet } from "../src/utils/index.ts";

// The codecs pick a bulk decoder from what the runtime offers: Node's
// `Buffer`, the TC39 `Uint8Array` methods, or a hand-rolled loop. Which one
// runs must be invisible, so the same table is asserted against literal bytes
// with `Buffer` stubbed out and left in place. The `native-base64` project
// runs this file again with the TC39 methods enabled, covering the four
// combinations between them.

type Codec = "hex" | "base64" | "base32";

/** Bytes on success; the error class and our label prefix on failure. */
type Outcome = readonly number[] | { readonly syntaxError: string };

interface Vector {
  readonly codec: Codec;
  readonly text: string;
  readonly alphabet?: string;
  readonly strict: Outcome;
  readonly loose: readonly number[];
}

const FOO = [102, 111, 111] as const;
const FOOBAR = [102, 111, 111, 98, 97, 114] as const;
const B64_THROWS = { syntaxError: "Base64.parse" } as const;
const B32_THROWS = { syntaxError: "Base32.parse" } as const;
const HEX_THROWS = { syntaxError: "Hex.parse" } as const;

const VECTORS: readonly Vector[] = [
  { codec: "base64", text: "", strict: [], loose: [] },
  { codec: "base64", text: "AQID", strict: [1, 2, 3], loose: [1, 2, 3] },
  { codec: "base64", text: "Zm9vYmFy", strict: FOOBAR, loose: FOOBAR },
  {
    codec: "base64",
    text: "Zm9vYmE=",
    strict: [102, 111, 111, 98, 97],
    loose: [102, 111, 111, 98, 97],
  },
  {
    codec: "base64",
    text: "Zm9vYmE",
    strict: [102, 111, 111, 98, 97],
    loose: [102, 111, 111, 98, 97],
  },
  { codec: "base64", text: "Zg==", strict: [102], loose: [102] },
  { codec: "base64", text: "Zg", strict: [102], loose: [102] },
  // Set bits past the final byte: two texts for one byte string.
  { codec: "base64", text: "Zh==", strict: B64_THROWS, loose: [102] },
  { codec: "base64", text: "Zh", strict: B64_THROWS, loose: [102] },
  // Padding present but not the count the length calls for.
  { codec: "base64", text: "Zm9vYg=", strict: B64_THROWS, loose: [102, 111, 111, 98] },
  { codec: "base64", text: "Zm9vYmFy=", strict: B64_THROWS, loose: FOOBAR },
  { codec: "base64", text: "====", strict: B64_THROWS, loose: [] },
  { codec: "base64", text: "Zg=Zg==", strict: B64_THROWS, loose: [102, 6, 96] },
  // A trailing symbol that cannot start a byte.
  { codec: "base64", text: "Zm9vY", strict: B64_THROWS, loose: FOO },
  { codec: "base64", text: "Zm 9v", strict: B64_THROWS, loose: FOO },
  { codec: "base64", text: "Zg=@", strict: B64_THROWS, loose: [102] },
  { codec: "base64", text: "!!!", strict: B64_THROWS, loose: [] },
  // Alphabets are enforced in strict, folded in loose.
  { codec: "base64", text: "Zm9v-A", strict: B64_THROWS, loose: [102, 111, 111, 248] },
  { codec: "base64", text: "+/8=", strict: [0xfb, 0xff], loose: [0xfb, 0xff] },
  {
    codec: "base64",
    text: "-_8",
    alphabet: "base64url",
    strict: [0xfb, 0xff],
    loose: [0xfb, 0xff],
  },
  { codec: "base64", text: "+/8=", alphabet: "base64url", strict: B64_THROWS, loose: [0xfb, 0xff] },

  { codec: "base32", text: "", strict: [], loose: [] },
  { codec: "base32", text: "MZXW6YTBOI======", strict: FOOBAR, loose: FOOBAR },
  { codec: "base32", text: "MZXW6===", strict: FOO, loose: FOO },
  { codec: "base32", text: "MZXW6", strict: FOO, loose: FOO },
  { codec: "base32", text: "MZXW7===", strict: B32_THROWS, loose: FOO },
  { codec: "base32", text: "MZ=XW6===", strict: B32_THROWS, loose: FOO },
  { codec: "base32", text: "MZXW6=", strict: B32_THROWS, loose: FOO },
  { codec: "base32", text: "MZXW 6", strict: B32_THROWS, loose: FOO },
  { codec: "base32", text: "M", strict: B32_THROWS, loose: [] },
  { codec: "base32", text: "========", strict: B32_THROWS, loose: [] },
  { codec: "base32", text: "mzxw6===", strict: B32_THROWS, loose: FOO },
  { codec: "base32", text: "CPNMU===", alphabet: "base32hex", strict: FOO, loose: FOO },
  { codec: "base32", text: "cpnmu===", alphabet: "base32hex", strict: B32_THROWS, loose: FOO },
  { codec: "base32", text: "OO", alphabet: "crockford", strict: [0], loose: [0] },
  { codec: "base32", text: "oo", alphabet: "crockford", strict: [0], loose: [0] },

  { codec: "hex", text: "", strict: [], loose: [] },
  { codec: "hex", text: "666f6f", strict: FOO, loose: FOO },
  { codec: "hex", text: "666F6F", strict: FOO, loose: FOO },
  { codec: "hex", text: "666f6", strict: HEX_THROWS, loose: [102, 111] },
  { codec: "hex", text: "66 6f 6f", strict: HEX_THROWS, loose: FOO },
  { codec: "hex", text: "zz666f6f", strict: HEX_THROWS, loose: FOO },
  { codec: "hex", text: "666f6fzz", strict: HEX_THROWS, loose: FOO },
  { codec: "hex", text: "66:6f:6f", strict: HEX_THROWS, loose: FOO },
  // Loose drops non-digits, not "prefixes": the 0 of "0x" is a hex digit.
  { codec: "hex", text: "0x66", strict: HEX_THROWS, loose: [0x06] },
];

type Codecs = typeof import("../src/utils/index.ts");

function decode(codecs: Codecs, vector: Vector, loose: boolean): Uint8Array {
  const { text, alphabet } = vector;
  switch (vector.codec) {
    case "hex": {
      return codecs.hexParse(text, { loose, returnAs: "bytes" });
    }
    case "base64": {
      return codecs.base64Parse(text, {
        alphabet: alphabet as Base64Alphabet | undefined,
        loose,
        returnAs: "bytes",
      });
    }
    case "base32": {
      return codecs.base32Parse(text, {
        alphabet: alphabet as Base32Alphabet | undefined,
        loose,
        returnAs: "bytes",
      });
    }
  }
}

/** Compare success and failure in one shape, so neither needs a branch in a test. */
function outcome(run: () => Uint8Array): Outcome | { readonly unexpected: string } {
  try {
    return [...run()];
  } catch (error) {
    if (error instanceof SyntaxError) {
      return { syntaxError: error.message.slice(0, error.message.indexOf(":")) };
    }
    return { unexpected: String(error) };
  }
}

for (const withBuffer of [true, false]) {
  describe(`codec backends — Buffer ${withBuffer ? "present" : "absent"}`, () => {
    let codecs: Codecs;

    beforeAll(async () => {
      if (!withBuffer) vi.stubGlobal("Buffer", undefined);
      vi.resetModules();
      codecs = await import("../src/utils/index.ts");
    });

    afterAll(() => {
      vi.unstubAllGlobals();
      vi.resetModules();
    });

    for (const vector of VECTORS) {
      const name = `${vector.codec} ${vector.alphabet ?? "default"} ${JSON.stringify(vector.text)}`;
      // oxlint-disable-next-line vitest/valid-title
      it(name, () => {
        expect(outcome(() => decode(codecs, vector, false))).toEqual(vector.strict);
        expect(outcome(() => decode(codecs, vector, true))).toEqual(vector.loose);
      });
    }

    it("encoders round-trip every byte", () => {
      const allBytes = Uint8Array.from({ length: 256 }, (_, i) => i);
      const { base32Parse, base32Stringify, base64Parse, base64Stringify } = codecs;
      const { hexParse, hexStringify } = codecs;
      expect(hexParse(hexStringify(allBytes), { returnAs: "bytes" })).toEqual(allBytes);
      expect(base64Parse(base64Stringify(allBytes), { returnAs: "bytes" })).toEqual(allBytes);
      const url = base64Stringify(allBytes, { alphabet: "base64url" });
      expect(base64Parse(url, { alphabet: "base64url", returnAs: "bytes" })).toEqual(allBytes);
      expect(base32Parse(base32Stringify(allBytes), { returnAs: "bytes" })).toEqual(allBytes);
      expect(base64Stringify(Uint8Array.of(102))).toBe("Zg==");
      expect(base64Stringify(Uint8Array.of(102), { padding: false })).toBe("Zg");
      expect(base64Stringify(Uint8Array.from(FOOBAR), { alphabet: "base64url" })).toBe("Zm9vYmFy");
      expect(hexStringify(Uint8Array.of(104, 105))).toBe("6869");
    });
  });
}
