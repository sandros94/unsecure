import { type MockInstance, describe, it, expect, beforeAll, afterAll, vi } from "vitest";
import type { Base32Alphabet, Base64Alphabet } from "../src/utils/index.ts";
import { UnsecureError } from "../src/errors.ts";

// The codecs pick a bulk decoder from what the runtime offers: Node's
// `Buffer`, the TC39 `Uint8Array` methods, or a hand-rolled loop. Which one
// runs must be invisible, so the same table is asserted against literal bytes
// with `Buffer` stubbed out and left in place. The `native-base64` project
// runs this file again with the TC39 methods enabled, covering the four
// combinations between them.

type Codec = "hex" | "base64" | "base32";

/** Bytes on success; the whole `MALFORMED` message on failure. */
type Outcome = readonly number[] | { readonly syntaxError: string };

/** A strict decode that must fail with exactly this message, on any backend. */
function throws(message: string): Outcome {
  return { syntaxError: message };
}

interface Vector {
  readonly codec: Codec;
  readonly text: string;
  readonly alphabet?: string;
  readonly strict: Outcome;
  readonly loose: readonly number[];
}

const FOO = [102, 111, 111] as const;
const FOOBAR = [102, 111, 111, 98, 97, 114] as const;

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
  {
    codec: "base64",
    text: "Zh==",
    strict: throws("Base64.parse: the last base64 symbol sets bits past the final byte."),
    loose: [102],
  },
  {
    codec: "base64",
    text: "Zh",
    strict: throws("Base64.parse: the last base64 symbol sets bits past the final byte."),
    loose: [102],
  },
  // Padding present but not the count the length calls for.
  {
    codec: "base64",
    text: "Zm9vYg=",
    strict: throws('Base64.parse: expected 2 "=" padding characters, found 1.'),
    loose: [102, 111, 111, 98],
  },
  {
    codec: "base64",
    text: "Zm9vYmFy=",
    strict: throws('Base64.parse: unexpected "=" padding.'),
    loose: FOOBAR,
  },
  {
    codec: "base64",
    text: "====",
    strict: throws('Base64.parse: unexpected "=" padding.'),
    loose: [],
  },
  {
    codec: "base64",
    text: "Zg=Zg==",
    strict: throws('Base64.parse: invalid base64 character "=" at index 2.'),
    loose: [102, 6, 96],
  },
  // A trailing symbol that cannot start a byte.
  {
    codec: "base64",
    text: "Zm9vY",
    strict: throws("Base64.parse: 5 base64 symbols cannot encode whole bytes."),
    loose: FOO,
  },
  {
    codec: "base64",
    text: "Zm 9v",
    strict: throws('Base64.parse: invalid base64 character " " at index 2.'),
    loose: FOO,
  },
  {
    codec: "base64",
    text: "Zg=@",
    strict: throws('Base64.parse: invalid base64 character "=" at index 2.'),
    loose: [102],
  },
  {
    codec: "base64",
    text: "!!!",
    strict: throws('Base64.parse: invalid base64 character "!" at index 0.'),
    loose: [],
  },
  // Alphabets are enforced in strict, folded in loose.
  {
    codec: "base64",
    text: "Zm9v-A",
    strict: throws('Base64.parse: invalid base64 character "-" at index 4.'),
    loose: [102, 111, 111, 248],
  },
  { codec: "base64", text: "+/8=", strict: [0xfb, 0xff], loose: [0xfb, 0xff] },
  {
    codec: "base64",
    text: "-_8",
    alphabet: "base64url",
    strict: [0xfb, 0xff],
    loose: [0xfb, 0xff],
  },
  {
    codec: "base64",
    text: "+/8=",
    alphabet: "base64url",
    strict: throws('Base64.parse: invalid base64 character "+" at index 0.'),
    loose: [0xfb, 0xff],
  },

  { codec: "base32", text: "", strict: [], loose: [] },
  { codec: "base32", text: "MZXW6YTBOI======", strict: FOOBAR, loose: FOOBAR },
  { codec: "base32", text: "MZXW6===", strict: FOO, loose: FOO },
  { codec: "base32", text: "MZXW6", strict: FOO, loose: FOO },
  {
    codec: "base32",
    text: "MZXW7===",
    strict: throws("Base32.parse: the last base32 symbol sets bits past the final byte."),
    loose: FOO,
  },
  {
    codec: "base32",
    text: "MZ=XW6===",
    strict: throws('Base32.parse: invalid base32 character "=" at index 2.'),
    loose: FOO,
  },
  {
    codec: "base32",
    text: "MZXW6=",
    strict: throws('Base32.parse: expected 3 "=" padding characters, found 1.'),
    loose: FOO,
  },
  {
    codec: "base32",
    text: "MZXW 6",
    strict: throws('Base32.parse: invalid base32 character " " at index 4.'),
    loose: FOO,
  },
  {
    codec: "base32",
    text: "M",
    strict: throws("Base32.parse: 1 base32 symbols cannot encode whole bytes."),
    loose: [],
  },
  {
    codec: "base32",
    text: "========",
    strict: throws('Base32.parse: unexpected "=" padding.'),
    loose: [],
  },
  {
    codec: "base32",
    text: "mzxw6===",
    strict: throws('Base32.parse: invalid base32 character "m" at index 0.'),
    loose: FOO,
  },
  { codec: "base32", text: "CPNMU===", alphabet: "base32hex", strict: FOO, loose: FOO },
  {
    codec: "base32",
    text: "cpnmu===",
    alphabet: "base32hex",
    strict: throws('Base32.parse: invalid base32 character "c" at index 0.'),
    loose: FOO,
  },
  { codec: "base32", text: "OO", alphabet: "crockford", strict: [0], loose: [0] },
  { codec: "base32", text: "oo", alphabet: "crockford", strict: [0], loose: [0] },

  { codec: "hex", text: "", strict: [], loose: [] },
  { codec: "hex", text: "666f6f", strict: FOO, loose: FOO },
  { codec: "hex", text: "666F6F", strict: FOO, loose: FOO },
  {
    codec: "hex",
    text: "666f6",
    strict: throws("Hex.parse: 5 hexadecimal characters cannot encode whole bytes."),
    loose: [102, 111],
  },
  {
    codec: "hex",
    text: "66 6f 6f",
    strict: throws('Hex.parse: invalid hexadecimal character " " at index 2.'),
    loose: FOO,
  },
  {
    codec: "hex",
    text: "zz666f6f",
    strict: throws('Hex.parse: invalid hexadecimal character "z" at index 0.'),
    loose: FOO,
  },
  {
    codec: "hex",
    text: "666f6fzz",
    strict: throws('Hex.parse: invalid hexadecimal character "z" at index 6.'),
    loose: FOO,
  },
  {
    codec: "hex",
    text: "66:6f:6f",
    strict: throws('Hex.parse: invalid hexadecimal character ":" at index 2.'),
    loose: FOO,
  },
  // Loose drops non-digits, not "prefixes": the 0 of "0x" is a hex digit.
  {
    codec: "hex",
    text: "0x66",
    strict: throws('Hex.parse: invalid hexadecimal character "x" at index 1.'),
    loose: [0x06],
  },
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

/**
 * Compare success and failure in one shape, so neither needs a branch in a
 * test. The error class comes from the caller: each backend runs against a
 * module registry of its own, so the class the codecs threw is not the one a
 * static import of this file holds.
 */
function outcome(
  run: () => Uint8Array,
  errorClass: typeof UnsecureError,
): Outcome | { readonly unexpected: string } {
  try {
    return [...run()];
  } catch (error) {
    if (error instanceof errorClass && error.code === "MALFORMED") {
      return { syntaxError: error.message };
    }
    return { unexpected: String(error) };
  }
}

for (const withBuffer of [true, false]) {
  describe(`codec backends — Buffer ${withBuffer ? "present" : "absent"}`, () => {
    let codecs: Codecs;
    let errorClass: typeof UnsecureError;

    beforeAll(async () => {
      if (!withBuffer) vi.stubGlobal("Buffer", undefined);
      vi.resetModules();
      codecs = await import("../src/utils/index.ts");
      ({ UnsecureError: errorClass } = await import("../src/errors.ts"));
    });

    afterAll(() => {
      vi.unstubAllGlobals();
      vi.resetModules();
    });

    for (const vector of VECTORS) {
      const name = `${vector.codec} ${vector.alphabet ?? "default"} ${JSON.stringify(vector.text)}`;
      // oxlint-disable-next-line vitest/valid-title
      it(name, () => {
        expect(outcome(() => decode(codecs, vector, false), errorClass)).toEqual(vector.strict);
        expect(outcome(() => decode(codecs, vector, true), errorClass)).toEqual(vector.loose);
      });
    }

    it("encodes a view that does not start at its buffer", () => {
      const backing = Uint8Array.of(1, 2, 3, 4);
      const { base32Stringify, base64Stringify, hexStringify } = codecs;
      for (const view of [
        new Uint8Array(backing.buffer, 1, 2),
        backing.subarray(1, 3),
        new DataView(backing.buffer, 1, 2),
      ]) {
        expect(hexStringify(view)).toBe("0203");
        expect(base64Stringify(view)).toBe("AgM=");
        expect(base32Stringify(view)).toBe("AIBQ====");
      }
    });

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

// Where `Buffer` and the TC39 methods coexist, the input size decides which
// one does the bulk work: the TC39 method up to 64 bytes, `Buffer` above. The
// fakes below stand in for the TC39 methods so the choice is observable on a
// runtime that lacks them, and so it can be removed on one that has them.

type NativeName = "toHex" | "toBase64" | "fromHex" | "fromBase64";

const HEX_OF_BYTE = Array.from({ length: 256 }, (_, i) => (i + 0x100).toString(16).slice(1));

/** Install counting stand-ins for the TC39 methods, or remove the real ones. */
function stubNatives(
  present: boolean,
  honourViews = true,
): { calls: Record<NativeName, number>; restore(): void } {
  // A stand-in that reads from the start of the backing buffer, as a runtime
  // that ignores the view would.
  const read = (view: Uint8Array): Uint8Array => (honourViews ? view : new Uint8Array(view.buffer));
  const calls: Record<NativeName, number> = { toHex: 0, toBase64: 0, fromHex: 0, fromBase64: 0 };
  const targets: ReadonlyArray<readonly [object, NativeName, unknown]> = [
    [
      Uint8Array.prototype,
      "toHex",
      function (this: Uint8Array): string {
        calls.toHex++;
        return Array.from(read(this), (byte) => HEX_OF_BYTE[byte]).join("");
      },
    ],
    [
      Uint8Array.prototype,
      "toBase64",
      function (this: Uint8Array, options?: { alphabet?: string; omitPadding?: boolean }): string {
        calls.toBase64++;
        let text = btoa(Array.from(read(this), (byte) => String.fromCharCode(byte)).join(""));
        if (options?.alphabet === "base64url") text = text.replace(/\+/g, "-").replace(/\//g, "_");
        return options?.omitPadding ? text.replace(/=+$/, "") : text;
      },
    ],
    [
      Uint8Array,
      "fromHex",
      (text: string): Uint8Array => {
        calls.fromHex++;
        return Uint8Array.from({ length: text.length / 2 }, (_, i) =>
          Number.parseInt(text.slice(i * 2, i * 2 + 2), 16),
        );
      },
    ],
    [
      Uint8Array,
      "fromBase64",
      (text: string): Uint8Array => {
        calls.fromBase64++;
        return Uint8Array.from(atob(text), (char) => char.charCodeAt(0));
      },
    ],
  ];
  const saved = targets.map(([target, name]) => Object.getOwnPropertyDescriptor(target, name));
  for (const [target, name, value] of targets) {
    Object.defineProperty(target, name, {
      configurable: true,
      writable: true,
      value: present ? value : undefined,
    });
  }
  return {
    calls,
    restore() {
      targets.forEach(([target, name], i) => {
        const descriptor = saved[i];
        if (descriptor === undefined) delete (target as Record<string, unknown>)[name];
        else Object.defineProperty(target, name, descriptor);
      });
    },
  };
}

/** Which backend each size must land on. */
interface Expectation {
  readonly native: boolean;
  readonly buffer: boolean;
}

const SIZES: ReadonlyArray<readonly [label: string, length: number]> = [
  ["64 bytes", 64],
  ["65 bytes", 65],
];

const BACKENDS: ReadonlyArray<{
  readonly name: string;
  readonly withBuffer: boolean;
  readonly withNative: boolean;
  readonly expect: Readonly<Record<number, Expectation>>;
}> = [
  {
    name: "both present",
    withBuffer: true,
    withNative: true,
    expect: { 64: { native: true, buffer: false }, 65: { native: false, buffer: true } },
  },
  {
    name: "Buffer only",
    withBuffer: true,
    withNative: false,
    expect: { 64: { native: false, buffer: true }, 65: { native: false, buffer: true } },
  },
  {
    name: "TC39 methods only",
    withBuffer: false,
    withNative: true,
    expect: { 64: { native: true, buffer: false }, 65: { native: true, buffer: false } },
  },
];

for (const backend of BACKENDS) {
  describe(`codec backend selection — ${backend.name}`, () => {
    let codecs: Codecs;
    let natives: ReturnType<typeof stubNatives>;
    let bufferFrom: MockInstance<typeof Buffer.from> | undefined;

    beforeAll(async () => {
      natives = stubNatives(backend.withNative);
      if (backend.withBuffer) bufferFrom = vi.spyOn(Buffer, "from");
      else vi.stubGlobal("Buffer", undefined);
      vi.resetModules();
      codecs = await import("../src/utils/index.ts");
    });

    afterAll(() => {
      natives.restore();
      vi.unstubAllGlobals();
      vi.restoreAllMocks();
      vi.resetModules();
    });

    for (const [label, length] of SIZES) {
      const wanted = backend.expect[length]!;
      const bytes = Uint8Array.from({ length }, (_, i) => (i * 37 + 11) & 0xff);
      const hex = Array.from(bytes, (byte) => HEX_OF_BYTE[byte]).join("");
      const b64 = btoa(Array.from(bytes, (byte) => String.fromCharCode(byte)).join(""));

      const check = (name: NativeName, run: () => void): void => {
        natives.calls[name] = 0;
        bufferFrom?.mockClear();
        run();
        expect(natives.calls[name] > 0, `${name} used`).toBe(wanted.native);
        expect((bufferFrom?.mock.calls.length ?? 0) > 0, "Buffer used").toBe(wanted.buffer);
      };

      it(`routes ${label} of hex`, () => {
        check("toHex", () => expect(codecs.hexStringify(bytes)).toBe(hex));
        check("fromHex", () => expect(codecs.hexParse(hex, { returnAs: "bytes" })).toEqual(bytes));
      });

      it(`routes ${label} of base64`, () => {
        check("toBase64", () => expect(codecs.base64Stringify(bytes)).toBe(b64));
        check("fromBase64", () =>
          expect(codecs.base64Parse(b64, { returnAs: "bytes" })).toEqual(bytes),
        );
      });
    }
  });
}

describe("codec backend selection — TC39 methods that ignore a view's offset", () => {
  let codecs: Codecs;
  let natives: ReturnType<typeof stubNatives>;

  beforeAll(async () => {
    natives = stubNatives(true, false);
    vi.stubGlobal("Buffer", undefined);
    vi.resetModules();
    codecs = await import("../src/utils/index.ts");
  });

  afterAll(() => {
    natives.restore();
    vi.unstubAllGlobals();
    vi.resetModules();
  });

  it("still encodes the view, not its buffer", () => {
    const backing = Uint8Array.of(1, 2, 3, 4);
    const view = backing.subarray(1, 3);
    expect(codecs.hexStringify(view)).toBe("0203");
    expect(codecs.base64Stringify(view)).toBe("AgM=");
    expect(natives.calls.toHex).toBeGreaterThan(0);
    expect(natives.calls.toBase64).toBeGreaterThan(0);
  });
});
