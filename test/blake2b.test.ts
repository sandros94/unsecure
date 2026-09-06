import { describe, it, expect } from "vitest";
import { blake2b as nobleBlake2b } from "@noble/hashes/blake2.js";
import { blake2b, createBlake2b } from "../src/_internal/blake2b.ts";
import { hexStringify } from "../src/utils/index.ts";
import { expectUnsecureError } from "./_helpers.ts";

/** The KAT inputs are the byte string `00 01 02 … (n-1)`. */
function counting(length: number): Uint8Array {
  return Uint8Array.from({ length }, (_, i) => i);
}

/** The 64-byte key every keyed vector in the official KAT uses. */
const KEY = counting(64);

// https://github.com/BLAKE2/BLAKE2 `testvectors/blake2-kat.json`, unkeyed entries.
const UNKEYED: Record<number, string> = {
  0:
    "786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419" +
    "d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce",
  1:
    "2fa3f686df876995167e7c2e5d74c4c7b6e48f8068fe0e44208344d480f7904c" +
    "36963e44115fe3eb2a3ac8694c28bcb4f5a0f3276f2e79487d8219057a506e4b",
  2:
    "1c08798dc641aba9dee435e22519a4729a09b2bfe0ff00ef2dcd8ed6f8a07d15" +
    "eaf4aee52bbf18ab5608a6190f70b90486c8a7d4873710b1115d3debbb4327b5",
  31:
    "29f8b8c78c80f2fcb4bdf7825ed90a70d625ff785d262677e250c04f3720c888" +
    "d03f8045e4edf3f5285bd39d928a10a7d0a5df00b8484ac2868142a1e8bea351",
  128:
    "2319e3789c47e2daa5fe807f61bec2a1a6537fa03f19ff32e87eecbfd64b7e0e" +
    "8ccff439ac333b040f19b0c4ddd11a61e24ac1fe0f10a039806c5dcc0da3d115",
  255:
    "5b21c5fd8868367612474fa2e70e9cfa2201ffeee8fafab5797ad58fefa17c9b" +
    "5b107da4a3db6320baaf2c8617d5a51df914ae88da3867c2d41f0cc14fa67928",
};

// Same file, keyed entries (key = `00 01 … 3f`).
const KEYED: Record<number, string> = {
  0:
    "10ebb67700b1868efb4417987acf4690ae9d972fb7a590c2f02871799aaa4786" +
    "b5e996e8f0f4eb981fc214b005f42d2ff4233499391653df7aefcbc13fc51568",
  1:
    "961f6dd1e4dd30f63901690c512e78e4b45e4742ed197c3c5e45c549fd25f2e4" +
    "187b0bc9fe30492b16b0d0bc4ef9b0f34c7003fac09a5ef1532e69430234cebd",
  2:
    "da2cfbe2d8409a0f38026113884f84b50156371ae304c4430173d08a99d9fb1b" +
    "983164a3770706d537f49e0c916d9f32b95cc37a95b99d857436f0232c88a965",
  63:
    "bd965bf31e87d70327536f2a341cebc4768eca275fa05ef98f7f1b71a0351298" +
    "de006fba73fe6733ed01d75801b4a928e54231b38e38c562b2e33ea1284992fa",
  255:
    "142709d62e28fcccd0af97fad0f8465b971e82201dc51070faa0372aa43e9248" +
    "4be1c1e73ba10906d5d1853db6a4106e0a7bf9800d373d6dee2d46d62ef2a461",
};

describe.concurrent("blake2b (RFC 7693)", () => {
  it('matches the Appendix A vector for BLAKE2b-512("abc")', () => {
    expect(hexStringify(blake2b(new TextEncoder().encode("abc")))).toBe(
      "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d1" +
        "7d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923",
    );
  });

  for (const [length, expected] of Object.entries(UNKEYED)) {
    it(`matches the unkeyed KAT vector for a ${length}-byte input`, () => {
      expect(hexStringify(blake2b(counting(Number(length))))).toBe(expected);
    });
  }

  for (const [length, expected] of Object.entries(KEYED)) {
    it(`matches the keyed KAT vector for a ${length}-byte input`, () => {
      expect(hexStringify(blake2b(counting(Number(length)), 64, KEY))).toBe(expected);
    });
  }
});

describe.concurrent("blake2b API", () => {
  it("defaults to a 64-byte digest", () => {
    expect(blake2b(counting(10)).length).toBe(64);
  });

  it("produces the same digest whether the message arrives in one chunk or many", () => {
    const message = counting(300);
    const streamed = createBlake2b(64);
    for (let offset = 0; offset < message.length; offset += 37) {
      streamed.update(message.subarray(offset, offset + 37));
    }
    expect(hexStringify(streamed.digest())).toBe(hexStringify(blake2b(message)));
  });

  it("handles a message that lands exactly on the 128-byte block boundary", () => {
    for (const length of [127, 128, 129, 255, 256, 257]) {
      expect(hexStringify(blake2b(counting(length)))).toBe(
        hexStringify(nobleBlake2b(counting(length), { dkLen: 64 })),
      );
    }
  });

  it("agrees with @noble/hashes across output lengths", () => {
    for (const outLength of [1, 16, 20, 28, 32, 48, 63, 64]) {
      const message = counting(97);
      expect(hexStringify(blake2b(message, outLength))).toBe(
        hexStringify(nobleBlake2b(message, { dkLen: outLength })),
      );
    }
  });

  it("agrees with @noble/hashes for keyed digests", () => {
    for (const keyLength of [1, 16, 32, 64]) {
      const key = counting(keyLength);
      const message = counting(200);
      expect(hexStringify(blake2b(message, 32, key))).toBe(
        hexStringify(nobleBlake2b(message, { dkLen: 32, key })),
      );
    }
  });

  it("throws on an out-of-range output length", () => {
    const message = "blake2b: outLength must be an integer between 1 and 64.";
    expectUnsecureError(() => blake2b(counting(4), 0), "OUT_OF_RANGE", message);
    expectUnsecureError(() => blake2b(counting(4), 65), "OUT_OF_RANGE", message);
    expectUnsecureError(() => blake2b(counting(4), 32.5), "OUT_OF_RANGE", message);
  });

  it("throws on an over-long key", () => {
    expectUnsecureError(
      () => blake2b(counting(4), 64, counting(65)),
      "OUT_OF_RANGE",
      "blake2b: key must be at most 64 bytes.",
    );
  });
});
