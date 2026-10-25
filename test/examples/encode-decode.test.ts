import { describe, expect, it } from "vitest";
import { UnsecureError } from "unsecure/errors";
import { Hex, base32Parse, base64Parse, hexParse, hexStringify } from "unsecure/utils";
import {
  decodeSessionId,
  encodeSessionId,
  normalizeLicenseKey,
} from "../../examples/safety/encode-decode.ts";

function codeOf(run: () => unknown): string | undefined {
  try {
    run();
  } catch (error) {
    if (error instanceof UnsecureError) return error.code;
    throw error;
  }
  return undefined;
}

describe("examples/safety/encode-decode", () => {
  it("round-trips a session id as unpadded base64url", () => {
    const id = crypto.getRandomValues(new Uint8Array(32));
    const cookie = encodeSessionId(id);
    expect(cookie).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(decodeSessionId(cookie)).toEqual(id);
  });

  it("returns null for every other spelling and for a missing cookie", () => {
    const id = new Uint8Array(32).fill(0xfb);
    const cookie = encodeSessionId(id);
    expect(decodeSessionId(undefined)).toBeNull();
    expect(decodeSessionId(`${cookie}=`)).toBeNull();
    expect(decodeSessionId(cookie.replace(/-/g, "+").replace(/_/g, "/"))).toBeNull();
    expect(decodeSessionId(` ${cookie}`)).toBeNull();
    expect(decodeSessionId(encodeSessionId(new Uint8Array(31)))).toBeNull();
  });

  it("normalizes a typed license key to one canonical spelling", () => {
    const key = "7ZQ4M2KD9XHT3WVR1B8NCPFG";
    expect(normalizeLicenseKey(key)).toBe(key);
    expect(normalizeLicenseKey("7zq4-m2kd 9xht-3wvr ib8n-cpfg")).toBe(key);
    expect(normalizeLicenseKey("7ZQ4-M2KD-9XHT")).toBeNull();
    expect(normalizeLicenseKey("7ZQ4-M2KD-9XHT-3WVR-1B8N-CPF!")).toBeNull();
  });

  it("matches the return values the page shows", () => {
    expect(hexStringify("hello")).toBe("68656c6c6f");
    expect(Hex.stringify).toBe(hexStringify);
    expect(base64Parse("aGVsbG8=")).toBe("hello");
    expect(base64Parse("aGVsbG8=", { returnAs: "bytes" })).toEqual(
      new Uint8Array([104, 101, 108, 108, 111]),
    );
  });

  it("shows the failure rows the page lists", () => {
    expect(codeOf(() => base64Parse("aGVs bG8="))).toBe("MALFORMED");
    expect(codeOf(() => base64Parse("aGVsbG9="))).toBe("MALFORMED");
    expect(codeOf(() => base64Parse("/w=="))).toBe("MALFORMED");
    expect(base64Parse("/w==", { loose: true })).toBe("�");
    expect(codeOf(() => base64Parse(null as never))).toBe("INVALID_TYPE");
    expect(codeOf(() => base32Parse("mzxw6ytboi"))).toBe("MALFORMED");
    expect(codeOf(() => base32Parse("MZXW6YTBOI", { alphabet: "ABC" }))).toBe("OUT_OF_RANGE");
    expect(codeOf(() => base64Parse("aGVsbG8=", { alphabet: "base64url", padding: false }))).toBe(
      "MALFORMED",
    );
  });

  it("strict hex and Crockford still accept more than one spelling", () => {
    expect(hexParse("DEAD", { returnAs: "bytes" })).toEqual(
      hexParse("dead", { returnAs: "bytes" }),
    );
    expect(base32Parse("csqpyrk1e8", { alphabet: "crockford" })).toBe("foobar");
    expect(base32Parse("CSQPYRKIE8", { alphabet: "crockford" })).toBe("foobar");
  });
});
