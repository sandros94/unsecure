import { describe, it, expect } from "vitest";
import { UnsecureError } from "../src/errors.ts";
import * as api from "../src/index.ts";

describe.concurrent("UnsecureError", () => {
  it("is an Error with the library's name", () => {
    const error = new UnsecureError("INVALID_TYPE", "x: boom.");
    expect(error).toBeInstanceOf(Error);
    expect(error).toBeInstanceOf(UnsecureError);
    expect(error.name).toBe("UnsecureError");
  });

  it("carries the code it was constructed with", () => {
    expect(new UnsecureError("OUT_OF_RANGE", "x: boom.").code).toBe("OUT_OF_RANGE");
    expect(new UnsecureError("PLATFORM", "x: boom.").code).toBe("PLATFORM");
  });

  it("leaves the message untouched", () => {
    const message = "hkdf: length must be an integer between 1 and 8160, got 0.";
    expect(new UnsecureError("OUT_OF_RANGE", message).message).toBe(message);
  });

  it("passes cause through to Error", () => {
    const cause = new DOMException("NotSupportedError");
    const error = new UnsecureError("PLATFORM", "x: boom.", { cause });
    expect(error.cause).toBe(cause);
  });

  it("has no cause when none was given", () => {
    expect("cause" in new UnsecureError("MALFORMED", "x: boom.")).toBe(false);
  });

  it("reads as its name in a stack trace", () => {
    const error = new UnsecureError("FROZEN", "x: boom.");
    expect(String(error)).toBe("UnsecureError: x: boom.");
    expect(error.stack?.startsWith("UnsecureError: x: boom.")).toBe(true);
  });
});

/**
 * One representative bad input per public function. The point is not the code
 * — the module suites cover those — but that nothing in the library can go
 * back to throwing a native class without a test noticing.
 */
describe("every public function throws UnsecureError", () => {
  const syncCases: Array<[string, () => unknown]> = [
    ["secureCompare", () => api.secureCompare(42 as any, "x")],
    ["secureGenerate", () => api.secureGenerate({ length: 0 })],
    ["generateOTPSecret", () => api.generateOTPSecret(0)],
    ["otpauthURI", () => api.otpauthURI({ type: "nope" as any, secret: "JBSWY3DP", account: "a" })],
    ["secureRandomNumber", () => api.secureRandomNumber(0)],
    ["secureRandomBytes", () => api.secureRandomBytes(-1)],
    ["createSecureRandomGenerator().next", () => api.createSecureRandomGenerator().next(0)],
    ["randomJitter", () => api.randomJitter(-1)],
    [
      "sanitizeObject",
      () => api.sanitizeObject(Object.freeze(JSON.parse('{"__proto__": {"x": 1}}'))),
    ],
    ["safeJsonParse", () => api.safeJsonParse("not json")],
    ["uuidv7", () => api.uuidv7(-1)],
    ["secureUUID", () => api.secureUUID(-1)],
    ["createUUIDv7Generator().next", () => api.createUUIDv7Generator().next(-1)],
    ["uuidv7Timestamp", () => api.uuidv7Timestamp("not-a-uuid")],
    ["hexStringify", () => api.hexStringify(null as any)],
    ["hexParse", () => api.hexParse("zz")],
    ["base64Stringify", () => api.base64Stringify(null as any)],
    ["base64Parse", () => api.base64Parse("Zg=@")],
    ["base32Stringify", () => api.base32Stringify(null as any)],
    ["base32Parse", () => api.base32Parse("M")],
    ["Hex.parse", () => api.Hex.parse("zz")],
    ["Base64.parse", () => api.Base64.parse("Zg=@")],
    ["Base32.parse", () => api.Base32.parse("M")],
  ];

  const asyncCases: Array<[string, () => Promise<unknown>]> = [
    ["hash", () => api.hash("d", { algorithm: "SHA-3" as any })],
    ["hmac", () => api.hmac("", "d")],
    ["hmacVerify", () => api.hmacVerify("", "d", "00")],
    ["hkdf", () => api.hkdf("i", { length: 0 })],
    ["hotp", () => api.hotp("", 0)],
    ["hotpVerify", () => api.hotpVerify("", "755224", 0)],
    ["totp", () => api.totp("")],
    ["totpVerify", () => api.totpVerify("", "755224")],
  ];

  for (const [name, call] of syncCases) {
    it(`${name} throws UnsecureError`, () => {
      assertLibraryError(thrownBy(call));
    });
  }

  for (const [name, call] of asyncCases) {
    it(`${name} rejects with UnsecureError`, async () => {
      assertLibraryError(
        await call().then(
          () => undefined,
          (reason: unknown) => reason,
        ),
      );
    });
  }
});

function thrownBy(call: () => unknown): unknown {
  try {
    call();
  } catch (error) {
    return error;
  }
  return undefined;
}

/**
 * `toBeInstanceOf` accepts any subclass, and the library has none: what a
 * public function throws must be this class exactly, or something native has
 * crept back in.
 */
function assertLibraryError(error: unknown): void {
  expect(error).toBeInstanceOf(UnsecureError);
  expect((error as Error).constructor).toBe(UnsecureError);
  expect((error as Error).name).toBe("UnsecureError");
}
