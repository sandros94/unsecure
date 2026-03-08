import { describe, it, expect } from "vitest";
import { hash } from "../src/hash.ts";
import { hexEncode, base64Encode, base64UrlEncode } from "../src/utils.ts";

describe("hash utility", () => {
  const testString =
    "Hello, Vitest! 👋 This is a test string with some special characters: Ā 𐀀 文 +/=";
  const testUint8Array = new TextEncoder().encode(testString);

  // Known hash values for the `testString`
  const sha256 = new Uint8Array([
    82, 28, 176, 65, 95, 26, 6, 66, 132, 86, 217, 239, 78, 148, 140, 2, 112, 168, 6, 68, 35, 37, 37,
    60, 183, 168, 166, 183, 228, 61, 169, 199,
  ]);
  const sha256Hex = hexEncode(sha256);
  const sha256Base64 = base64Encode(sha256);
  const sha256Base64Url = base64UrlEncode(sha256);
  const sha1Hex = "e2cb0ebe7cfd01ff810f5c3ef321bd6779d1f05f";
  const sha384Hex =
    "ad34d79a7831c2ca6de3012696b9b25746cb7491f613bb6a3716d05de01f84bf180b5758bd3185fcea084ac9c2ba01b4";
  const sha512Hex =
    "0cd29c9881fc9dc562a8e8dace0598b62521d7030ecbc601083afd0e1c8f9c5795305462c232656c92a575fc2ab01a40bd6b10d7702428d533d76a927b428a3d";

  it("should hash a string using SHA-256 by default and return a hex string", async () => {
    const result = await hash(testString);
    expect(result).toBe(sha256Hex);
  });

  it("should hash a Uint8Array using SHA-256 by default and return a Uint8Array", async () => {
    const result = await hash(testUint8Array);
    expect(result).toBeInstanceOf(Uint8Array);
    expect(result).toStrictEqual(sha256);
  });

  it("should return a hex string when 'returnAs' is 'hex'", async () => {
    const result = await hash(testString, { returnAs: "hex" });
    expect(result).toBe(sha256Hex);
  });

  it("should return a hex string when 'returnAs' is 'base64'", async () => {
    const result = await hash(testString, { returnAs: "base64" });
    expect(result).toBe(sha256Base64);
  });

  it("should return a hex string when 'returnAs' is 'base64url'", async () => {
    const result = await hash(testString, { returnAs: "base64url" });
    expect(result).toBe(sha256Base64Url);
  });

  it("should return a Uint8Array when 'returnAs' is 'uint8array'", async () => {
    const result = await hash(testString, { returnAs: "uint8array" });

    expect(result).toBeInstanceOf(Uint8Array);
    expect(result).toStrictEqual(sha256);
  });

  it("should hash using SHA-1 when specified", async () => {
    const result = await hash(testString, { algorithm: "SHA-1" });
    expect(result).toBe(sha1Hex);
    // SHA-1 = 20 bytes = 40 hex chars
    expect(result.length).toBe(40);
  });

  it("should hash Uint8Array using SHA-1 and return bytes", async () => {
    const result = await hash(testUint8Array, { algorithm: "SHA-1" });
    expect(result).toBeInstanceOf(Uint8Array);
    expect(result.length).toBe(20);
    const hex = [...result].map((b) => b.toString(16).padStart(2, "0")).join("");
    expect(hex).toBe(sha1Hex);
  });

  it("should hash using SHA-384 when specified", async () => {
    const result = await hash(testString, { algorithm: "SHA-384" });
    expect(result).toBe(sha384Hex);
  });

  it("should hash using SHA-512 when specified", async () => {
    const result = await hash(testString, { algorithm: "SHA-512" });
    expect(result).toBe(sha512Hex);
  });

  it("should hash using SHA-512 and return bytes when specified", async () => {
    const result = await hash(testString, {
      algorithm: "SHA-512",
      returnAs: "uint8array",
    });
    expect(result).toBeInstanceOf(Uint8Array);
    const hexResult = [...result].map((b) => b.toString(16).padStart(2, "0")).join("");
    expect(hexResult).toBe(sha512Hex);
  });

  it("should handle empty string input", async () => {
    const emptySha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    const result = await hash("");
    expect(result).toBe(emptySha256);
  });

  it("should handle empty Uint8Array input", async () => {
    const emptySha256Bytes = new Uint8Array([
      227, 176, 196, 66, 152, 252, 28, 20, 154, 251, 244, 200, 153, 111, 185, 36, 39, 174, 65, 228,
      100, 155, 147, 76, 164, 149, 153, 27, 120, 82, 184, 85,
    ]);
    const result = await hash(new Uint8Array(0));
    expect(result).toBeInstanceOf(Uint8Array);
    expect(result).toStrictEqual(emptySha256Bytes);
  });

  it("should return hex string for Uint8Array input when returnAs is 'hex'", async () => {
    const result = await hash(testUint8Array, { returnAs: "hex" });
    expect(result).toBe(sha256Hex);
  });

  it("should return Uint8Array for string input when returnAs is 'uint8array'", async () => {
    const result = await hash(testString, { returnAs: "uint8array" });
    expect(result).toBeInstanceOf(Uint8Array);
    expect(result).toStrictEqual(sha256);
  });

  it("should return Uint8Array for Uint8Array input with only algorithm option", async () => {
    const result = await hash(testUint8Array, { algorithm: "SHA-256" });
    expect(result).toBeInstanceOf(Uint8Array);
    expect(result).toStrictEqual(sha256);
  });

  it("should return base64 string when returnAs is 'b64' alias", async () => {
    const result = await hash(testString, { returnAs: "b64" });
    expect(result).toBe(sha256Base64);
  });

  it("should return base64url string when returnAs is 'b64url' alias", async () => {
    const result = await hash(testString, { returnAs: "b64url" });
    expect(result).toBe(sha256Base64Url);
  });

  it("should return Uint8Array when returnAs is 'bytes' alias", async () => {
    const result = await hash(testString, { returnAs: "bytes" });
    expect(result).toBeInstanceOf(Uint8Array);
    expect(result).toStrictEqual(sha256);
  });

  it("should throw for unsupported returnAs", async () => {
    await expect(hash(testString, { returnAs: "unsupported" as any })).rejects.toThrow(
      'Unsupported hash "returnAs" option: unsupported',
    );
  });
});
