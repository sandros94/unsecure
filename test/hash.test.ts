import { describe, it, expect } from "vitest";
import { hash } from "../src/hash";

describe("hash utility", () => {
  const testString =
    "Hello, Vitest! 👋 This is a test string with some special characters: Ā 𐀀 文 +/=";
  const testUint8Array = new TextEncoder().encode(testString);

  // Known hash values for the `testString`
  const sha256Hex =
    "521cb0415f1a06428456d9ef4e948c0270a806442325253cb7a8a6b7e43da9c7";
  const sha384Hex =
    "ad34d79a7831c2ca6de3012696b9b25746cb7491f613bb6a3716d05de01f84bf180b5758bd3185fcea084ac9c2ba01b4";
  const sha512Hex =
    "0cd29c9881fc9dc562a8e8dace0598b62521d7030ecbc601083afd0e1c8f9c5795305462c232656c92a575fc2ab01a40bd6b10d7702428d533d76a927b428a3d";

  it("should hash a string using SHA-256 by default and return a hex string", async () => {
    const result = await hash(testString);
    expect(result).toBe(sha256Hex);
  });

  it("should hash a Uint8Array using SHA-256 by default and return a hex string", async () => {
    const result = await hash(testUint8Array);
    expect(result).toBe(sha256Hex);
  });

  it("should return a hex string when 'asString' is 'true'", async () => {
    const result = await hash(testString, { asString: true });
    expect(result).toBe(sha256Hex);
  });

  it("should return a Uint8Array when 'asString' is 'false'", async () => {
    const result = await hash(testString, { asString: false });
    expect(result).toBeInstanceOf(Uint8Array);

    // Verify the bytes by converting them to hex
    const hexResult = [...result]
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");
    expect(hexResult).toBe(sha256Hex);
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
      asString: false,
    });
    expect(result).toBeInstanceOf(Uint8Array);
    const hexResult = [...result]
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");
    expect(hexResult).toBe(sha512Hex);
  });

  it("should handle empty string input", async () => {
    const emptySha256 =
      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    const result = await hash("");
    expect(result).toBe(emptySha256);
  });

  it("should handle empty Uint8Array input", async () => {
    const emptySha256 =
      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    const result = await hash(new Uint8Array(0));
    expect(result).toBe(emptySha256);
  });
});
