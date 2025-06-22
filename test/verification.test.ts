import { describe, it, expect } from "vitest";
import { secureVerify } from "../src/verification";
import { textEncoder } from "../src/utils";

describe.concurrent("secureVerify", () => {
  // Test cases for matching data
  it("should return true for identical strings", () => {
    const str1 = "secret_token_123";
    const str2 = "secret_token_123";
    expect(secureVerify(str1, str2)).toBe(true);
  });

  it("should return true for identical Uint8Arrays", () => {
    const arr1 = new Uint8Array([1, 2, 3, 4, 5]);
    const arr2 = new Uint8Array([1, 2, 3, 4, 5]);
    expect(secureVerify(arr1, arr2)).toBe(true);
  });

  it("should return true for matching string and Uint8Array", () => {
    const str = "hello world";
    const arr = textEncoder.encode("hello world");
    expect(secureVerify(str, arr)).toBe(true);
    expect(secureVerify(arr, str)).toBe(true);
  });

  // Test cases for non-matching data
  // TODO: measure time taken to complete execution
  it("should return false for different Uint8Arrays of same length", () => {
    const arr1 = new Uint8Array([1, 2, 3, 4, 5]);
    const arr2 = new Uint8Array([1, 2, 3, 4, 6]);
    expect(secureVerify(arr1, arr2)).toBe(false);
  });

  it("should return false for different Uint8Arrays of different lengths (reference shorter)", () => {
    const arr1 = new Uint8Array([1, 2, 3]);
    const arr2 = new Uint8Array([1, 2, 3, 4]);
    expect(secureVerify(arr1, arr2)).toBe(false);
  });

  it("should return false for different Uint8Arrays of different lengths (incoming shorter)", () => {
    const arr1 = new Uint8Array([1, 2, 3, 4]);
    const arr2 = new Uint8Array([1, 2, 3]);
    expect(secureVerify(arr1, arr2)).toBe(false);
  });

  it("should return false for different strings of same length", () => {
    const str1 = "abcde";
    const str2 = "abcdf";
    expect(secureVerify(str1, str2)).toBe(false);
  });

  it("should return false for different strings of different lengths (reference shorter)", () => {
    const str1 = "abc";
    const str2 = "abcd";
    expect(secureVerify(str1, str2)).toBe(false);
  });

  it("should return false for different strings of different lengths (incoming shorter)", () => {
    const str1 = "abcd";
    const str2 = "abc";
    expect(secureVerify(str1, str2)).toBe(false);
  });

  it("should return false for non-matching string and Uint8Array", () => {
    const str = "hello world";
    const arr = textEncoder.encode("hello worlD"); // Different case
    expect(secureVerify(str, arr)).toBe(false);
    expect(secureVerify(arr, str)).toBe(false);
  });

  it("should return false for string and Uint8Array with different lengths", () => {
    const str = "short";
    const arr = textEncoder.encode("longer");
    expect(secureVerify(str, arr)).toBe(false);
    expect(secureVerify(arr, str)).toBe(false);
  });

  // Test cases for undefined incoming
  it("should return false when incoming is undefined (string reference)", () => {
    const reference = "some_secure_value";
    expect(secureVerify(reference, undefined)).toBe(false);
  });

  it("should return false when incoming is undefined (Uint8Array reference)", () => {
    const reference = new Uint8Array([10, 20, 30]);
    expect(secureVerify(reference, undefined)).toBe(false);
  });

  // Test with special characters
  it("should correctly verify string vs Uint8Array with special characters", () => {
    const testString =
      "Hello, Vitest! 👋 This is a test string with some special characters: Ā 𐀀 文 +/=";
    const testUint8Array = new TextEncoder().encode(testString);

    expect(secureVerify(testString, testUint8Array)).toBe(true);
    expect(secureVerify(testUint8Array, testString)).toBe(true);

    expect(secureVerify(testString, testString + "x")).toBe(false);
    const modifiedUint8Array = new Uint8Array([...testUint8Array, 1]);
    expect(secureVerify(testUint8Array, modifiedUint8Array)).toBe(false);
  });

  // Test errors
  it("should throw an error when reference is undefined", () => {
    // @ts-expect-error
    expect(() => secureVerify(undefined, "test")).toThrow(
      "Cannot verify. Reference is undefined.",
    );
  });
});
