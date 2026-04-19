import { describe, it, expect } from "vitest";
import { secureCompare } from "../src/compare.ts";
import { textEncoder } from "../src/utils/index.ts";

describe.concurrent("secureCompare", () => {
  // Test cases for matching data
  it("should return true for identical strings", () => {
    const str1 = "secret_token_123";
    const str2 = "secret_token_123";
    expect(secureCompare(str1, str2)).toBe(true);
  });

  it("should return true for identical Uint8Arrays", () => {
    const arr1 = new Uint8Array([1, 2, 3, 4, 5]);
    const arr2 = new Uint8Array([1, 2, 3, 4, 5]);
    expect(secureCompare(arr1, arr2)).toBe(true);
  });

  it("should return true for matching string and Uint8Array", () => {
    const str = "hello world";
    const arr = textEncoder.encode("hello world");
    expect(secureCompare(str, arr)).toBe(true);
    expect(secureCompare(arr, str)).toBe(true);
  });

  // Test cases for non-matching data
  // TODO: measure time taken to complete execution
  it("should return false for different Uint8Arrays of same length", () => {
    const arr1 = new Uint8Array([1, 2, 3, 4, 5]);
    const arr2 = new Uint8Array([1, 2, 3, 4, 6]);
    expect(secureCompare(arr1, arr2)).toBe(false);
  });

  it("should return false for different Uint8Arrays of different lengths (expected shorter)", () => {
    const arr1 = new Uint8Array([1, 2, 3]);
    const arr2 = new Uint8Array([1, 2, 3, 4]);
    expect(secureCompare(arr1, arr2)).toBe(false);
  });

  it("should return false for different Uint8Arrays of different lengths (received shorter)", () => {
    const arr1 = new Uint8Array([1, 2, 3, 4]);
    const arr2 = new Uint8Array([1, 2, 3]);
    expect(secureCompare(arr1, arr2)).toBe(false);
  });

  it("should return false for different strings of same length", () => {
    const str1 = "abcde";
    const str2 = "abcdf";
    expect(secureCompare(str1, str2)).toBe(false);
  });

  it("should return false for different strings of different lengths (expected shorter)", () => {
    const str1 = "abc";
    const str2 = "abcd";
    expect(secureCompare(str1, str2)).toBe(false);
  });

  it("should return false for different strings of different lengths (received shorter)", () => {
    const str1 = "abcd";
    const str2 = "abc";
    expect(secureCompare(str1, str2)).toBe(false);
  });

  it("should return false for non-matching string and Uint8Array", () => {
    const str = "hello world";
    const arr = textEncoder.encode("hello worlD"); // Different case
    expect(secureCompare(str, arr)).toBe(false);
    expect(secureCompare(arr, str)).toBe(false);
  });

  it("should return false for string and Uint8Array with different lengths", () => {
    const str = "short";
    const arr = textEncoder.encode("longer");
    expect(secureCompare(str, arr)).toBe(false);
    expect(secureCompare(arr, str)).toBe(false);
  });

  // Test cases for undefined received
  it("should return false when received is undefined (string expected)", () => {
    const expected = "some_secure_value";
    expect(secureCompare(expected, undefined)).toBe(false);
  });

  it("should return false when received is undefined (Uint8Array expected)", () => {
    const expected = new Uint8Array([10, 20, 30]);
    expect(secureCompare(expected, undefined)).toBe(false);
  });

  // Test with special characters
  it("should correctly verify string vs Uint8Array with special characters", () => {
    const testString =
      "Hello, Vitest! 👋 This is a test string with some special characters: Ā 𐀀 文 +/=";
    const testUint8Array = new TextEncoder().encode(testString);

    expect(secureCompare(testString, testUint8Array)).toBe(true);
    expect(secureCompare(testUint8Array, testString)).toBe(true);

    expect(secureCompare(testString, testString + "x")).toBe(false);
    const modifiedUint8Array = new Uint8Array([...testUint8Array, 1]);
    expect(secureCompare(testUint8Array, modifiedUint8Array)).toBe(false);
  });

  // Empty / undefined expected — default behavior: return false, do not throw
  it("returns false when expected is undefined (default)", () => {
    expect(secureCompare(undefined, "test")).toBe(false);
  });

  it("returns false when expected is an empty string (default)", () => {
    expect(secureCompare("", "test")).toBe(false);
  });

  it("returns false when expected is an empty Uint8Array (default)", () => {
    expect(secureCompare(new Uint8Array(0), "test")).toBe(false);
  });

  it("still returns false (not true) when both expected and received are empty/undefined", () => {
    // Avoids the footgun where empty == empty could be read as "valid match".
    expect(secureCompare(undefined, undefined)).toBe(false);
    expect(secureCompare("", "")).toBe(false);
    expect(secureCompare(new Uint8Array(0), new Uint8Array(0))).toBe(false);
  });

  // Opt-in strict mode: throw on empty / undefined expected
  it("throws in strict mode when expected is undefined", () => {
    expect(() => secureCompare(undefined, "test", { strict: true })).toThrow(
      "Cannot verify. Expected value is empty or undefined.",
    );
  });

  it("throws in strict mode when expected is an empty string", () => {
    expect(() => secureCompare("", "test", { strict: true })).toThrow(
      "Cannot verify. Expected value is empty or undefined.",
    );
  });

  it("strict: false is equivalent to the default (returns false, does not throw)", () => {
    expect(secureCompare(undefined, "test", { strict: false })).toBe(false);
    expect(secureCompare("", "test", { strict: false })).toBe(false);
  });
});
