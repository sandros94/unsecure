import { describe, it, expect } from "vitest";
import { secureGenerate } from "../src/generate";

describe.concurrent("secureGenerate", () => {
  // Test case 1: Default options
  it("should generate a token with default options (length 16, all types)", () => {
    const token = secureGenerate();
    expect(token).toBeTypeOf("string");
    expect(token.length).toBe(16);

    // Check presence of default character types
    expect(hasCharsFromSet(token, "ABCDEFGHIJKLMNOPQRSTUVWXYZ")).toBe(true);
    expect(hasCharsFromSet(token, "abcdefghijklmnopqrstuvwxyz")).toBe(true);
    expect(hasCharsFromSet(token, "0123456789")).toBe(true);
    expect(hasCharsFromSet(token, "!@#$%^&*()_+{}:<>?|[];,./~-=")).toBe(true);
  });

  // Test case 2: Custom length
  it("should generate a token with a custom length", () => {
    const length = 20;
    const token = secureGenerate({ length });
    expect(token).toBeTypeOf("string");
    expect(token.length).toBe(length);

    // Check presence of default character types (since none were excluded)
    expect(hasCharsFromSet(token, "ABCDEFGHIJKLMNOPQRSTUVWXYZ")).toBe(true);
    expect(hasCharsFromSet(token, "abcdefghijklmnopqrstuvwxyz")).toBe(true);
    expect(hasCharsFromSet(token, "0123456789")).toBe(true);
    expect(hasCharsFromSet(token, "!@#$%^&*()_+{}:<>?|[];,./~-=")).toBe(true);
  });

  // Test case 3: Exclude specific character types
  it("should exclude uppercase letters when uppercase is false", () => {
    const token = secureGenerate({ uppercase: false });
    expect(token.length).toBe(16);
    expect(hasCharsFromSet(token, "ABCDEFGHIJKLMNOPQRSTUVWXYZ")).toBe(false);
    expect(hasCharsFromSet(token, "abcdefghijklmnopqrstuvwxyz")).toBe(true);
    expect(hasCharsFromSet(token, "0123456789")).toBe(true);
    expect(hasCharsFromSet(token, "!@#$%^&*()_+{}:<>?|[];,./~-=")).toBe(true);
  });

  it("should exclude lowercase letters when lowercase is false", () => {
    const token = secureGenerate({ lowercase: false });
    expect(token.length).toBe(16);
    expect(hasCharsFromSet(token, "abcdefghijklmnopqrstuvwxyz")).toBe(false);
    expect(hasCharsFromSet(token, "ABCDEFGHIJKLMNOPQRSTUVWXYZ")).toBe(true);
    expect(hasCharsFromSet(token, "0123456789")).toBe(true);
    expect(hasCharsFromSet(token, "!@#$%^&*()_+{}:<>?|[];,./~-=")).toBe(true);
  });

  it("should exclude numbers when numbers is false", () => {
    const token = secureGenerate({ numbers: false });
    expect(token.length).toBe(16);
    expect(hasCharsFromSet(token, "0123456789")).toBe(false);
    expect(hasCharsFromSet(token, "ABCDEFGHIJKLMNOPQRSTUVWXYZ")).toBe(true);
    expect(hasCharsFromSet(token, "abcdefghijklmnopqrstuvwxyz")).toBe(true);
    expect(hasCharsFromSet(token, "!@#$%^&*()_+{}:<>?|[];,./~-=")).toBe(true);
  });

  it("should exclude special characters when specials is false", () => {
    const token = secureGenerate({ specials: false });
    expect(token.length).toBe(16);
    expect(hasCharsFromSet(token, "!@#$%^&*()_+{}:<>?|[];,./~-=")).toBe(false);
    expect(hasCharsFromSet(token, "ABCDEFGHIJKLMNOPQRSTUVWXYZ")).toBe(true);
    expect(hasCharsFromSet(token, "abcdefghijklmnopqrstuvwxyz")).toBe(true);
    expect(hasCharsFromSet(token, "0123456789")).toBe(true);
  });

  it("should exclude multiple character types when set to false", () => {
    const token = secureGenerate({
      uppercase: false,
      numbers: false,
    });
    expect(token.length).toBe(16);
    expect(hasCharsFromSet(token, "ABCDEFGHIJKLMNOPQRSTUVWXYZ")).toBe(false);
    expect(hasCharsFromSet(token, "0123456789")).toBe(false);
    expect(hasCharsFromSet(token, "abcdefghijklmnopqrstuvwxyz")).toBe(true);
    expect(hasCharsFromSet(token, "!@#$%^&*()_+{}:<>?|[];,./~-=")).toBe(true);
  });

  // Test case 4: Include only specific character types
  it("should include only uppercase when other types are false", () => {
    const allowedSet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    const token = secureGenerate({
      uppercase: true,
      lowercase: false,
      numbers: false,
      specials: false,
    });
    expect(token.length).toBe(16);
    expect(hasCharsFromSet(token, allowedSet)).toBe(true); // Should contain at least one uppercase
    expect(containsOnlyCharsFromSet(token, allowedSet)).toBe(true);
  });

  it("should include only lowercase when other types are false", () => {
    const allowedSet = "abcdefghijklmnopqrstuvwxyz";
    const token = secureGenerate({
      uppercase: false,
      lowercase: true,
      numbers: false,
      specials: false,
    });
    expect(token.length).toBe(16);
    expect(hasCharsFromSet(token, allowedSet)).toBe(true); // Should contain at least one lowercase
    expect(containsOnlyCharsFromSet(token, allowedSet)).toBe(true);
  });

  it("should include only numbers when other types are false", () => {
    const allowedSet = "0123456789";
    const token = secureGenerate({
      uppercase: false,
      lowercase: false,
      numbers: true,
      specials: false,
    });
    expect(token.length).toBe(16);
    expect(hasCharsFromSet(token, allowedSet)).toBe(true); // Should contain at least one number
    expect(containsOnlyCharsFromSet(token, allowedSet)).toBe(true);
  });

  it("should include only specials when other types are false", () => {
    const allowedSet = "!@#$%^&*()_+{}:<>?|[];,./~-=";
    const token = secureGenerate({
      uppercase: false,
      lowercase: false,
      numbers: false,
      specials: true,
    });
    expect(token.length).toBe(16);
    expect(hasCharsFromSet(token, allowedSet)).toBe(true); // Should contain at least one special
    expect(containsOnlyCharsFromSet(token, allowedSet)).toBe(true);
  });

  // Test case 5: Custom character sets
  it("should use a custom uppercase character set", () => {
    const customSet = "ABC";
    const token = secureGenerate({
      uppercase: customSet,
      lowercase: false,
      numbers: false,
      specials: false,
      length: 5, // Use a smaller length for easier checking
    });
    expect(token.length).toBe(5);
    expect(containsOnlyCharsFromSet(token, customSet)).toBe(true);
    expect(hasCharsFromSet(token, customSet)).toBe(true); // Should contain at least one from custom set
  });

  it("should use a custom lowercase character set", () => {
    const customSet = "xyz";
    const token = secureGenerate({
      uppercase: false,
      lowercase: customSet,
      numbers: false,
      specials: false,
      length: 5,
    });
    expect(token.length).toBe(5);
    expect(containsOnlyCharsFromSet(token, customSet)).toBe(true);
    expect(hasCharsFromSet(token, customSet)).toBe(true);
  });

  it("should use a custom number character set", () => {
    const customSet = "123";
    const token = secureGenerate({
      uppercase: false,
      lowercase: false,
      numbers: customSet,
      specials: false,
      length: 5,
    });
    expect(token.length).toBe(5);
    expect(containsOnlyCharsFromSet(token, customSet)).toBe(true);
    expect(hasCharsFromSet(token, customSet)).toBe(true);
  });

  it("should use a custom special character set", () => {
    const customSet = "!@#";
    const token = secureGenerate({
      uppercase: false,
      // lowercase: false, // Default true, but we only want specials
      numbers: false,
      specials: customSet,
      length: 5,
    });
    // The default lowercase is true, so the allowed set is customSet + default lowercase
    const allowedSet = customSet + "abcdefghijklmnopqrstuvwxyz";
    expect(token.length).toBe(5);
    expect(containsOnlyCharsFromSet(token, allowedSet)).toBe(true);
    expect(hasCharsFromSet(token, customSet)).toBe(true); // Should contain at least one from custom set
    expect(hasCharsFromSet(token, "abcdefghijklmnopqrstuvwxyz")).toBe(true); // Should contain at least one from default lowercase
  });

  it("should combine custom character sets and other options", () => {
    const customUpper = "ABC";
    const customNumbers = "123";
    const allowedSet =
      customUpper +
      "abcdefghijklmnopqrstuvwxyz" +
      customNumbers +
      "!@#$%^&*()_+{}:<>?|[];,./~-=";
    const token = secureGenerate({
      length: 10,
      uppercase: customUpper,
      lowercase: true, // Default
      numbers: customNumbers,
      specials: true, // Default
    });
    expect(token.length).toBe(10);
    expect(containsOnlyCharsFromSet(token, allowedSet)).toBe(true);
    expect(hasCharsFromSet(token, customUpper)).toBe(true);
    expect(hasCharsFromSet(token, "abcdefghijklmnopqrstuvwxyz")).toBe(true);
    expect(hasCharsFromSet(token, customNumbers)).toBe(true);
    expect(hasCharsFromSet(token, "!@#$%^&*()_+{}:<>?|[];,./~-=")).toBe(true);
  });

  // Test case 6: Edge case - invalid length
  it("should throw an error if length is 0", () => {
    expect(() => secureGenerate({ length: 0 })).toThrow(
      "Password length must be at least 1.",
    );
  });

  it("should throw an error if length is negative", () => {
    expect(() => secureGenerate({ length: -1 })).toThrow(
      "Password length must be at least 1.",
    );
  });

  // Test case 7: Error case - no character types selected
  it("should throw an error if no character types are selected", () => {
    expect(() =>
      secureGenerate({
        uppercase: false,
        lowercase: false,
        numbers: false,
        specials: false,
      }),
    ).toThrow("Cannot generate string. No character types selected.");
  });

  // Test case 8: Basic check for randomness/shuffling (non-deterministic)
  it("should produce different tokens on multiple calls with same options", () => {
    const token1 = secureGenerate();
    const token2 = secureGenerate();
    // While not guaranteed, the probability of two random 16-char tokens being identical is extremely low.
    expect(token1).not.toBe(token2);
  });

  it("should contain at least one character from each included custom set", () => {
    const customUpper = "A";
    const customLower = "b";
    const customNumbers = "1";
    const customSpecials = "!";
    const token = secureGenerate({
      length: 10, // Length > number of included types
      uppercase: customUpper,
      lowercase: customLower,
      numbers: customNumbers,
      specials: customSpecials,
    });

    // Check that at least one character from each custom set is present (guaranteed chars)
    expect(token).toContain(customUpper);
    expect(token).toContain(customLower);
    expect(token).toContain(customNumbers);
    expect(token).toContain(customSpecials);

    // Check that only characters from the combined set are present
    const allowedSet =
      customUpper + customLower + customNumbers + customSpecials;
    expect(containsOnlyCharsFromSet(token, allowedSet)).toBe(true);
  });
});

/**
 * Helper function to check if a string contains at least one character from a given set.
 */
function hasCharsFromSet(token: string, set: string): boolean {
  for (const char of token) {
    if (set.includes(char)) {
      return true;
    }
  }
  return false;
}

/**
 * Helper function to check if a string contains *only* characters from a given set.
 */
function containsOnlyCharsFromSet(token: string, allowedSet: string): boolean {
  for (const char of token) {
    if (!allowedSet.includes(char)) {
      return false;
    }
  }
  return true;
}
