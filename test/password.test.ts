import { describe, it, expect } from "vitest";
import { generateSecurePassword } from "../src/password";

describe.concurrent("generateSecurePassword", () => {
  // Test case 1: Default options
  it("should generate a password with default options (length 16, all types)", () => {
    const password = generateSecurePassword();
    expect(password).toBeTypeOf("string");
    expect(password.length).toBe(16);

    // Check presence of default character types
    expect(hasCharsFromSet(password, "ABCDEFGHIJKLMNOPQRSTUVWXYZ")).toBe(true);
    expect(hasCharsFromSet(password, "abcdefghijklmnopqrstuvwxyz")).toBe(true);
    expect(hasCharsFromSet(password, "0123456789")).toBe(true);
    expect(hasCharsFromSet(password, "!@#$%^&*()_+{}:<>?|[];,./~-=")).toBe(
      true,
    );
  });

  // Test case 2: Custom length
  it("should generate a password with a custom length", () => {
    const length = 20;
    const password = generateSecurePassword({ length });
    expect(password).toBeTypeOf("string");
    expect(password.length).toBe(length);

    // Check presence of default character types (since none were excluded)
    expect(hasCharsFromSet(password, "ABCDEFGHIJKLMNOPQRSTUVWXYZ")).toBe(true);
    expect(hasCharsFromSet(password, "abcdefghijklmnopqrstuvwxyz")).toBe(true);
    expect(hasCharsFromSet(password, "0123456789")).toBe(true);
    expect(hasCharsFromSet(password, "!@#$%^&*()_+{}:<>?|[];,./~-=")).toBe(
      true,
    );
  });

  // Test case 3: Exclude specific character types
  it("should exclude uppercase letters when uppercase is false", () => {
    const password = generateSecurePassword({ uppercase: false });
    expect(password.length).toBe(16);
    expect(hasCharsFromSet(password, "ABCDEFGHIJKLMNOPQRSTUVWXYZ")).toBe(false);
    expect(hasCharsFromSet(password, "abcdefghijklmnopqrstuvwxyz")).toBe(true);
    expect(hasCharsFromSet(password, "0123456789")).toBe(true);
    expect(hasCharsFromSet(password, "!@#$%^&*()_+{}:<>?|[];,./~-=")).toBe(
      true,
    );
  });

  it("should exclude lowercase letters when lowercase is false", () => {
    const password = generateSecurePassword({ lowercase: false });
    expect(password.length).toBe(16);
    expect(hasCharsFromSet(password, "abcdefghijklmnopqrstuvwxyz")).toBe(false);
    expect(hasCharsFromSet(password, "ABCDEFGHIJKLMNOPQRSTUVWXYZ")).toBe(true);
    expect(hasCharsFromSet(password, "0123456789")).toBe(true);
    expect(hasCharsFromSet(password, "!@#$%^&*()_+{}:<>?|[];,./~-=")).toBe(
      true,
    );
  });

  it("should exclude numbers when numbers is false", () => {
    const password = generateSecurePassword({ numbers: false });
    expect(password.length).toBe(16);
    expect(hasCharsFromSet(password, "0123456789")).toBe(false);
    expect(hasCharsFromSet(password, "ABCDEFGHIJKLMNOPQRSTUVWXYZ")).toBe(true);
    expect(hasCharsFromSet(password, "abcdefghijklmnopqrstuvwxyz")).toBe(true);
    expect(hasCharsFromSet(password, "!@#$%^&*()_+{}:<>?|[];,./~-=")).toBe(
      true,
    );
  });

  it("should exclude special characters when specials is false", () => {
    const password = generateSecurePassword({ specials: false });
    expect(password.length).toBe(16);
    expect(hasCharsFromSet(password, "!@#$%^&*()_+{}:<>?|[];,./~-=")).toBe(
      false,
    );
    expect(hasCharsFromSet(password, "ABCDEFGHIJKLMNOPQRSTUVWXYZ")).toBe(true);
    expect(hasCharsFromSet(password, "abcdefghijklmnopqrstuvwxyz")).toBe(true);
    expect(hasCharsFromSet(password, "0123456789")).toBe(true);
  });

  it("should exclude multiple character types when set to false", () => {
    const password = generateSecurePassword({
      uppercase: false,
      numbers: false,
    });
    expect(password.length).toBe(16);
    expect(hasCharsFromSet(password, "ABCDEFGHIJKLMNOPQRSTUVWXYZ")).toBe(false);
    expect(hasCharsFromSet(password, "0123456789")).toBe(false);
    expect(hasCharsFromSet(password, "abcdefghijklmnopqrstuvwxyz")).toBe(true);
    expect(hasCharsFromSet(password, "!@#$%^&*()_+{}:<>?|[];,./~-=")).toBe(
      true,
    );
  });

  // Test case 4: Include only specific character types
  it("should include only uppercase when other types are false", () => {
    const allowedSet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    const password = generateSecurePassword({
      uppercase: true,
      lowercase: false,
      numbers: false,
      specials: false,
    });
    expect(password.length).toBe(16);
    expect(hasCharsFromSet(password, allowedSet)).toBe(true); // Should contain at least one uppercase
    expect(containsOnlyCharsFromSet(password, allowedSet)).toBe(true);
  });

  it("should include only lowercase when other types are false", () => {
    const allowedSet = "abcdefghijklmnopqrstuvwxyz";
    const password = generateSecurePassword({
      uppercase: false,
      lowercase: true,
      numbers: false,
      specials: false,
    });
    expect(password.length).toBe(16);
    expect(hasCharsFromSet(password, allowedSet)).toBe(true); // Should contain at least one lowercase
    expect(containsOnlyCharsFromSet(password, allowedSet)).toBe(true);
  });

  it("should include only numbers when other types are false", () => {
    const allowedSet = "0123456789";
    const password = generateSecurePassword({
      uppercase: false,
      lowercase: false,
      numbers: true,
      specials: false,
    });
    expect(password.length).toBe(16);
    expect(hasCharsFromSet(password, allowedSet)).toBe(true); // Should contain at least one number
    expect(containsOnlyCharsFromSet(password, allowedSet)).toBe(true);
  });

  it("should include only specials when other types are false", () => {
    const allowedSet = "!@#$%^&*()_+{}:<>?|[];,./~-=";
    const password = generateSecurePassword({
      uppercase: false,
      lowercase: false,
      numbers: false,
      specials: true,
    });
    expect(password.length).toBe(16);
    expect(hasCharsFromSet(password, allowedSet)).toBe(true); // Should contain at least one special
    expect(containsOnlyCharsFromSet(password, allowedSet)).toBe(true);
  });

  // Test case 5: Custom character sets
  it("should use a custom uppercase character set", () => {
    const customSet = "ABC";
    const password = generateSecurePassword({
      uppercase: customSet,
      lowercase: false,
      numbers: false,
      specials: false,
      length: 5, // Use a smaller length for easier checking
    });
    expect(password.length).toBe(5);
    expect(containsOnlyCharsFromSet(password, customSet)).toBe(true);
    expect(hasCharsFromSet(password, customSet)).toBe(true); // Should contain at least one from custom set
  });

  it("should use a custom lowercase character set", () => {
    const customSet = "xyz";
    const password = generateSecurePassword({
      uppercase: false,
      lowercase: customSet,
      numbers: false,
      specials: false,
      length: 5,
    });
    expect(password.length).toBe(5);
    expect(containsOnlyCharsFromSet(password, customSet)).toBe(true);
    expect(hasCharsFromSet(password, customSet)).toBe(true);
  });

  it("should use a custom number character set", () => {
    const customSet = "123";
    const password = generateSecurePassword({
      uppercase: false,
      lowercase: false,
      numbers: customSet,
      specials: false,
      length: 5,
    });
    expect(password.length).toBe(5);
    expect(containsOnlyCharsFromSet(password, customSet)).toBe(true);
    expect(hasCharsFromSet(password, customSet)).toBe(true);
  });

  it("should use a custom special character set", () => {
    const customSet = "!@#";
    const password = generateSecurePassword({
      uppercase: false,
      // lowercase: false, // Default true, but we only want specials
      numbers: false,
      specials: customSet,
      length: 5,
    });
    // The default lowercase is true, so the allowed set is customSet + default lowercase
    const allowedSet = customSet + "abcdefghijklmnopqrstuvwxyz";
    expect(password.length).toBe(5);
    expect(containsOnlyCharsFromSet(password, allowedSet)).toBe(true);
    expect(hasCharsFromSet(password, customSet)).toBe(true); // Should contain at least one from custom set
    expect(hasCharsFromSet(password, "abcdefghijklmnopqrstuvwxyz")).toBe(true); // Should contain at least one from default lowercase
  });

  it("should combine custom character sets and other options", () => {
    const customUpper = "ABC";
    const customNumbers = "123";
    const allowedSet =
      customUpper +
      "abcdefghijklmnopqrstuvwxyz" +
      customNumbers +
      "!@#$%^&*()_+{}:<>?|[];,./~-=";
    const password = generateSecurePassword({
      length: 10,
      uppercase: customUpper,
      lowercase: true, // Default
      numbers: customNumbers,
      specials: true, // Default
    });
    expect(password.length).toBe(10);
    expect(containsOnlyCharsFromSet(password, allowedSet)).toBe(true);
    expect(hasCharsFromSet(password, customUpper)).toBe(true);
    expect(hasCharsFromSet(password, "abcdefghijklmnopqrstuvwxyz")).toBe(true);
    expect(hasCharsFromSet(password, customNumbers)).toBe(true);
    expect(hasCharsFromSet(password, "!@#$%^&*()_+{}:<>?|[];,./~-=")).toBe(
      true,
    );
  });

  // Test case 6: Edge case - invalid length
  it("should throw an error if length is 0", () => {
    expect(() => generateSecurePassword({ length: 0 })).toThrow(
      "Password length must be at least 1.",
    );
  });

  it("should throw an error if length is negative", () => {
    expect(() => generateSecurePassword({ length: -1 })).toThrow(
      "Password length must be at least 1.",
    );
  });

  // Test case 7: Error case - no character types selected
  it("should throw an error if no character types are selected", () => {
    expect(() =>
      generateSecurePassword({
        uppercase: false,
        lowercase: false,
        numbers: false,
        specials: false,
      }),
    ).toThrow("Cannot generate password. No character types selected.");
  });

  // Test case 8: Basic check for randomness/shuffling (non-deterministic)
  it("should produce different passwords on multiple calls with same options", () => {
    const password1 = generateSecurePassword();
    const password2 = generateSecurePassword();
    // While not guaranteed, the probability of two random 16-char passwords being identical is extremely low.
    expect(password1).not.toBe(password2);
  });

  it("should contain at least one character from each included custom set", () => {
    const customUpper = "A";
    const customLower = "b";
    const customNumbers = "1";
    const customSpecials = "!";
    const password = generateSecurePassword({
      length: 10, // Length > number of included types
      uppercase: customUpper,
      lowercase: customLower,
      numbers: customNumbers,
      specials: customSpecials,
    });

    // Check that at least one character from each custom set is present (guaranteed chars)
    expect(password).toContain(customUpper);
    expect(password).toContain(customLower);
    expect(password).toContain(customNumbers);
    expect(password).toContain(customSpecials);

    // Check that only characters from the combined set are present
    const allowedSet =
      customUpper + customLower + customNumbers + customSpecials;
    expect(containsOnlyCharsFromSet(password, allowedSet)).toBe(true);
  });
});

/**
 * Helper function to check if a string contains at least one character from a given set.
 */
function hasCharsFromSet(password: string, set: string): boolean {
  for (const char of password) {
    if (set.includes(char)) {
      return true;
    }
  }
  return false;
}

/**
 * Helper function to check if a string contains *only* characters from a given set.
 */
function containsOnlyCharsFromSet(
  password: string,
  allowedSet: string,
): boolean {
  for (const char of password) {
    if (!allowedSet.includes(char)) {
      return false;
    }
  }
  return true;
}
