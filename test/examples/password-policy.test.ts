import { describe, expect, it } from "vitest";
import { entropy } from "unsecure/entropy";
import { secureGenerate } from "unsecure/generate";
import { weakPasswordReason } from "../../examples/generate/password-policy.ts";
import { expectUnsecureError } from "../_helpers.ts";

describe("examples/generate/password-policy", () => {
  it("rejects short, repetitive and sequential passwords", () => {
    expect(weakPasswordReason(undefined)).toBe("Enter a password.");
    expect(weakPasswordReason(42)).toBe("Enter a password.");
    expect(weakPasswordReason("Password1234")).toBe("Use at least 15 characters.");
    expect(weakPasswordReason("abababababababab")).toBe("Use more different characters.");
    expect(weakPasswordReason("Xq12345678abcdefgh")).toBe(
      "Avoid sequences such as 12345678 or abcdefgh.",
    );
    expect(weakPasswordReason("aaaaaaaaaaaabcdefaaaa")).toBe("Repeat characters less often.");
    expect(weakPasswordReason("aaaaaaaaaaaabcdef")).toBe("Repeat characters less often.");
    expect(weakPasswordReason("aaaaaaaaaaaaaaaa")).toBe("Use more different characters.");
    expect(weakPasswordReason("12345678abcdefgh")).toBe(
      "Avoid sequences such as 12345678 or abcdefgh.",
    );
  });

  it("lets a famous dictionary phrase through: passing is not a verdict", () => {
    expect(weakPasswordReason("correct horse battery staple")).toBeUndefined();
    expect(Math.round(entropy("correct horse battery staple").bits)).toBe(98);
    // A keyboard walk is varied by every measure here.
    expect(weakPasswordReason("qwertyuiopasdfghjk")).toBeUndefined();
  });

  it("almost never rejects a generated password", () => {
    let rejected = 0;
    for (let i = 0; i < 2000; i++) {
      if (weakPasswordReason(secureGenerate({ length: 20 })) !== undefined) rejected++;
    }
    expect(rejected).toBeLessThan(10);
  });

  it("throws INVALID_TYPE for a value that is not text or bytes", () => {
    expectUnsecureError(() => entropy(42 as unknown as string), "INVALID_TYPE");
    expectUnsecureError(() => entropy({ length: 3 } as unknown as string), "INVALID_TYPE");
    expectUnsecureError(() => entropy(new Uint16Array(4) as unknown as string), "INVALID_TYPE");
    expectUnsecureError(() => entropy(new ArrayBuffer(4) as unknown as string), "INVALID_TYPE");
    expect(entropy(null).bits).toBe(0);
    expect(entropy(null).monotonicDirection).toBe("none");
    expect(entropy("").symbolCount).toBe(0);
  });

  it("scores random bytes by sample size, not by source", () => {
    const large = entropy(crypto.getRandomValues(new Uint8Array(4096))).bitsPerSymbol;
    const small = entropy(crypto.getRandomValues(new Uint8Array(256))).bitsPerSymbol;
    expect(large).toBeGreaterThan(7.9);
    expect(small).toBeGreaterThan(6.9);
    expect(small).toBeLessThan(7.45);
  });

  it("scores order-blind: the sorted alphabet looks as varied as noise", () => {
    const sorted = entropy("abcdefghijklmnop");
    expect(sorted.bits).toBe(64);
    expect(sorted.longestRun).toBe(16);
    expect(sorted.monotonicDirection).toBe("ascending");
  });
});
