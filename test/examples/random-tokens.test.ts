import { describe, expect, it } from "vitest";
import { secureGenerate } from "unsecure/generate";
import {
  newApiToken,
  newInviteCode,
  newTemporaryPassword,
} from "../../examples/generate/random-tokens.ts";
import { expectUnsecureError } from "../_helpers.ts";

describe("examples/generate/random-tokens", () => {
  it("draws every token from its sets, with one character from each set", () => {
    for (let i = 0; i < 200; i++) {
      const token = newApiToken();
      expect(token).toMatch(/^[A-Za-z0-9]{32}$/);
      expect(token).toMatch(/[A-Z]/);
      expect(token).toMatch(/[a-z]/);
      expect(token).toMatch(/[0-9]/);

      const invite = newInviteCode();
      expect(invite).toMatch(/^[A-HJKMNP-Z2-9]{10}$/);
      expect(invite).toMatch(/[A-Z]/);
      expect(invite).toMatch(/[2-9]/);

      const password = newTemporaryPassword();
      expect(password).toHaveLength(20);
      expect(password).toMatch(/[!@#$%^&*()_+{}:<>?|[\];,./~\-=]/);
    }
  });

  it("puts a readable, non-secret timestamp in front when asked", () => {
    const at = new Date("2026-03-14T09:30:00Z");
    const token = secureGenerate({ length: 24, timestamp: at });
    expect(token.slice(0, 8)).toBe(at.getTime().toString(36));
    expect(Number.parseInt(token.slice(0, 8), 36)).toBe(at.getTime());
    expect(token).toHaveLength(24);
  });

  it("refuses the configurations the page lists", () => {
    expectUnsecureError(() => secureGenerate({ length: 0 }), "OUT_OF_RANGE");
    expectUnsecureError(() => secureGenerate({ length: 5.5 }), "OUT_OF_RANGE");
    expectUnsecureError(
      () => secureGenerate({ uppercase: false, lowercase: false, numbers: false, specials: false }),
      "OUT_OF_RANGE",
    );
    expectUnsecureError(() => secureGenerate({ numbers: "0123", specials: "0!" }), "OUT_OF_RANGE");
    expectUnsecureError(() => secureGenerate({ numbers: "1123" }), "OUT_OF_RANGE");
    expectUnsecureError(() => secureGenerate({ length: 8, timestamp: true }), "OUT_OF_RANGE");
    expectUnsecureError(
      () => secureGenerate({ timestamp: new Date("not a date") }),
      "OUT_OF_RANGE",
    );
    expectUnsecureError(
      () => secureGenerate({ timestamp: "2026-03-14" as unknown as Date }),
      "INVALID_TYPE",
    );
  });

  it("reads 0, an empty string and false as no timestamp, and a nonzero number as a mistake", () => {
    for (const timestamp of [0, "", false]) {
      expect(
        secureGenerate({ length: 20, specials: false, timestamp: timestamp as never }),
      ).toMatch(/^[A-Za-z0-9]{20}$/);
    }
    expectUnsecureError(
      () => secureGenerate({ timestamp: 1_700_000_000_000 as unknown as Date }),
      "INVALID_TYPE",
    );
  });

  it("cuts the guarantee when length is below the number of sets", () => {
    expect(secureGenerate({ length: 2 })).toHaveLength(2);
  });
});
