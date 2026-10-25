import { describe, expect, it } from "vitest";
import { readAvatar } from "../../examples/getting-started/migrate-errors.ts";

describe("examples/getting-started/migrate-errors", () => {
  it("decodes canonical base64 and maps MALFORMED to null", () => {
    expect(readAvatar("iVBORw0KGgo=")).toEqual(
      new Uint8Array([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
    );
    // Strict decoding refuses what 0.2 accepted: whitespace, wrong padding.
    expect(readAvatar("iVBORw0K Ggo=")).toBeNull();
    expect(readAvatar("Zm9vYg=")).toBeNull();
  });

  it("rethrows anything that is not MALFORMED", () => {
    expect(() => readAvatar(42 as unknown as string)).toThrow(
      expect.objectContaining({ code: "INVALID_TYPE" }),
    );
  });
});
