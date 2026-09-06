import { describe, it, expect } from "vitest";
import { UnsecureError } from "../src/errors.ts";

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
