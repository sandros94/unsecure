import { afterEach, describe, expect, it, vi } from "vitest";
import { secureCompare } from "unsecure/compare";
import { expectUnsecureError } from "../_helpers.ts";

const KEY = "kq7VhM2xP9cLwT4rZbN8sJ3dF6gY1aEu";

function request(headers: Record<string, string> = {}): Request {
  return new Request("https://api.example.com/admin/users", { headers });
}

afterEach(() => {
  vi.unstubAllEnvs();
  vi.resetModules();
});

describe("examples/generate/admin-key", () => {
  it("accepts the right key and refuses a wrong, short or missing one", async () => {
    vi.stubEnv("ADMIN_API_KEY", KEY);
    const { isAdmin } = await import("../../examples/generate/admin-key.ts");

    expect(isAdmin(request({ "X-Admin-Key": KEY }))).toBe(true);
    expect(isAdmin(request({ "X-Admin-Key": KEY.slice(0, -1) + "x" }))).toBe(false);
    expect(isAdmin(request({ "X-Admin-Key": KEY.slice(0, 8) }))).toBe(false);
    expect(isAdmin(request({ "X-Admin-Key": `${KEY}extra` }))).toBe(false);
    expect(isAdmin(request())).toBe(false);
  });

  it("refuses to start without a key", async () => {
    vi.stubEnv("ADMIN_API_KEY", "");
    await expect(import("../../examples/generate/admin-key.ts")).rejects.toThrow(
      "ADMIN_API_KEY is not set",
    );
  });

  it("treats anything the client sent as a mismatch, never a throw", () => {
    for (const received of [undefined, null, 12_345, [1, 2, 3], { key: KEY }]) {
      expect(secureCompare(KEY, received as unknown as string)).toBe(false);
    }
    expect(secureCompare("hello", new TextEncoder().encode("hello"))).toBe(true);
  });

  it("answers false for an empty expected value, or throws under strict", () => {
    expect(secureCompare("", "")).toBe(false);
    expect(secureCompare(undefined, undefined)).toBe(false);
    expectUnsecureError(() => secureCompare(undefined, "x", { strict: true }), "OUT_OF_RANGE");
    expectUnsecureError(() => secureCompare("", "x", { strict: true }), "OUT_OF_RANGE");
    expectUnsecureError(() => secureCompare(12_345 as unknown as string, "x"), "INVALID_TYPE");
  });
});
