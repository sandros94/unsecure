import { describe, expect, it, vi } from "vitest";
import {
  createSecureRandomGenerator,
  randomJitter,
  resetEntropy,
  secureRandomBytes,
  secureRandomNumber,
} from "unsecure/random";
import {
  newKeyMaterial,
  pickWinners,
  retryDelayMs,
  rollDie,
} from "../../examples/generate/fair-draws.ts";
import { expectUnsecureError } from "../_helpers.ts";

describe("examples/generate/fair-draws", () => {
  it("picks distinct winners and leaves the entries alone", () => {
    const entries = [
      "ada@example.com",
      "grace@example.com",
      "alan@example.com",
      "edsger@example.com",
    ];
    const before = [...entries];
    const winners = pickWinners(entries, 2);
    expect(winners).toHaveLength(2);
    expect(new Set(winners).size).toBe(2);
    for (const w of winners) expect(entries).toContain(w);
    expect(entries).toEqual(before);
  });

  it("draws inside the documented bounds", () => {
    const faces = new Set<number>();
    for (let i = 0; i < 2000; i++) {
      const face = rollDie();
      expect(face).toBeGreaterThanOrEqual(1);
      expect(face).toBeLessThanOrEqual(6);
      faces.add(face);
      const delay = retryDelayMs();
      expect(delay).toBeGreaterThanOrEqual(500);
      expect(delay).toBeLessThan(1000);
    }
    expect(faces.size).toBe(6);
    expect(newKeyMaterial()).toHaveLength(32);
  });

  it("skips ignored values and gives a private generator of its own", () => {
    for (let i = 0; i < 200; i++) expect([1, 3, 5]).toContain(secureRandomNumber(0, 6, [0, 2, 4]));
    for (let i = 0; i < 200; i++) expect(secureRandomNumber(1, 7, [6])).toBeLessThanOrEqual(5);
    const rng = createSecureRandomGenerator();
    expect(rng.next(10)).toBeLessThan(10);
    rng.reset();
    expect(rng.next(10, 20)).toBeGreaterThanOrEqual(10);
    resetEntropy({ refill: true });
    expect(secureRandomBytes(16)).toHaveLength(16);
  });

  it("reports a refusing runtime as PLATFORM", () => {
    const spy = vi.spyOn(crypto, "getRandomValues").mockImplementation(() => {
      throw new Error("disabled");
    });
    try {
      const error = expectUnsecureError(() => createSecureRandomGenerator().next(10), "PLATFORM");
      expect((error.cause as Error).message).toBe("disabled");
    } finally {
      spy.mockRestore();
    }
  });

  it("waits inside the jitter bounds", async () => {
    vi.useFakeTimers();
    try {
      let done = false;
      const wait = randomJitter(50, 51).then(() => (done = true));
      await vi.advanceTimersByTimeAsync(49);
      expect(done).toBe(false);
      await vi.advanceTimersByTimeAsync(1);
      await wait;
      expect(done).toBe(true);

      let exact = false;
      const fixed = randomJitter(30, 30).then(() => (exact = true));
      await vi.advanceTimersByTimeAsync(29);
      expect(exact).toBe(false);
      await vi.advanceTimersByTimeAsync(1);
      await fixed;
      expect(exact).toBe(true);
    } finally {
      vi.useRealTimers();
    }
  });

  it("refuses the bounds the page lists", () => {
    expectUnsecureError(() => secureRandomNumber(6, 6), "OUT_OF_RANGE");
    expectUnsecureError(() => secureRandomNumber(1.5), "OUT_OF_RANGE");
    expectUnsecureError(() => secureRandomNumber(2 ** 53, 2 ** 53 + 2), "OUT_OF_RANGE");
    expectUnsecureError(() => secureRandomNumber(0, 2 ** 32 + 1), "OUT_OF_RANGE");
    expect(secureRandomNumber(0, 2 ** 32)).toBeLessThan(2 ** 32);
    expectUnsecureError(() => secureRandomNumber(3, [0, 1, 2]), "OUT_OF_RANGE");
    expectUnsecureError(() => secureRandomNumber(3, {} as unknown as number[]), "INVALID_TYPE");
    expectUnsecureError(() => secureRandomBytes(-1), "OUT_OF_RANGE");
    expectUnsecureError(() => secureRandomBytes(2 ** 31), "OUT_OF_RANGE");
    // Thrown before a promise exists, so `.catch()` on the call never sees it.
    expectUnsecureError(() => randomJitter(1.5), "OUT_OF_RANGE");
    expectUnsecureError(() => randomJitter(200, 100), "OUT_OF_RANGE");
    expectUnsecureError(() => randomJitter(null as unknown as number), "OUT_OF_RANGE");
    expectUnsecureError(() => randomJitter(-1), "OUT_OF_RANGE");
  });
});
