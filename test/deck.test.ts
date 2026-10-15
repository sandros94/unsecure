import { describe, it, expect } from "vitest";
import { expectUnsecureError } from "./_helpers.ts";
import {
  type ChanceLike,
  type SecureRandomGenerator,
  createCascade,
  createChance,
  createDeck,
  secureShuffle,
} from "../src/index.ts";

/** A generator that always picks the first candidate, so draws come out in `order`. */
const FIRST: SecureRandomGenerator = {
  next: () => 0,
  reset: () => {},
};

/** A generator whose uniform draw is always `u`, so a streak model hits iff its odds exceed `u`. */
function fixed(u: number): SecureRandomGenerator {
  return { next: (max: number) => Math.floor(max * u), reset: () => {} };
}

/** A stand-in chance that reports `probability` and hits on a fixed script. */
function scripted(probability: number, hits: boolean[]): ChanceLike {
  let i = 0;
  return { probability, roll: () => hits[i++ % hits.length]! };
}

function counts<T>(values: T[]): Map<T, number> {
  const out = new Map<T, number>();
  for (const v of values) out.set(v, (out.get(v) ?? 0) + 1);
  return out;
}

describe("createDeck", () => {
  describe("cycles", () => {
    it("deals every card exactly once per cycle, for many cycles", () => {
      const deck = createDeck(["a", "b", "c", "d"]);
      for (let cycle = 0; cycle < 50; cycle++) {
        const seen = new Set<string>();
        for (let i = 0; i < 4; i++) seen.add(deck.draw());
        expect(seen.size).toBe(4);
      }
    });

    it("tracks remaining and size", () => {
      const deck = createDeck([1, 2, 3]);
      expect(deck.size).toBe(3);
      expect(deck.remaining).toBe(3);
      deck.draw();
      expect(deck.remaining).toBe(2);
      deck.draw();
      deck.draw();
      expect(deck.remaining).toBe(0);
      deck.draw();
      expect(deck.remaining).toBe(2);
    });

    it("reset() discards the cycle", () => {
      const deck = createDeck([1, 2, 3]);
      deck.draw();
      deck.reset();
      expect(deck.remaining).toBe(3);
    });

    it("orders are uniform across cycles", () => {
      const deck = createDeck(["a", "b", "c"]);
      const firsts: string[] = [];
      for (let i = 0; i < 3000; i++) {
        firsts.push(deck.draw());
        deck.draw();
        deck.draw();
      }
      for (const n of counts(firsts).values()) {
        expect(n).toBeGreaterThan(800);
        expect(n).toBeLessThan(1200);
      }
    });

    it("uses the generator it is given", () => {
      const deck = createDeck(["a", "b", "c"], { generator: FIRST });
      expect([deck.draw(), deck.draw(), deck.draw()]).toEqual(["a", "b", "c"]);
    });
  });

  describe("size and fill", () => {
    it("pads the items with the fill value", () => {
      const deck = createDeck([true], { size: 4, fill: false });
      const cycle = [deck.draw(), deck.draw(), deck.draw(), deck.draw()];
      expect(counts(cycle).get(true)).toBe(1);
      expect(counts(cycle).get(false)).toBe(3);
      expect(deck.size).toBe(4);
    });

    it("a size equal to the item count pads nothing", () => {
      const deck = createDeck([1, 2], { size: 2, fill: 0 });
      expect(deck.size).toBe(2);
    });

    it("refuses one of size and fill without the other", () => {
      expectUnsecureError(() => createDeck([1], { size: 4 } as never), "OUT_OF_RANGE");
      expect(() => createDeck([1], { size: 4 } as never)).toThrow("got size alone");
      expectUnsecureError(() => createDeck([1], { fill: 0 } as never), "OUT_OF_RANGE");
      expect(() => createDeck([1], { fill: 0 } as never)).toThrow("got fill alone");
    });

    it("refuses a size below the item count", () => {
      expectUnsecureError(() => createDeck([1, 2, 3], { size: 2, fill: 0 }), "OUT_OF_RANGE");
      expect(() => createDeck([1, 2, 3], { size: 2.5, fill: 0 })).toThrow(
        "createDeck: size must be an integer >= 3",
      );
    });
  });

  describe("items", () => {
    it("rejects a non-array and an empty array", () => {
      expectUnsecureError(() => createDeck("abc" as never), "INVALID_TYPE");
      expectUnsecureError(() => createDeck([]), "OUT_OF_RANGE");
      expectUnsecureError(() => createDeck(new Map()), "OUT_OF_RANGE");
    });

    it("takes a Map as a multiset, with fill paying for the remainder", () => {
      const deck = createDeck(
        new Map([
          ["legendary", 1],
          ["crit", 5],
        ]),
        { size: 100, fill: "hit" },
      );
      expect(deck.size).toBe(100);
      const cycle = counts(Array.from({ length: 100 }, () => deck.draw()));
      expect(cycle.get("legendary")).toBe(1);
      expect(cycle.get("crit")).toBe(5);
      expect(cycle.get("hit")).toBe(94);
    });

    it("a Map without size is exactly the sum of its counts", () => {
      const deck = createDeck(
        new Map([
          ["a", 2],
          ["b", 3],
        ]),
      );
      expect(deck.size).toBe(5);
    });

    it("rejects a count below one or a size below the counts", () => {
      expectUnsecureError(() => createDeck(new Map([["a", 0]])), "OUT_OF_RANGE");
      expectUnsecureError(() => createDeck(new Map([["a", 1.5]])), "OUT_OF_RANGE");
      expectUnsecureError(
        () => createDeck(new Map([["a", 3]]), { size: 2, fill: "b" }),
        "OUT_OF_RANGE",
      );
    });

    it("does not mutate or alias the array it is given", () => {
      const items = [3, 1, 2];
      const deck = createDeck(items);
      for (let i = 0; i < 9; i++) deck.draw();
      expect(items).toEqual([3, 1, 2]);
      items.push(9);
      expect(deck.size).toBe(3);
    });

    it("treats nested decks and functions as ordinary cards", () => {
      const inner = createDeck(["x", "y"]);
      const deck = createDeck([inner, () => "fn"]);
      const results = new Set<string>();
      for (let i = 0; i < 2; i++) {
        const card = deck.draw();
        results.add(typeof card === "function" ? card() : card.draw());
      }
      expect(results.size).toBe(2);
      for (const r of results) expect(["x", "y", "fn"]).toContain(r);
    });
  });

  describe("reshuffleAt", () => {
    it("starts a new cycle before the last cards become a certainty", () => {
      const deck = createDeck([true], { size: 4, fill: false, reshuffleAt: 1 });
      // Three draws per cycle, so a hit is not guaranteed within four draws
      // but still cannot run dry: over many draws the rate sits between 1/4 and 1/3.
      let hits = 0;
      const N = 30_000;
      for (let i = 0; i < N; i++) if (deck.draw()) hits++;
      expect(hits / N).toBeGreaterThan(0.24);
      expect(hits / N).toBeLessThan(0.34);
      expect(deck.remaining).not.toBe(0);
    });

    it("is bounded by the deck", () => {
      expectUnsecureError(() => createDeck([1, 2], { reshuffleAt: 2 }), "OUT_OF_RANGE");
      expectUnsecureError(() => createDeck([1, 2], { reshuffleAt: -1 }), "OUT_OF_RANGE");
    });
  });

  describe("state", () => {
    it("is a snapshot that resumes the exact cycle", () => {
      const deck = createDeck(["a", "b", "c", "d"]);
      deck.draw();
      const saved = JSON.parse(JSON.stringify(deck.state)) as typeof deck.state;
      const rest = [deck.draw(), deck.draw(), deck.draw()];
      const resumed = createDeck(["a", "b", "c", "d"], { state: saved, generator: FIRST });
      const resumedRest = [resumed.draw(), resumed.draw(), resumed.draw()];
      expect(new Set(resumedRest)).toEqual(new Set(rest));
      expect(resumed.remaining).toBe(0);
    });

    it("snapshots do not alias the live deck", () => {
      const deck = createDeck([1, 2]);
      const s = deck.state;
      s.order.reverse();
      s.cursor = 2;
      expect(deck.remaining).toBe(2);
    });

    it("is validated against the padded size", () => {
      expectUnsecureError(
        () => createDeck([true], { size: 4, fill: false, state: { order: [0], cursor: 0 } }),
        "OUT_OF_RANGE",
      );
      expectUnsecureError(
        () => createDeck([1, 2], { state: { order: [0, 0], cursor: 0 } }),
        "OUT_OF_RANGE",
      );
      expectUnsecureError(
        () => createDeck([1, 2], { state: { order: [1, 0], cursor: 3 } }),
        "OUT_OF_RANGE",
      );
      expectUnsecureError(() => createDeck([1, 2], { state: null as never }), "OUT_OF_RANGE");
    });
  });
});

describe("createChance", () => {
  describe("deck model", () => {
    it("delivers exactly the fraction per cycle", () => {
      const chance = createChance("deck", "1/4");
      expect(chance.model).toBe("deck");
      expect(chance.size).toBe(4);
      expect(chance.probability).toBe(0.25);
      let hits = 0;
      for (let i = 0; i < 400; i++) if (chance.roll()) hits++;
      expect(hits).toBe(100);
    });

    it("takes a fraction only: the rate and the cycle in one", () => {
      expect(createChance("deck", "17/100").size).toBe(100);
      expect(createChance("deck", "1/500").size).toBe(500);
      expectUnsecureError(() => createChance("deck", 0.25 as never), "INVALID_TYPE");
      expect(() => createChance("deck", 0.25 as never)).toThrow(
        'a deck takes a "hits/cards" string',
      );
    });

    it("exposes and restores state", () => {
      const chance = createChance("deck", "1/2");
      chance.roll();
      const resumed = createChance("deck", "1/2", { state: chance.state });
      expect(resumed.state).toEqual(chance.state);
      chance.reset();
      expect(chance.state.cursor).toBe(0);
    });
  });

  describe("prd model", () => {
    it("derives the Dota 2 constant for 25%", () => {
      const chance = createChance("prd", 0.25);
      expect(chance.model).toBe("prd");
      expect(chance.constant).toBeCloseTo(0.08474, 4);
      expect(chance.probability).toBe(0.25);
    });

    it("hits at the long-run rate with bounded streaks", () => {
      const chance = createChance("prd", 0.25);
      const N = 200_000;
      let hits = 0;
      let streak = 0;
      let longest = 0;
      for (let i = 0; i < N; i++) {
        if (chance.roll()) {
          hits++;
          streak = 0;
        } else {
          longest = Math.max(longest, ++streak);
        }
      }
      expect(hits / N).toBeGreaterThan(0.24);
      expect(hits / N).toBeLessThan(0.26);
      expect(longest).toBeLessThanOrEqual(Math.ceil(1 / chance.constant));
    });

    it("never makes a roll certain before the streak cap", () => {
      // With FIRST the uniform draw is always 0, which is below any positive
      // threshold, so the first roll hits: the odds start at `constant`, not 0.
      const chance = createChance("prd", 0.5, { generator: FIRST });
      expect(chance.roll()).toBe(true);
    });

    it("exposes and restores the streak", () => {
      const chance = createChance("prd", 0.5);
      while (chance.roll()) {
        /* reach a miss */
      }
      expect(chance.state.misses).toBe(1);
      const resumed = createChance("prd", 0.5, { state: { misses: 3 } });
      expect(resumed.state).toEqual({ misses: 3 });
      resumed.reset();
      expect(resumed.state).toEqual({ misses: 0 });
      expectUnsecureError(
        () => createChance("prd", 0.5, { state: { misses: -1 } }),
        "OUT_OF_RANGE",
      );
    });
  });

  describe("pity model", () => {
    it("is flat until soft, climbs after, and is certain at hard", () => {
      // u = 0.5: a roll hits only once the odds pass one half.
      const chance = createChance("pity", 0.1, { hard: 10, soft: 5, generator: fixed(0.5) });
      expect(chance.model).toBe("pity");
      expect(chance.nominal).toBe(0.1);
      expect(chance.hard).toBe(10);
      expect(chance.soft).toBe(5);
      // odds: rolls 1-5 at 0.1; roll 6 = 0.28, 7 = 0.46, 8 = 0.64 -> first hit on roll 8
      const rolls = Array.from({ length: 8 }, () => chance.roll());
      expect(rolls).toEqual([false, false, false, false, false, false, false, true]);
      expect(chance.state).toEqual({ misses: 0 });
    });

    it("without soft the chance stays flat and only hard is certain", () => {
      const chance = createChance("pity", 0.1, { hard: 4, generator: fixed(0.99) });
      expect(chance.soft).toBe(4);
      expect([chance.roll(), chance.roll(), chance.roll(), chance.roll()]).toEqual([
        false,
        false,
        false,
        true,
      ]);
    });

    it("delivers more than the nominal, and reports what it delivers", () => {
      const chance = createChance("pity", 0.006, { hard: 90, soft: 74 });
      expect(chance.probability).toBeGreaterThan(0.012);
      expect(chance.probability).toBeLessThan(0.02);
      const N = 200_000;
      let hits = 0;
      let streak = 0;
      let longest = 0;
      for (let i = 0; i < N; i++) {
        if (chance.roll()) {
          hits++;
          streak = 0;
        } else {
          longest = Math.max(longest, ++streak);
        }
      }
      expect(longest).toBeLessThan(90);
      expect(Math.abs(hits / N - chance.probability) / chance.probability).toBeLessThan(0.1);
    });

    it("exposes and restores the streak", () => {
      const resumed = createChance("pity", 0.5, { hard: 3, state: { misses: 2 } });
      expect(resumed.state).toEqual({ misses: 2 });
      expect(resumed.roll()).toBe(true); // the third roll is certain
      expect(resumed.state).toEqual({ misses: 0 });
    });

    it("validates hard and soft", () => {
      expectUnsecureError(() => createChance("pity", 0.5, {} as never), "OUT_OF_RANGE");
      expectUnsecureError(() => createChance("pity", 0.5, { hard: 0 }), "OUT_OF_RANGE");
      expectUnsecureError(() => createChance("pity", 0.5, { hard: 5, soft: 6 }), "OUT_OF_RANGE");
      expectUnsecureError(() => createChance("pity", 0.5, { hard: 5, soft: -1 }), "OUT_OF_RANGE");
    });
  });

  describe("probability and model validation", () => {
    it("accepts only (0, 1) numbers", () => {
      for (const p of [0, 1, -0.5, 1.5, Number.NaN, Number.POSITIVE_INFINITY]) {
        expectUnsecureError(() => createChance("prd", p), "OUT_OF_RANGE");
      }
    });

    it("accepts only hits/cards strings", () => {
      expectUnsecureError(() => createChance("prd", "1-in-6" as never), "MALFORMED");
      expectUnsecureError(() => createChance("prd", "25%" as never), "MALFORMED");
      expectUnsecureError(() => createChance("prd", "4/4"), "OUT_OF_RANGE");
      expectUnsecureError(() => createChance("prd", "0/4"), "OUT_OF_RANGE");
      expectUnsecureError(() => createChance("prd", null as never), "INVALID_TYPE");
    });

    it("names the model it does not know", () => {
      expectUnsecureError(() => createChance("dice" as never, 0.5), "UNSUPPORTED");
      expectUnsecureError(() => createChance(1 as never, 0.5), "INVALID_TYPE");
    });
  });
});

describe("createCascade", () => {
  it("asks tiers in order and falls back", () => {
    const roll = createCascade(
      ["legendary", scripted(0.01, [false, false, true])],
      ["crit", scripted(0.05, [false, true])],
      "hit",
    );
    const first: "legendary" | "crit" | "hit" = roll.draw();
    expect(first).toBe("hit");
    expect(roll.draw()).toBe("crit");
    expect(roll.draw()).toBe("legendary");
  });

  it("reports effective rates: each tier pays for those above it", () => {
    const roll = createCascade(
      ["legendary", scripted(0.01, [false])],
      ["crit", scripted(0.05, [false])],
      "hit",
    );
    expect(roll.rates.legendary).toBeCloseTo(0.01, 10);
    expect(roll.rates.crit).toBeCloseTo(0.0495, 10);
    expect(roll.rates.hit).toBeCloseTo(0.9405, 10);
    expect(Object.keys(roll.rates)).toEqual(["legendary", "crit", "hit"]);
  });

  it("matches its own rates over many draws with real chances", () => {
    const roll = createCascade(
      ["legendary", createChance("prd", 0.05)],
      ["crit", createChance("deck", "1/4")],
      "hit",
    );
    const N = 100_000;
    const seen = counts(Array.from({ length: N }, () => roll.draw()));
    for (const outcome of ["legendary", "crit", "hit"] as const) {
      expect(Math.abs((seen.get(outcome) ?? 0) / N - roll.rates[outcome])).toBeLessThan(0.01);
    }
  });

  it("accepts a model of your own", () => {
    const coin: ChanceLike = { probability: 0.5, roll: () => true };
    expect(createCascade(["heads", coin], "tails").draw()).toBe("heads");
  });

  it("refuses no tiers, repeated outcomes, and malformed arguments", () => {
    expectUnsecureError(() => createCascade("hit" as never), "OUT_OF_RANGE");
    expectUnsecureError(
      () => createCascade(["a", scripted(0.5, [true])], ["a", scripted(0.5, [true])], "b"),
      "OUT_OF_RANGE",
    );
    expectUnsecureError(() => createCascade(["a", scripted(0.5, [true])], "a"), "OUT_OF_RANGE");
    expectUnsecureError(
      () => createCascade(["a", scripted(0.5, [true])], ["b", scripted(0.5, [true])] as never),
      "INVALID_TYPE",
    );
    expectUnsecureError(() => createCascade(["a", {}] as never, "b"), "INVALID_TYPE");
    expectUnsecureError(
      () => createCascade([1, scripted(0.5, [true])] as never, "b"),
      "INVALID_TYPE",
    );
  });
});

describe("secureShuffle after the Fisher-Yates extraction", () => {
  it("still produces every permutation at about the same rate", () => {
    const seen = counts(Array.from({ length: 6000 }, () => secureShuffle([1, 2, 3]).join("")));
    expect(seen.size).toBe(6);
    for (const n of seen.values()) {
      expect(n).toBeGreaterThan(800);
      expect(n).toBeLessThan(1200);
    }
  });
});
