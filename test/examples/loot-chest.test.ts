import { describe, expect, it } from "vitest";
import { createCascade, createChance, createDeck } from "unsecure/odds";
import { openChest } from "../../examples/generate/loot-chest.ts";
import { expectUnsecureError } from "../_helpers.ts";

function memoryStore() {
  const rows = new Map<string, object>();
  return {
    rows,
    load: async (id: string) => structuredClone(rows.get(id) ?? {}),
    save: async (id: string, luck: object) => {
      rows.set(id, structuredClone(luck));
    },
  };
}

describe("examples/generate/loot-chest", () => {
  it("guarantees a legendary within 90 chests and keeps the streak between calls", async () => {
    const store = memoryStore();
    const loot: string[] = [];
    for (let i = 0; i < 90; i++) loot.push(await openChest(store, "ada@example.com"));
    expect(loot).toContain("legendary");
    for (const item of loot) expect(["legendary", "rare", "common"]).toContain(item);

    const saved = store.rows.get("ada@example.com") as { legendary: { misses: number } };
    expect(saved.legendary.misses).toBeLessThan(90);
    expect(saved.legendary.misses).toBe(loot.length - 1 - loot.lastIndexOf("legendary"));
  });

  it("reports the delivered rates", () => {
    const legendary = createChance("pity", 0.006, { hard: 90, soft: 74 });
    const rare = createChance("prd", 0.05);
    const rates = createCascade(["legendary", legendary], ["rare", rare], "common").rates;
    expect(legendary.nominal).toBe(0.006);
    expect(rare.constant).toBeCloseTo(0.0038, 4);
    let drought = 1;
    for (let n = 1; n <= 60; n++) drought *= 1 - n * rare.constant;
    expect(Math.round(1 / drought / 100) * 100).toBe(1900);
    expect(Math.round(1 / 0.95 ** 60)).toBe(22);
    expect(rates.legendary).toBeCloseTo(0.0159, 4);
    expect(rates.rare).toBeCloseTo(0.0492, 4);
    expect(Math.round(rates.legendary * 10_000) / 100).toBe(1.59);
    expect(Math.round(rates.rare * 10_000) / 100).toBe(4.92);
    expect(0.99 ** 100).toBeCloseTo(0.366, 3);
    expect(rates.legendary + rates.rare + rates.common).toBeCloseTo(1, 12);
  });

  it("lets whoever writes the state choose the next roll", () => {
    const forged = createChance("pity", 0.006, { hard: 90, state: { misses: 89 } });
    expect(forged.roll()).toBe(true);
  });

  it("deals every card once per cycle", () => {
    const rewards = createDeck(
      new Map([
        ["gem", 1],
        ["coins", 3],
      ]),
      { size: 10, fill: "nothing" },
    );
    const ten = Array.from({ length: 10 }, () => rewards.draw());
    expect(ten.filter((c) => c === "gem")).toHaveLength(1);
    expect(ten.filter((c) => c === "coins")).toHaveLength(3);
    expect(ten.filter((c) => c === "nothing")).toHaveLength(6);
    const cut = createDeck([true], { size: 4, fill: false, reshuffleAt: 1 });
    cut.draw();
    cut.draw();
    cut.draw();
    expect(cut.remaining).toBe(1);
    cut.draw();
    expect(cut.remaining).toBe(3);
    expectUnsecureError(
      () => createDeck([true], { size: 4, fill: false, reshuffleAt: 4 }),
      "OUT_OF_RANGE",
    );

    const deck = createDeck(new Map([["gem", 1]]), { size: 4, fill: "coins" });
    const cycle = [deck.draw(), deck.draw(), deck.draw(), deck.draw()];
    expect(cycle.filter((c) => c === "gem")).toHaveLength(1);
    expect(deck.remaining).toBe(0);
    const crit = createChance("deck", "1/4");
    expect([crit.roll(), crit.roll(), crit.roll(), crit.roll()].filter(Boolean)).toHaveLength(1);
  });

  it("refuses the configurations the page lists", () => {
    expectUnsecureError(() => createDeck([]), "OUT_OF_RANGE");
    expectUnsecureError(() => createDeck(new Map([["gem", 0]])), "OUT_OF_RANGE");
    expectUnsecureError(() => createDeck(["gem"], { size: 4 } as never), "OUT_OF_RANGE");
    expectUnsecureError(() => createDeck(["gem", "coins"], { size: 1, fill: "x" }), "OUT_OF_RANGE");
    expectUnsecureError(
      () => createDeck(["a", "b"], { state: { order: [0, 0], cursor: 0 } }),
      "OUT_OF_RANGE",
    );
    expectUnsecureError(() => createDeck("gem" as never), "INVALID_TYPE");
    expectUnsecureError(() => createChance("coin" as never, 0.5), "UNSUPPORTED");
    expectUnsecureError(() => createChance("deck", 0.25 as never), "INVALID_TYPE");
    expectUnsecureError(() => createChance("deck", "one in four" as never), "MALFORMED");
    expectUnsecureError(() => createChance("deck", "4/4"), "OUT_OF_RANGE");
    expectUnsecureError(() => createChance("prd", 1), "OUT_OF_RANGE");
    expectUnsecureError(() => createChance("prd", 0), "OUT_OF_RANGE");
    expectUnsecureError(() => createChance("deck", "0/4"), "OUT_OF_RANGE");
    expectUnsecureError(() => createChance("pity", 0.01, { hard: 10, soft: 11 }), "OUT_OF_RANGE");
    expectUnsecureError(() => createChance("prd", 0.05, { state: { misses: -1 } }), "OUT_OF_RANGE");
    const coin = createChance("prd", 0.5);
    expectUnsecureError(() => createCascade(["a", coin], ["a", coin], "b"), "OUT_OF_RANGE");
    expectUnsecureError(() => createCascade("common" as never), "OUT_OF_RANGE");
    expectUnsecureError(() => createCascade(["a", 0.5] as never, "b"), "INVALID_TYPE");
  });
});
