# createDeck() / createChance() / createCascade()

Randomness that feels fair, from the same CSPRNG as the rest of the library. About fairness, not secrecy: loot tables, critical hits, rotations.

**The one rule.** Over one roll the odds add to 100%, so every percent given to an outcome comes from somewhere. The three shapes decide _who pays_: a deck of equal cards (everyone, proportionally), a deck with counts and a fill (the fill), a cascade (the tiers below). The chance model decides _when_ the player feels the rate, not what it is.

## Signatures

```ts
type DeckItems<T> = readonly T[] | ReadonlyMap<T, number>; // list, or multiset of card → count
function createDeck<T>(items: DeckItems<T>, options?: DeckOptions): Deck<T>;
function createDeck<T, F>(
  items: DeckItems<T>,
  options: DeckOptions & { size: number; fill: F },
): Deck<T | F>;

interface DeckOptions {
  generator?: SecureRandomGenerator; // default: the shared one
  state?: DeckState; // resume a saved cycle
  reshuffleAt?: number; // start the next cycle with this many cards undrawn; default 0
}
interface Deck<T> {
  draw(): T;
  readonly remaining: number;
  readonly size: number;
  reset(): void;
  readonly state: DeckState; // { order: number[]; cursor: number }
}

type Fraction = `${number}/${number}`; // exact "hits/cards": the deck itself
type Probability = number | Fraction; // prd and pity: (0, 1) exclusive, or a fraction
function createChance(
  model: "deck",
  probability: Fraction,
  options?: { generator?; state?: DeckState; reshuffleAt? },
): DeckChance;
function createChance(
  model: "prd",
  probability: Probability,
  options?: { generator?; state?: { misses: number } },
): PRDChance;
function createChance(
  model: "pity",
  probability: Probability,
  options: { hard: number; soft?: number; generator?; state?: { misses: number } },
): PityChance;
// all: roll(): boolean; probability: number (delivered rate); reset(); state
// DeckChance adds size; PRDChance adds constant; PityChance adds nominal, hard, soft

interface ChanceLike {
  roll(): boolean;
  readonly probability: number;
} // any chance, or your own model
function createCascade<T extends string, D extends string>(
  ...args: [...tiers: Array<readonly [outcome: T, chance: ChanceLike]>, fallback: D]
): { draw(): T | D; readonly rates: Readonly<Record<T | D, number>> };
```

## Deck

```ts
createDeck(["sword", "shield", "potion"]).draw(); // each once per cycle, random order
createDeck(["crit", "miss", "miss", "hit", "hit"]); // shares: a sixth outcome moves them all
createDeck(
  new Map([
    ["legendary", 1],
    ["crit", 5],
  ]),
  { size: 100, fill: "hit" },
); // counts: only the fill moves
```

`size`/`fill` pad the cards and come as a pair. Cards may be functions or other decks. **Flat vs nested:** a real 52-card pack is one flat deck (five hearts in a row is legal); a deck of suit-decks deals each suit once per four draws, which is a tiered loot table, not a pack. Each draw is one Fisher-Yates step. `reshuffleAt` starts the next cycle early so the tail is never certain (the cut card).

## Chance

```ts
createChance("deck", "1/4").roll(); // exactly once per four rolls; "17/100" is a 100-card cycle
createChance("prd", 0.25).roll(); // odds grow per miss, reset on hit; long-run rate exact; never certain
createChance("pity", 0.006, { hard: 90, soft: 74 }).roll(); // flat, then climbs to certain at hard
```

`model` is required. `"deck"` is exact per cycle and predictable at cycle end. `"prd"` (Dota 2) solves `constant` so the long-run rate equals the probability. `"pity"` (Genshin `{ hard: 90, soft: 74 }`, Hearthstone `{ hard: 40 }`) is flat at `nominal` for `soft` rolls then linear to certain at `hard`; it delivers more than nominal and `probability` reports the delivered rate.

## Cascade

```ts
const roll = createCascade(
  ["legendary", createChance("prd", 0.01)],
  ["crit", createChance("deck", "1/20")],
  "hit",
);
roll.draw(); // "legendary" | "crit" | "hit"
roll.rates; // { legendary: 0.01, crit: 0.0495, hit: 0.9405 }
```

Tiers are asked in order; the first to fire wins; the trailing string is the fallback. A tier is only asked when those above declined, so crit at nominal 5% wins 4.95% once legendary is 1%: adding a tier dilutes only the tiers below. `rates` shows the effective split. No state on the cascade; each tier keeps its own.

## State

One instance per player/feature; nothing shared, nothing kept by the library. `state` is a plain serializable snapshot (deck: indices, never the cards; prd/pity: `{ misses }`); pass it back as `state` to resume. A wrong-size deck snapshot is `OUT_OF_RANGE`.

## Pitfall: Card Counting

Three misses in a 4-card deck make the next hit certain. Use `reshuffleAt`, `"prd"` or `"pity"` when the other side can count.

## Pitfall: A Wheel Is Not a Deck

A weighted wheel is memoryless (regulated gambling, simulation); a deck remembers (game feel). For a wheel use `secureRandomNumber` against cumulative weights and keep no state.

## Pitfall: Expecting Replays

The CSPRNG cannot be seeded. Record the draws to replay a match.
