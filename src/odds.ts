import { assertInteger, showValue } from "./_internal/assert.ts";
import { drawInPlace } from "./_internal/shuffle.ts";
import { UnsecureError } from "./errors.ts";
import { type SecureRandomGenerator, secureRandomNumber } from "./random.ts";
import { ownOptions } from "./_internal/options.ts";

const _DECK = "createDeck";
const _CHANCE = "createChance";
const _CASCADE = "createCascade";

// #region Chance

/**
 * How a chance feels over time. `"deck"` guarantees the long-run rate inside
 * every cycle: a 1-in-4 hit shows up exactly once per four rolls, so the last
 * rolls of a cycle are predictable unless `reshuffleAt` is set. `"prd"`
 * (pseudo-random distribution) raises the odds after every miss and resets on
 * a hit: the long-run rate is exact, streaks are bounded, and no roll is ever
 * a certainty.
 */
export type ChanceModel = "deck" | "prd" | "pity";

/** An exact `"hits/cards"` fraction such as `"1/6"`: the rate and the cycle in one. */
export type Fraction = `${number}/${number}`;

/** A number in (0, 1), or a {@link Fraction}. */
export type Probability = number | Fraction;

export interface ChanceOptions {
  /** Draw from this generator instead of the one shared by the process. */
  generator?: SecureRandomGenerator;
}

export interface DeckChanceOptions extends ChanceOptions {
  state?: DeckState;
  /** See {@link DeckOptions.reshuffleAt}. @default 0 */
  reshuffleAt?: number;
}

export interface PRDState {
  misses: number;
}

export interface PRDChanceOptions extends ChanceOptions {
  state?: PRDState;
}

export interface PityState {
  misses: number;
}

export interface PityChanceOptions extends ChanceOptions {
  state?: PityState;
  /** The roll that is certain: a hit comes within this many rolls. */
  hard: number;
  /**
   * Rolls at the flat nominal chance before the odds start climbing toward
   * `hard`. Omitted, the chance stays flat and only `hard` is certain.
   * @default hard
   */
  soft?: number;
}

export interface Chance<State> {
  /** Did it happen this time. */
  roll(): boolean;
  /** The rate actually delivered over the long run. */
  readonly probability: number;
  /** Forget the streak or the cycle. */
  reset(): void;
  /** A plain snapshot to persist; pass it back as `state` to resume. */
  readonly state: State;
}

export interface DeckChance extends Chance<DeckState> {
  readonly model: "deck";
  /** Cards per cycle. */
  readonly size: number;
}

export interface PRDChance extends Chance<PRDState> {
  readonly model: "prd";
  /** The per-miss increment; the first roll after a hit succeeds with this probability. */
  readonly constant: number;
}

export interface PityChance extends Chance<PityState> {
  readonly model: "pity";
  /** The flat chance of the early rolls. `probability` is the higher rate the ramp delivers. */
  readonly nominal: number;
  readonly hard: number;
  readonly soft: number;
}

/**
 * A chance that feels fair. `"deck"` draws from a shuffled bag with the hits
 * dealt in; `"prd"` grows the odds after every miss and solves its increment
 * so the long-run rate equals `probability`; `"pity"` stays flat at the
 * nominal chance, then climbs to a certain hit at `hard`, delivering more than
 * the nominal over the long run. A deck takes an exact `"hits/cards"`
 * fraction, which is its composition; the other two also take a number in
 * (0, 1), since they have no cycle to size.
 *
 * @throws {UnsecureError} `INVALID_TYPE` for a non-string `model`, a deck
 *   `probability` that is not a string, or any other that is neither number
 *   nor string; `UNSUPPORTED` for an unknown `model`; `MALFORMED` for a string
 *   that is not `"hits/cards"`; `OUT_OF_RANGE` for a probability outside
 *   (0, 1), a fraction without `0 < hits < cards`, a `hard`/`soft` that is not
 *   `0 <= soft <= hard`, `hard` below 1, or a `state` that does not fit.
 */
export function createChance(
  model: "deck",
  probability: Fraction,
  options?: DeckChanceOptions,
): DeckChance;
export function createChance(
  model: "prd",
  probability: Probability,
  options?: PRDChanceOptions,
): PRDChance;
export function createChance(
  model: "pity",
  probability: Probability,
  options: PityChanceOptions,
): PityChance;
/* @__NO_SIDE_EFFECTS__ */
export function createChance(
  model: ChanceModel,
  probability: Probability,
  input?: DeckChanceOptions | PRDChanceOptions | PityChanceOptions,
): DeckChance | PRDChance | PityChance {
  const options = ownOptions(input ?? ({} as PRDChanceOptions));
  if (typeof model !== "string") {
    throw new UnsecureError(
      "INVALID_TYPE",
      `${_CHANCE}: model must be a string, got ${showValue(model)}.`,
    );
  }
  if (model === "deck") {
    return _deckChance(_parseFraction(probability as Fraction), options as DeckChanceOptions);
  }
  if (model === "prd") {
    return _prdChance(_parseProbability(probability).p, options as PRDChanceOptions);
  }
  if (model === "pity") {
    return _pityChance(_parseProbability(probability).p, options as PityChanceOptions);
  }
  throw new UnsecureError(
    "UNSUPPORTED",
    `${_CHANCE}: model must be "deck", "prd" or "pity", got ${showValue(model)}.`,
  );
}

// #region Deck

/** Where a deck is in its cycle: a permutation of card indices and how many are drawn. */
export interface DeckState {
  order: number[];
  cursor: number;
}

export interface DeckOptions {
  /** Draw from this generator instead of the one shared by the process. */
  generator?: SecureRandomGenerator;
  /** Resume a cycle saved from another deck's `state` over the same items. */
  state?: DeckState;
  /**
   * Start a new cycle when this many cards are left instead of when none are,
   * so the last cards of a cycle are never a certainty (the casino's cut card).
   * @default 0
   */
  reshuffleAt?: number;
}

/** `size` and `fill` pad the items with copies of `fill` up to `size` cards. */
export interface PaddedDeckOptions<F> extends DeckOptions {
  size: number;
  fill: F;
}

export interface Deck<T> {
  /** The next card. A new cycle starts when the current one is exhausted. */
  draw(): T;
  /** Cards left in the current cycle. */
  readonly remaining: number;
  /** Cards per cycle. */
  readonly size: number;
  /** Discard the current cycle; the next draw starts a fresh one. */
  reset(): void;
  /** A plain snapshot to persist; pass it back as `state` to resume. */
  readonly state: DeckState;
}

/**
 * A shuffled deck: every card comes up exactly once per cycle, in a random
 * order, and the next cycle is a fresh shuffle. Pass `size` and `fill` to pad
 * `items` with blanks, so one hit card in four is `createDeck([true],
 * { size: 4, fill: false })`. Nested decks and functions are ordinary cards.
 *
 * @throws {UnsecureError} `INVALID_TYPE` if `items` is not an array;
 *   `OUT_OF_RANGE` if it is empty, if `size` is below its length, if `size` or
 *   `fill` comes without the other, if `reshuffleAt` is not in `[0, size)`, or
 *   if `state` does not describe a deck of this size.
 */
export function createDeck<T>(items: DeckItems<T>, options?: DeckOptions): Deck<T>;
export function createDeck<T, F>(items: DeckItems<T>, options: PaddedDeckOptions<F>): Deck<T | F>;
/* @__NO_SIDE_EFFECTS__ */
export function createDeck<T, F>(
  items: DeckItems<T>,
  input?: DeckOptions | PaddedDeckOptions<F>,
): Deck<T | F> {
  const options = ownOptions(input ?? ({} as DeckOptions));
  const expanded = _expand(items);
  const hasSize = "size" in options && options.size !== undefined;
  const hasFill = "fill" in options;
  if (hasSize !== hasFill) {
    throw new UnsecureError(
      "OUT_OF_RANGE",
      `${_DECK}: size and fill come together; got ${hasSize ? "size" : "fill"} alone.`,
    );
  }
  let cards: Array<T | F> = expanded;
  if (hasSize) {
    const { size, fill } = options as PaddedDeckOptions<F>;
    assertInteger(size, "size", _DECK, expanded.length);
    cards = cards.concat(Array.from({ length: size - expanded.length }, () => fill));
  }
  return _deck(cards, options, _DECK);
}

/** Cards as a list (one card per entry) or a multiset (`Map` of card to count). */
export type DeckItems<T> = readonly T[] | ReadonlyMap<T, number>;

// #region Cascade

/**
 * What a cascade tier needs from a chance: every `createChance` result
 * fits, and so does a model of your own.
 */
export interface ChanceLike {
  roll(): boolean;
  /** The long-run hit rate, used for {@link Cascade.rates}. */
  readonly probability: number;
}

/** An outcome and the chance that it fires, asked in cascade order. */
export type CascadeTier<T extends string> = readonly [outcome: T, chance: ChanceLike];

export interface Cascade<T extends string, D extends string> {
  /** The first tier whose chance fires, else the fallback. */
  draw(): T | D;
  /**
   * How often each outcome wins over the long run: a tier's own rate times
   * the miss rates of every tier above it, the fallback taking the rest.
   */
  readonly rates: Readonly<Record<T | D, number>>;
}

/**
 * Independent chances asked in order; the first to fire names the outcome, and
 * none firing yields the trailing fallback. Adding a tier costs only the tiers
 * below it, so order decides who is protected from dilution. Each tier keeps
 * its own memory and state; the cascade has none.
 *
 * @throws {UnsecureError} `OUT_OF_RANGE` without a tier, or when two outcomes
 *   share a name; `INVALID_TYPE` for a tier that is not `[string, chance]` or a
 *   fallback that is not a string.
 */
/* @__NO_SIDE_EFFECTS__ */
export function createCascade<T extends string, D extends string>(
  ...args: [...tiers: CascadeTier<T>[], fallback: D]
): Cascade<T, D> {
  const fallback = args[args.length - 1];
  if (typeof fallback !== "string") {
    throw new UnsecureError(
      "INVALID_TYPE",
      `${_CASCADE}: the last argument is the fallback outcome, a string, got ${showValue(fallback)}.`,
    );
  }
  if (args.length < 2) {
    throw new UnsecureError("OUT_OF_RANGE", `${_CASCADE}: at least one tier is required.`);
  }
  const tiers: Array<{ outcome: T; chance: ChanceLike }> = [];
  const rates = {} as Record<T | D, number>;
  let reach = 1;
  for (let i = 0; i < args.length - 1; i++) {
    const tier = args[i] as unknown;
    if (
      !Array.isArray(tier) ||
      tier.length !== 2 ||
      typeof tier[0] !== "string" ||
      typeof (tier[1] as ChanceLike | null)?.roll !== "function" ||
      typeof (tier[1] as ChanceLike).probability !== "number"
    ) {
      throw new UnsecureError(
        "INVALID_TYPE",
        `${_CASCADE}: tier ${i} must be [outcome, chance], got ${showValue(tier)}.`,
      );
    }
    const [outcome, chance] = tier as [T, ChanceLike];
    if (outcome in rates || (outcome as string) === fallback) {
      throw new UnsecureError(
        "OUT_OF_RANGE",
        `${_CASCADE}: outcome ${showValue(outcome)} appears twice.`,
      );
    }
    tiers.push({ outcome, chance });
    rates[outcome] = reach * chance.probability;
    reach *= 1 - chance.probability;
  }
  rates[fallback as D] = reach;
  return {
    draw(): T | D {
      for (const { outcome, chance } of tiers) if (chance.roll()) return outcome;
      return fallback as D;
    },
    rates,
  };
}

// #region Internal

/* @__NO_SIDE_EFFECTS__ */
function _expand<T>(items: DeckItems<T>): T[] {
  let cards: T[];
  if (Array.isArray(items)) {
    cards = items.slice() as T[];
  } else if (items instanceof Map) {
    cards = [];
    for (const [card, count] of items as ReadonlyMap<T, number>) {
      assertInteger(count, "count", _DECK, 1);
      for (let i = 0; i < count; i++) cards.push(card);
    }
  } else {
    throw new UnsecureError(
      "INVALID_TYPE",
      `${_DECK}: items must be an array or a Map of card to count, got ${showValue(items)}.`,
    );
  }
  if (cards.length === 0) {
    throw new UnsecureError("OUT_OF_RANGE", `${_DECK}: items must hold at least one card.`);
  }
  return cards;
}

/* @__NO_SIDE_EFFECTS__ */
function _deck<T>(cards: readonly T[], options: DeckOptions, source: string): Deck<T> {
  const size = cards.length;
  const reshuffleAt = options.reshuffleAt ?? 0;
  assertInteger(reshuffleAt, "reshuffleAt", source, 0, size - 1);
  const next = _next(options.generator);

  let order: number[];
  let cursor: number;
  if (options.state === undefined) {
    order = Array.from({ length: size }, (_, i) => i);
    cursor = 0;
  } else {
    ({ order, cursor } = _deckState(options.state, size, source));
  }

  return {
    draw(): T {
      if (size - cursor <= reshuffleAt) cursor = 0;
      return cards[drawInPlace(order, cursor++, size, next)]!;
    },
    get remaining(): number {
      return size - cursor;
    },
    size,
    reset(): void {
      cursor = 0;
    },
    get state(): DeckState {
      return { order: order.slice(), cursor };
    },
  };
}

/* @__NO_SIDE_EFFECTS__ */
function _next(generator: SecureRandomGenerator | undefined): (max: number) => number {
  return generator === undefined ? secureRandomNumber : (max) => generator.next(max);
}

/** A saved state is trusted only once it is a permutation of this deck's cards. */
/* @__NO_SIDE_EFFECTS__ */
function _deckState(state: DeckState, size: number, source: string): DeckState {
  const order = (state as Partial<DeckState> | null)?.order;
  const cursor = (state as Partial<DeckState> | null)?.cursor;
  if (!Array.isArray(order) || order.length !== size) {
    throw new UnsecureError(
      "OUT_OF_RANGE",
      `${source}: state.order must list the ${size} cards of this deck, got ${showValue(order)}.`,
    );
  }
  const seen = new Set<number>();
  for (const index of order) {
    if (!Number.isInteger(index) || index < 0 || index >= size || seen.has(index)) {
      throw new UnsecureError(
        "OUT_OF_RANGE",
        `${source}: state.order must be a permutation of 0..${size - 1}, got ${showValue(index)}.`,
      );
    }
    seen.add(index);
  }
  assertInteger(cursor as number, "state.cursor", source, 0, size);
  return { order: order.slice(), cursor: cursor as number };
}

/* @__NO_SIDE_EFFECTS__ */
function _parseProbability(value: Probability): { p: number } {
  if (typeof value === "number") {
    if (!(value > 0 && value < 1)) {
      throw new UnsecureError(
        "OUT_OF_RANGE",
        `${_CHANCE}: probability must be between 0 and 1 exclusive, got ${showValue(value)}.`,
      );
    }
    return { p: value };
  }
  if (typeof value !== "string") {
    throw new UnsecureError(
      "INVALID_TYPE",
      `${_CHANCE}: probability must be a number or a "hits/cards" string, got ${showValue(value)}.`,
    );
  }
  const [hits, cards] = _parseFraction(value);
  return { p: hits / cards };
}

/* @__NO_SIDE_EFFECTS__ */
function _parseFraction(value: Fraction): readonly [hits: number, cards: number] {
  if (typeof value !== "string") {
    throw new UnsecureError(
      "INVALID_TYPE",
      `${_CHANCE}: a deck takes a "hits/cards" string, got ${showValue(value)}.`,
    );
  }
  const match = /^(\d+)\/(\d+)$/.exec(value);
  if (match === null) {
    throw new UnsecureError(
      "MALFORMED",
      `${_CHANCE}: probability must read "hits/cards", got ${showValue(value)}.`,
    );
  }
  const hits = Number(match[1]);
  const cards = Number(match[2]);
  if (!(hits > 0 && hits < cards && Number.isSafeInteger(cards))) {
    throw new UnsecureError(
      "OUT_OF_RANGE",
      `${_CHANCE}: a fraction needs 0 < hits < cards, got ${showValue(value)}.`,
    );
  }
  return [hits, cards];
}

/* @__NO_SIDE_EFFECTS__ */
function _deckChance(
  [hits, cards]: readonly [number, number],
  options: DeckChanceOptions,
): DeckChance {
  const deck = createDeck(
    Array.from({ length: hits }, () => true),
    {
      size: cards,
      fill: false,
      generator: options.generator,
      state: options.state,
      reshuffleAt: options.reshuffleAt,
    },
  );
  return {
    model: "deck",
    roll: () => deck.draw(),
    probability: hits / cards,
    size: cards,
    reset: () => deck.reset(),
    get state(): DeckState {
      return deck.state;
    },
  };
}

/**
 * A chance whose odds depend on the current miss streak: `odds(n)` is the hit
 * chance of the n-th roll since the last hit (n >= 1). PRD and pity differ
 * only in that function.
 */
interface _Streak {
  roll: () => boolean;
  reset: () => void;
  readonly state: { misses: number };
}

/* @__NO_SIDE_EFFECTS__ */
function _streak(
  odds: (n: number) => number,
  options: ChanceOptions & { state?: { misses: number } },
): _Streak {
  const next = _next(options.generator);
  let misses = 0;
  if (options.state !== undefined) {
    const saved = (options.state as Partial<{ misses: number }> | null)?.misses;
    assertInteger(saved as number, "state.misses", _CHANCE, 0);
    misses = saved as number;
  }
  return {
    roll(): boolean {
      // A uniform draw in [0, 1) at 32-bit resolution.
      if (next(2 ** 32) / 2 ** 32 < odds(misses + 1)) {
        misses = 0;
        return true;
      }
      misses++;
      return false;
    },
    reset(): void {
      misses = 0;
    },
    get state(): { misses: number } {
      return { misses };
    },
  };
}

/** The long-run hit rate of `odds`, which must reach 1 by roll `maxRolls`. */
/* @__NO_SIDE_EFFECTS__ */
function _streakRate(odds: (n: number) => number, maxRolls: number): number {
  let hitByNow = 0;
  let expectedRolls = 0;
  for (let n = 1; n <= maxRolls; n++) {
    const hitOnN = odds(n) * (1 - hitByNow);
    hitByNow += hitOnN;
    expectedRolls += n * hitOnN;
  }
  return 1 / expectedRolls;
}

/* @__NO_SIDE_EFFECTS__ */
function _prdChance(p: number, options: PRDChanceOptions): PRDChance {
  const constant = _prdConstant(p);
  const streak = _streak((n) => Math.min(1, n * constant), options);
  return {
    model: "prd",
    probability: p,
    constant,
    roll: streak.roll,
    reset: streak.reset,
    get state(): PRDState {
      return streak.state;
    },
  };
}

/** The long-run hit rate of a PRD whose odds grow by `c` per miss. */
/* @__NO_SIDE_EFFECTS__ */
function _prdRate(c: number): number {
  return _streakRate((n) => Math.min(1, n * c), Math.ceil(1 / c));
}

/* @__NO_SIDE_EFFECTS__ */
function _pityChance(p: number, options: PityChanceOptions): PityChance {
  const hard = options.hard;
  assertInteger(hard, "hard", _CHANCE, 1);
  const soft = options.soft ?? hard;
  assertInteger(soft, "soft", _CHANCE, 0, hard);
  // Flat until `soft` rolls, a straight climb after, certain at `hard`.
  const odds = (n: number): number =>
    n >= hard ? 1 : n <= soft ? p : p + ((1 - p) * (n - soft)) / (hard - soft);
  const streak = _streak(odds, options);
  return {
    model: "pity",
    nominal: p,
    probability: _streakRate(odds, hard),
    hard,
    soft,
    roll: streak.roll,
    reset: streak.reset,
    get state(): PityState {
      return streak.state;
    },
  };
}

/** The increment whose long-run rate is `p`, by bisection: the rate grows with it. */
/* @__NO_SIDE_EFFECTS__ */
function _prdConstant(p: number): number {
  let low = 0;
  let high = p;
  let mid = p;
  for (let i = 0; i < 64 && high - low > 1e-12; i++) {
    mid = (low + high) / 2;
    if (_prdRate(mid) > p) high = mid;
    else low = mid;
  }
  return mid;
}
