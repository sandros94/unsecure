import { type PRDState, type PityState, createCascade, createChance } from "unsecure/odds";

// #region docs
/** Each player's luck, kept on the server next to their inventory. */
interface PlayerLuck {
  legendary?: PityState;
  rare?: PRDState;
}

interface LuckStore {
  load(playerId: string): Promise<PlayerLuck>;
  save(playerId: string, luck: PlayerLuck): Promise<void>;
}

export async function openChest(
  store: LuckStore,
  playerId: string,
): Promise<"legendary" | "rare" | "common"> {
  const luck = await store.load(playerId);
  // 0.6% a chest, climbing after 74 misses, certain on the 90th.
  const legendary = createChance("pity", 0.006, { hard: 90, soft: 74, state: luck.legendary });
  // 5% a chest, with long droughts and lucky streaks smoothed out.
  const rare = createChance("prd", 0.05, { state: luck.rare });
  const loot = createCascade(["legendary", legendary], ["rare", rare], "common").draw();
  await store.save(playerId, { legendary: legendary.state, rare: rare.state });
  return loot;
}
// #endregion
