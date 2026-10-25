import { secureRandomBytes, secureRandomNumber, secureShuffle } from "unsecure/random";

// #region docs
/** `count` distinct winners. The copy leaves the caller's list in its order. */
export function pickWinners(entries: readonly string[], count: number): string[] {
  return secureShuffle([...entries]).slice(0, count);
}

/** One roll of a six-sided die: 1 to 6. The upper bound is exclusive. */
export function rollDie(): number {
  return secureRandomNumber(1, 7);
}

/** A delay between 500 and 999 ms, so clients that failed together retry apart. */
export function retryDelayMs(): number {
  return secureRandomNumber(500, 1000);
}

/** 32 random bytes: key material for HMAC or encryption. */
export function newKeyMaterial(): Uint8Array {
  return secureRandomBytes(32);
}
// #endregion
