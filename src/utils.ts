export * from "./internal/utils/base32.ts";
export * from "./internal/utils/base64.ts";
export * from "./internal/utils/hex.ts";

export const textEncoder: TextEncoder = /* @__PURE__ */ new TextEncoder();
export const textDecoder: TextDecoder = /* @__PURE__ */ new TextDecoder();

/**
 * Add a random delay in milliseconds. Useful as defense-in-depth against timing side-channels.
 *
 * - `randomJitter()` — delay between 0 and 99ms
 * - `randomJitter(maxMs)` — delay between 0 and `maxMs - 1`
 * - `randomJitter(minMs, maxMs)` — delay between `minMs` and `maxMs - 1`
 */
export function randomJitter(maxMs?: number): Promise<void>;
export function randomJitter(minMs: number, maxMs: number): Promise<void>;
export function randomJitter(minOrMax = 100, maxMs?: number): Promise<void> {
  const min = maxMs === undefined ? 0 : minOrMax;
  const max = maxMs === undefined ? minOrMax : maxMs;
  const buf = new Uint32Array(1);
  crypto.getRandomValues(buf);
  return new Promise((resolve) => setTimeout(resolve, min + (buf[0] % (max - min))));
}
