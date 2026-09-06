import { describeValue } from "./bytes.ts";
import type { DigestAlgorithm } from "../hash.ts";

/**
 * Digest output size in bytes — RFC 5869 calls it HashLen. Doubles as the
 * registry of algorithms the library accepts: a name is supported exactly
 * when it has a length here.
 */
export const HASH_LENGTH: Record<DigestAlgorithm, number> = {
  "SHA-1": 20,
  "SHA-256": 32,
  "SHA-384": 48,
  "SHA-512": 64,
};

const SUPPORTED = /* @__PURE__ */ Object.keys(HASH_LENGTH).join(", ");

/**
 * Resolve a caller's algorithm name to its canonical spelling.
 *
 * Web Crypto matches these names case-insensitively but reports an unknown one
 * as an opaque `NotSupportedError`, and a name it accepts in one call can be a
 * table miss in ours. Every entry point resolves through here so the accepted
 * set is one list, checked before any platform call.
 */
/* @__NO_SIDE_EFFECTS__ */
export function normalizeAlgorithm(name: string, source: string): DigestAlgorithm {
  if (typeof name !== "string") {
    throw new TypeError(`${source}: expected an algorithm name, got ${describeValue(name)}.`);
  }
  const canonical = name.toUpperCase();
  if (!Object.hasOwn(HASH_LENGTH, canonical)) {
    throw new RangeError(
      `${source}: unsupported algorithm "${name}"; expected one of ${SUPPORTED}.`,
    );
  }
  return canonical as DigestAlgorithm;
}
