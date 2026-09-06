import type { DigestAlgorithm } from "../hash.ts";
import { normalizeAlgorithm } from "./algorithm.ts";
import { showValue } from "./assert.ts";
import { UnsecureError } from "../errors.ts";

/**
 * Recognize a Web Crypto key.
 *
 * The global is optional: a runtime can expose `crypto.subtle` without naming
 * `CryptoKey` on `globalThis`, and reading a missing global throws rather than
 * answering `false`. Where the class is absent no caller can be holding one of
 * its instances, so the value is bytes or a mistake either way.
 */
/* @__NO_SIDE_EFFECTS__ */
export function isCryptoKey(value: unknown): value is CryptoKey {
  return typeof CryptoKey !== "undefined" && value instanceof CryptoKey;
}

/**
 * Refuse a key that cannot do the job asked of it.
 *
 * Web Crypto reports the same mistake as an `InvalidAccessError` from inside
 * the operation, which says neither what the key was nor what was wanted; the
 * message here names both. It is `OUT_OF_RANGE` rather than `INVALID_TYPE`
 * because a `CryptoKey` is the right type — it is the wrong key.
 */
function _assertKey(key: CryptoKey, name: string, usage: KeyUsage, source: string): void {
  if (key.algorithm.name === name && key.usages.includes(usage)) return;
  throw new UnsecureError(
    "OUT_OF_RANGE",
    `${source}: key must be an ${name} key with the "${usage}" usage, got ${key.algorithm.name} with [${key.usages.join(", ")}].`,
  );
}

/**
 * Check a caller-supplied HMAC key, and that an explicit `algorithm` names the
 * hash it was imported with. A key carries its own hash, so an `algorithm`
 * option is a second statement of the same fact: agreeing with it silently
 * would let a caller believe a MAC was computed with a digest it was not.
 */
export function assertHmacKey(
  key: CryptoKey,
  algorithm: DigestAlgorithm | undefined,
  source: string,
): void {
  // The name is resolved first, so an algorithm the library does not know is
  // `UNSUPPORTED` whatever key it was paired with.
  const wanted = algorithm === undefined ? undefined : normalizeAlgorithm(algorithm, source);
  _assertKey(key, "HMAC", "sign", source);
  if (wanted === undefined) return;
  const hash = (key.algorithm as HmacKeyAlgorithm).hash.name.toUpperCase();
  if (hash !== wanted) {
    throw new UnsecureError(
      "OUT_OF_RANGE",
      `${source}: algorithm must match the key's hash ${hash}, got ${showValue(algorithm)}.`,
    );
  }
}

/** Check a caller-supplied HKDF key. HKDF keys carry no hash — `deriveBits` picks it. */
export function assertHkdfKey(key: CryptoKey, source: string): void {
  _assertKey(key, "HKDF", "deriveBits", source);
}
