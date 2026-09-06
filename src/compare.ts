import { type BytesSource, toBytes } from "./_internal/bytes.ts";

/** Stand-in for a `received` value that carries no bytes to compare. */
const EMPTY = /* @__PURE__ */ new Uint8Array(0);

export interface SecureCompareOptions {
  /**
   * When `true`, throws if `expected` is empty or undefined (pre-0.2 behavior).
   * When `false` (the default since 0.2), returns `false` instead so that
   * every failure mode produces the same result.
   *
   * Leaving this at the default is recommended for most code — the throw
   * is rarely what callers want, and can be used by an attacker to
   * distinguish "empty server value" from "mismatch".
   *
   * @default false
   */
  strict?: boolean;
}

/**
 * Compares two inputs (text or bytes) in a way that is safe against timing attacks.
 * It takes a constant amount of time to execute, regardless of whether the values match,
 * where the first difference occurs, or whether `received` carries any bytes at all.
 *
 * **Important:** The `expected` parameter determines the loop length. Always pass the
 * trusted, server-side value as `expected` and the untrusted, user-provided value as
 * `received`. Swapping them could leak length information about the attacker's input.
 *
 * @param expected The known, trusted value (e.g. a computed HMAC or stored token).
 *                 A string or any `BytesSource`. If empty or `undefined`, the function
 *                 returns `false` by default, or throws when `options.strict` is set.
 *                 Anything else is a caller bug and throws a {@link TypeError}.
 * @param received The untrusted, user-provided value to verify against `expected`.
 *                 A string or any `BytesSource` is compared; anything else — `null`,
 *                 `undefined`, a number, a plain array, an object — is a mismatch and
 *                 yields `false` in timing-safe fashion, never a throw.
 * @param options Behavior options. See {@link SecureCompareOptions.strict}.
 * @returns `true` if the values match, `false` otherwise.
 *
 * @throws {TypeError} If `expected` is neither text, bytes nor `undefined`.
 *
 * @example
 * // Comparing two strings
 * secureCompare('secret_token_123', 'secret_token_123'); // true
 * secureCompare('secret_token_123', 'wrong_token');      // false
 *
 * @example
 * // Comparing two Uint8Arrays
 * const mac1 = new Uint8Array([1, 2, 3]);
 * const mac2 = new Uint8Array([1, 2, 3]);
 * const mac3 = new Uint8Array([1, 2, 4]);
 *
 * secureCompare(mac1, mac2); // true
 * secureCompare(mac1, mac3); // false
 *
 * @example
 * // Comparing a string with a Uint8Array
 * const tokenBytes = new TextEncoder().encode('my_secure_token');
 * secureCompare('my_secure_token', tokenBytes); // true
 *
 * @example
 * // A missing header is a mismatch, not a crash
 * secureCompare(computedSignature, request.headers.get('x-signature')); // false when absent
 *
 * @example
 * // Opt-in strict mode throws on empty / undefined `expected`
 * secureCompare(undefined, 'x', { strict: true }); // throws
 */
export function secureCompare(
  expected: string | BytesSource | undefined,
  received: string | BytesSource | null | undefined,
  options?: SecureCompareOptions,
): boolean {
  const a =
    expected === undefined || expected === null ? EMPTY : toBytes(expected, "secureCompare");

  if (a.length === 0) {
    if (options?.strict) {
      throw new Error("Cannot verify. Expected value is empty or undefined.");
    }
    return false;
  }

  // `received` comes from the wire: a missing header, a JSON number or a
  // parsed array is a wrong value, not a caller bug, so it compares as no
  // bytes at all rather than throwing. The execution path stays the same
  // whichever it is — only `expected` decides how long the loop runs.
  let b: Uint8Array;
  try {
    b = received === undefined || received === null ? EMPTY : toBytes(received, "secureCompare");
  } catch {
    b = EMPTY;
  }

  let mismatch = a.length ^ b.length;

  // This ensures a constant number of loop iterations based on the expected length.
  for (const [i, element] of a.entries()) {
    // Bitwise OR (`|`) accumulates mismatches. If `element` and `b[i]` are
    // different, their XOR result will be non-zero.
    // Use 0 for out-of-bounds access to prevent `undefined` issues and
    // ensure a consistent comparison value.
    mismatch |= element ^ (b[i] ?? 0);
  }

  return mismatch === 0;
}
