import { textEncoder } from "./utils.ts";

/**
 * Compares two inputs (Uint8Array or string) in a way that is safe against timing attacks.
 * It takes a constant amount of time to execute, regardless of whether the values match,
 * where the first difference occurs, or if the `received` value is `undefined`.
 *
 * **Important:** The `expected` parameter determines the loop length. Always pass the
 * trusted, server-side value as `expected` and the untrusted, user-provided value as
 * `received`. Swapping them could leak length information about the attacker's input.
 *
 * @param expected The known, trusted value (e.g. a computed HMAC or stored token).
 *                 This argument is always expected to be present.
 * @param received The untrusted, user-provided value to verify against `expected`.
 *                 This argument can be undefined (returns `false`).
 * @returns `true` if the values match, `false` otherwise.
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
 * // Handling undefined received data in a timing-safe manner
 * secureCompare('some_expected_value', undefined); // false
 */
export function secureCompare(
  expected: Uint8Array | string,
  received: Uint8Array | string | undefined,
): boolean {
  if (!expected || expected.length === 0) {
    throw new Error("Cannot verify. Expected value is empty or undefined.");
  }

  const a = _toUint8Array(expected);

  // To prevent timing attacks, the execution path must be consistent
  // regardless of whether `received` is defined or not.
  let b: Uint8Array;
  let isReceivedUndefined = 0;

  if (received === undefined) {
    b = new Uint8Array(0);
    isReceivedUndefined = 1;
  } else {
    b = _toUint8Array(received);
  }

  let mismatch = isReceivedUndefined | (a.length ^ b.length);

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

function _toUint8Array(input: Uint8Array | string): Uint8Array {
  if (typeof input === "string") {
    return textEncoder.encode(input);
  }
  return input;
}
