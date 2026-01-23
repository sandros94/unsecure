import { textEncoder } from "./utils.ts";

/**
 * Compares two inputs (Uint8Array or string) in a way that is safe against timing attacks.
 * It takes a constant amount of time to execute, regardless of whether thearrays match
 * or where the first difference occurs, or if the `incoming` value is `undefined`.
 *
 * @param reference The known secure reference point. This argument is always expected to be present.
 * @param incoming The incoming data to be verified against the reference. This argument can be undefined.
 * @returns Returns a boolean if the data does match or not.
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
 * // Handling undefined incoming data in a timing-safe manner
 * secureCompare('some_reference', undefined); // false
 */
export function secureCompare(
  reference: Uint8Array | string,
  incoming: Uint8Array | string | undefined,
): boolean {
  if (!reference || reference.length === 0) {
    throw new Error("Cannot verify. Reference is undefined.");
  }

  const a = _toUint8Array(reference);

  // To prevent timing attacks, the execution path must be consistent
  // regardless of whether `incoming` is defined or not.
  let b: Uint8Array;
  let isIncomingUndefined = 0; // bitwise operation

  if (incoming === undefined) {
    b = new Uint8Array(0);
    isIncomingUndefined = 1;
  } else {
    b = _toUint8Array(incoming);
  }

  let mismatch = isIncomingUndefined || a.length ^ b.length;

  // This ensures a constant number of loop iterations based on the reference length.
  for (const [i, element] of a.entries()) {
    // Bitwise OR (`|`) accumulates mismatches. If `element` and `b[i]` are
    // different, their XOR result will be non-zero.
    // Use 0 for out-of-bounds access to prevent `undefined` issues and
    // ensure a consistent comparison value.
    mismatch |= element ^ (b[i] ?? 0);
  }

  return mismatch === 0;
}

/**
 * @deprecated Use `secureCompare` instead.
 */
export const secureVerify: typeof secureCompare = secureCompare;

function _toUint8Array(input: Uint8Array | string): Uint8Array {
  if (typeof input === "string") {
    return textEncoder.encode(input);
  }
  return input;
}
