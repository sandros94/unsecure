# secureCompare()

Constant-time comparison to prevent timing attacks. Compares two values (a string or any byte container: `Uint8Array`, `ArrayBuffer`, `DataView`, a `SharedArrayBuffer`-backed view, …) in a way that takes the same time regardless of where the first difference occurs.

## Signature

```ts
function secureCompare(
  expected: string | BytesSource | undefined,
  received: string | BytesSource | null | undefined,
  options?: { strict?: boolean }, // default: { strict: false }
): boolean;
```

**Critical rule:** The `expected` parameter (first argument) determines the loop length. Always pass the **trusted, server-side value** as `expected` and the **untrusted, user-provided value** as `received`.

**`received` behavior:** `received` is untrusted input. A string or any `BytesSource` is compared; anything else — `null` from a missing header, `undefined` from a missing DB column, a number or an array out of a JSON body — is a mismatch and returns `false` without throwing. A wrong `expected` type is a bug in your own code and throws an `UnsecureError` with code `INVALID_TYPE` (see [errors.md](./errors.md)).

**Empty / undefined `expected` behavior:**

- **Default (`strict: false`, since 0.2):** returns `false`. Same failure mode as a mismatch — no distinguishable error path.
- **`strict: true`:** throws `"Cannot verify. Expected value is empty or undefined."` Useful during development to surface bugs where a server-side secret failed to load; avoid in attacker-reachable code paths, since the throw can be used as a side-channel.

## Examples

```ts
import { secureCompare } from "unsecure";

// Compare strings
secureCompare("expected-token", "received-token"); // false
secureCompare("match", "match"); // true

// Compare Uint8Arrays
const a = new Uint8Array([1, 2, 3]);
const b = new Uint8Array([1, 2, 3]);
secureCompare(a, b); // true

// Mixed types work (compared as UTF-8 bytes)
secureCompare("hello", new TextEncoder().encode("hello")); // true

// Handles undefined / empty gracefully (returns false, no throw)
secureCompare("expected", undefined); // false
secureCompare("expected", req.headers.get("x-signature")); // false when absent — no `!` needed
secureCompare("expected", 12345); // false — not text or bytes
secureCompare("", "something"); // false
secureCompare(undefined, undefined); // false — never "empty matches empty"

// Strict mode surfaces server-side bugs
secureCompare(undefined, "x", { strict: true }); // throws
```

## Pitfall: Swapping Arguments

The **first** argument determines loop length. Swapping leaks length information about the attacker's input.

```ts
// ❌ WRONG — leaks info about attacker's input length
secureCompare(userInput, serverToken);

// ✅ CORRECT — server value first, user input second
secureCompare(serverToken, userInput);
```

## Pitfall: Using `===` for Secret Comparison

Standard equality checks short-circuit on the first mismatch, leaking timing information.

```ts
// ❌ Vulnerable to timing attacks
if (storedToken === receivedToken) { ... }

// ✅ Use constant-time comparison
if (secureCompare(storedToken, receivedToken)) { ... }
```

## Pitfall: Enabling `strict: true` in Handlers

`strict: true` makes a missing server-side value throw rather than return `false`. In request-handler code paths this is a side-channel: an attacker can tell apart "secret lookup failed" (throws, becomes a 500) from "wrong signature" (returns false, becomes a 403). Prefer the default in any code reachable by an attacker and handle "missing secret" explicitly with a separate check if you need to fail loudly during boot.

```ts
// ❌ Attacker can distinguish via status code
const valid = secureCompare(serverSecret, userInput, { strict: true });

// ✅ Default mode + explicit boot-time invariant check
if (!serverSecret) throw new Error("BOOT: serverSecret is not configured");
const valid = secureCompare(serverSecret, userInput);
```

## Note

`hmacVerify()` and all OTP verification functions use `secureCompare()` internally — you don't need to call it separately when using those APIs.
