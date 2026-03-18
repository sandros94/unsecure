# secureCompare()

Constant-time comparison to prevent timing attacks. Compares two values (string or `Uint8Array`) in a way that takes the same time regardless of where the first difference occurs.

## Signature

```ts
function secureCompare(
  expected: Uint8Array | string,
  received: Uint8Array | string | undefined,
): boolean;
```

**Critical rule:** The `expected` parameter (first argument) determines the loop length. Always pass the **trusted, server-side value** as `expected` and the **untrusted, user-provided value** as `received`.

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

// Handles undefined gracefully
secureCompare("expected", undefined); // false

// Throws if expected is empty
secureCompare("", "something"); // Error: Expected value is empty or undefined
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

## Note

`hmacVerify()` and all OTP verification functions use `secureCompare()` internally — you don't need to call it separately when using those APIs.
