# sanitizeObject()

In-place prototype-pollution sanitization. Removes `__proto__`, `prototype`, and `constructor` own properties recursively from plain objects and arrays.

## Signature

```ts
function sanitizeObject<T extends Record<string, unknown> | undefined>(obj: T): T;
```

Returns the same reference passed in (mutates in-place).

## Behavior

- Deep, in-place sanitization over objects and arrays
- Cycle-safe (handles circular references via `WeakSet`)
- Only own properties named exactly `__proto__`, `prototype`, and `constructor` are removed
- Leaves `Date`, `Map`, `Set`, functions, and primitives unchanged (but traverses into them if nested inside plain objects/arrays)
- `undefined` and non-object inputs are returned unchanged

## Examples

```ts
import { sanitizeObject } from "unsecure";

const payload = JSON.parse(untrustedInput);
sanitizeObject(payload); // mutates in-place, returns same ref

// Nested sanitization
const data = {
  user: {
    name: "alice",
    __proto__: { hacked: true },
    profile: [{ constructor: "bad" }, { prototype: { x: 1 } }],
  },
};
sanitizeObject(data);
// data.user no longer has __proto__
// data.user.profile[0] no longer has constructor
// data.user.profile[1] no longer has prototype
```

## Use Case: Sanitizing Untrusted JSON Input

```ts
import { sanitizeObject } from "unsecure";

function parseUntrustedJSON(raw: string): Record<string, unknown> {
  const parsed = JSON.parse(raw);
  return sanitizeObject(parsed);
}

// Express/Hono middleware pattern
function sanitizeMiddleware(req, res, next) {
  if (req.body && typeof req.body === "object") {
    sanitizeObject(req.body);
  }
  next();
}
```

## Pitfall: Assuming sanitizeObject() Clones the Input

It mutates in-place for performance and memory efficiency. If you need the original, clone first.

```ts
// ❌ Original is mutated
const original = JSON.parse(data);
sanitizeObject(original); // original is now modified

// ✅ Clone first if you need the original
const original = JSON.parse(data);
const safe = sanitizeObject(structuredClone(original));
```
