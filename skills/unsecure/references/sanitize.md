# sanitizeObject() / sanitizeObjectCopy() / safeJsonParse()

Prototype-pollution sanitization utilities. Remove own properties named `__proto__`, `prototype`, and `constructor` recursively from objects and arrays — at parse time, in-place, or into a copy.

## Signatures

```ts
// Mutates the input in place; returns the same reference.
function sanitizeObject<T extends Record<string, unknown> | undefined>(obj: T): T;

// Returns a sanitized deep copy; input is never mutated. Cycle-safe.
function sanitizeObjectCopy<T extends Record<string, unknown> | undefined>(obj: T): T;

// Strips dangerous keys during JSON.parse via a reviver (never materializes them).
function safeJsonParse<T = unknown>(json: string): T;
```

## Which one to use

| If you…                                  | Use                        |
| ---------------------------------------- | -------------------------- |
| Receive JSON text and want one safe step | `safeJsonParse`            |
| Already have a parsed object you own     | `sanitizeObject` (fastest) |
| Must preserve the caller's object        | `sanitizeObjectCopy`       |

`safeJsonParse` is cheapest because dangerous keys never materialize on the parsed result (the reviver drops them before assignment). `sanitizeObject` is the fastest of the two post-parse variants — single-pass traversal, no intermediate allocations, mutates in place.

## Behavior

- Deep traversal over objects and arrays.
- Cycle-safe (`sanitizeObject` uses `WeakSet`; `sanitizeObjectCopy` uses `WeakMap` and rewires cycles to point at the copied node, not the original).
- Only own properties named exactly `__proto__`, `prototype`, and `constructor` are removed.
- Leaves `Date`, `Map`, `Set`, functions, and primitives unchanged (but traverses into them if nested inside plain objects/arrays).
- `undefined` and non-object inputs are returned unchanged.
- `sanitizeObjectCopy` returns plain objects rooted on `Object.prototype` even when the input had a `null` prototype.

## Examples

```ts
import { safeJsonParse, sanitizeObject, sanitizeObjectCopy } from "unsecure";

// 1. Parse + sanitize in one step
const payload = safeJsonParse<{ user: { name: string } }>(untrustedInput);

// 2. Post-parse, mutate in-place (cheapest on hot paths)
const parsed = JSON.parse(untrustedInput);
sanitizeObject(parsed); // same reference returned

// 3. Post-parse, keep the caller's object untouched
const safe = sanitizeObjectCopy(caller.body);
```

## Use Case: Sanitizing Untrusted JSON Input (middleware)

```ts
import { safeJsonParse, sanitizeObject } from "unsecure";

// Express / Hono: mutate the body in place
function sanitizeMiddleware(req, res, next) {
  if (req.body && typeof req.body === "object") {
    sanitizeObject(req.body);
  }
  next();
}

// Or do both parse + sanitize up front
async function readBody(req: Request) {
  const text = await req.text();
  return safeJsonParse(text);
}
```

## Performance

`sanitizeObject` does a single pass over each node:

- iterates `Object.keys(current)` once
- inlines the dangerous-key check into that same loop (no speculative `hasOwnProperty` + `delete` on absent keys)
- recurses on values without allocating an intermediate values array
- arrays iterate via numeric for-loop (faster than `Object.keys` on dense arrays)

For deep trees the single-pass rewrite noticeably reduces both allocations and branches compared to a "scan for bad keys, then scan values" approach.

## Pitfall: Mutation (`sanitizeObject`) vs Copy (`sanitizeObjectCopy`)

```ts
// ❌ Original is mutated — may surprise callers that still hold a reference
const original = JSON.parse(data);
sanitizeObject(original);

// ✅ If you don't own the object, use the copy variant
const safe = sanitizeObjectCopy(caller.body);

// ✅ Or parse into a fresh object with safeJsonParse, then do whatever
const safe2 = safeJsonParse(rawText);
```

## Pitfall: Assuming Non-Plain Objects Are Sanitized "Hard"

These utilities strip dangerous **own properties**. They do not re-home class instances, convert `Map`s, or alter prototype chains. If you need a strictly plain object, use `sanitizeObjectCopy` (it rebuilds onto `Object.prototype`) or feed the input through `safeJsonParse(JSON.stringify(obj))`.
