# sanitizeObject() / sanitizeObjectCopy() / safeJsonParse()

Prototype-pollution sanitization utilities. Remove own properties named `__proto__`, `prototype`, and `constructor` recursively from objects and arrays — at parse time, in-place, or into a copy.

## Signatures

```ts
// Mutates the input in place; returns the same reference.
function sanitizeObject<T extends Record<string, unknown> | undefined>(obj: T): T;

// Returns a sanitized deep copy; input is never mutated. Cycle-safe.
function sanitizeObjectCopy<T extends Record<string, unknown> | undefined>(obj: T): T;

// JSON.parse, then the in-place sanitizer. Any JSON root: object, array or primitive.
function safeJsonParse<T = any>(json: string): T;
```

## Which one to use

| If you…                                  | Use                        |
| ---------------------------------------- | -------------------------- |
| Receive JSON text and want one safe step | `safeJsonParse`            |
| Already have a parsed object you own     | `sanitizeObject` (fastest) |
| Must preserve the caller's object        | `sanitizeObjectCopy`       |

`safeJsonParse` parses and then sanitizes in place, so the value it returns holds no dangerous key at any depth. `sanitizeObject` is the fastest of the two post-parse variants — single-pass traversal, no intermediate allocations, mutates in place.

## Behavior

- Deep traversal over objects and arrays, driven by an explicit stack — nesting depth is bounded by memory, not by the call stack, so a deeply nested payload cannot overflow it.
- Cycle-safe (`sanitizeObject` uses `WeakSet`; `sanitizeObjectCopy` uses `WeakMap` and rewires cycles to point at the copied node, not the original).
- Only own properties named exactly `__proto__`, `prototype`, and `constructor` are removed.
- Object identity survives both: `sanitizeObject` strips dangerous own keys from every object it reaches and never replaces one; `sanitizeObjectCopy` rebuilds arrays and plain objects (rooted on `Object.prototype` or on `null`) and carries every other value — `Date`, `Map`, `Set`, typed arrays, `RegExp`, class instances, functions — into the copy by reference, so `copy.when === input.when` for a `Date`.
- `undefined` and non-object inputs are returned unchanged, as is a copy root that is not an array or plain object.
- `sanitizeObjectCopy` returns plain objects rooted on `Object.prototype` even when the input had a `null` prototype.

## Examples

```ts
import { safeJsonParse, sanitizeObject, sanitizeObjectCopy } from "unsecure/sanitize";

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
import { safeJsonParse, sanitizeObject } from "unsecure/sanitize";

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
- pushes child nodes onto a traversal stack without allocating an intermediate values array
- arrays iterate via numeric for-loop (faster than `Object.keys` on dense arrays)

For deep trees the single-pass walk noticeably reduces both allocations and branches compared to a "scan for bad keys, then scan values" approach.

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

These utilities strip dangerous **own properties** from arrays and plain objects. They do not re-home class instances, convert `Map`s, or alter prototype chains — a `Date` or a `Map` reached from a sanitized tree is the same object it was, dangerous own properties and all. If you need a strictly plain, fully-walked structure, feed the input through `safeJsonParse(JSON.stringify(obj))`.
