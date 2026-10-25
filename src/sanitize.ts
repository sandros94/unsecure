import { describeValue } from "./_internal/bytes.ts";
import { ownOptions } from "./_internal/options.ts";
import { UnsecureError } from "./errors.ts";

/**
 * Parse JSON and strip prototype-pollution vectors from the result.
 *
 * `JSON.parse` runs first, then the in-place sanitizer walks the parsed value
 * and removes own properties named `__proto__`, `prototype`, or `constructor`
 * at every depth. Nothing holding a dangerous key survives the call — the
 * sanitizer finishes before the value is returned — and no caller-visible
 * object is ever assigned through, so no prototype is polluted along the way.
 *
 * Any JSON root is handled: objects, arrays, and primitives alike.
 *
 * @param json The JSON text to parse.
 * @returns The parsed value with dangerous keys stripped.
 * @throws {UnsecureError} `MALFORMED` if `json` is not valid JSON — the engine's
 *                         own error travels as `cause`; `FROZEN` if a dangerous key
 *                         sits on a frozen or sealed object, see
 *                         {@link sanitizeObject}.
 *
 * @example
 * const payload = safeJsonParse<{ user: { name: string } }>(untrustedInput);
 */
/* @__NO_SIDE_EFFECTS__ */
export function safeJsonParse<T = any>(json: string): T {
  let parsed: unknown;
  try {
    parsed = JSON.parse(json) as unknown;
  } catch (error) {
    // The engine's message says where the text stopped being JSON, which is
    // the useful half; the prefix says which call rejected it, like every
    // other message here.
    throw new UnsecureError("MALFORMED", `safeJsonParse: ${(error as Error).message}`, {
      cause: error,
    });
  }
  if (parsed === null || typeof parsed !== "object") return parsed as T;
  _sanitizeInPlace(parsed, new WeakSet<object>());
  return parsed as T;
}

/**
 * Remove prototype-pollution vectors from a plain record in-place.
 *
 * Strips own properties named `__proto__`, `prototype`, and `constructor`
 * through nested objects and arrays — a named property hung on an array
 * included — enumerable or not. Cycle-safe.
 *
 * Values are read from their property descriptors — array elements included —
 * so a getter is never invoked: an accessor is neither traversed nor removed
 * unless its name is one of the three. A `Proxy` is the exception and cannot
 * be otherwise: its traps run for every property operation, so a proxied
 * object is traversed through its own traps.
 *
 * Traversal reaches every object held in a data property, whatever its
 * prototype. What such an object *holds* internally is another matter: `Map`
 * entries, `Set` members and anything else living outside own properties are
 * never read, so they are never sanitized.
 *
 * Returns the same reference for convenience. Use {@link sanitizeObjectCopy}
 * if you need a deep copy with the original preserved.
 *
 * @throws {UnsecureError} `FROZEN` if a dangerous key cannot be removed because
 *                         the object holding it is frozen or sealed. Leaving the
 *                         key in place would report a sanitized object that is not
 *                         one.
 */
export function sanitizeObject<T extends Record<string, unknown> | undefined>(obj: T): T {
  if (!obj || typeof obj !== "object") return obj;
  _sanitizeInPlace(obj, new WeakSet<object>());
  return obj;
}

/** Options for {@link sanitizeObjectCopy}. */
export interface SanitizeCopyOptions {
  /**
   * Constructors whose instances the copy carries by reference, untouched.
   * Everything the copy meets must be JSON-shaped — a plain object or an
   * array — unless it is an instance (`instanceof`, so subclasses count) of
   * one of these. By reference means unchanged *and* unsanitized: an instance
   * listed here is trusted as the caller holds it.
   *
   * `instanceof` is bound to the realm the constructor came from, which is
   * the realm the caller's own `Date` or `Map` belong to.
   */
  allowlist?: Iterable<abstract new (...args: never[]) => object>;
}

/**
 * Return a sanitized deep copy of `obj`. The input is never mutated.
 *
 * Dangerous keys (`__proto__`, `prototype`, `constructor`) are stripped from
 * every array and plain object reached. A plain object is one rooted on
 * `null` or on an `Object.prototype` — this realm's or another's, so a value
 * parsed inside a `vm` context or a frame is rebuilt like one parsed here;
 * copies of both are rooted on this realm's `Object.prototype`.
 *
 * Anything else — a `Date`, `Map`, `Set`, typed array, `RegExp` or class
 * instance — is refused: such a value is not the JSON shape this copy exists
 * for, and carrying it through silently would report a sanitized copy that
 * holds an unexamined object. Name the constructors you trust in
 * `allowlist`, and their instances are carried into the copy by reference,
 * or use {@link sanitizeObject} to walk a live object graph in place.
 * Functions are values, not containers, and are carried by reference.
 *
 * Only own enumerable data properties are copied — the JSON shape. Accessors
 * are skipped rather than invoked, so the copy never runs caller code; an
 * accessor at an array index leaves a hole there and the elements after it
 * keep their positions. A `Proxy` is traversed through its own traps, which
 * run whatever the copy asks for.
 *
 * Cycle-safe: circular references in the input are preserved in the output
 * (pointing at the copied node, not the original reference).
 *
 * Primitives and `undefined` are returned unchanged.
 *
 * @throws {UnsecureError} `INVALID_TYPE` if an object that is neither plain,
 *                         an array nor an instance of an `allowlist` entry is
 *                         met at any depth, or if `allowlist` holds something
 *                         that is not a constructor.
 */
/* @__NO_SIDE_EFFECTS__ */
export function sanitizeObjectCopy<T>(obj: T, options?: SanitizeCopyOptions): T {
  const trusted = _allowlist(ownOptions(options).allowlist);
  if (obj === null || typeof obj !== "object") return obj;
  if (!_isCopyable(obj)) {
    if (_isTrusted(obj, trusted)) return obj;
    throw _notCopyable(obj);
  }
  return _sanitizeCopy(obj, trusted, new WeakMap<object, unknown>()) as T;
}

// #region Internal

/* @__NO_SIDE_EFFECTS__ */
function _isDangerousKey(key: string): boolean {
  return key === "__proto__" || key === "prototype" || key === "constructor";
}

/**
 * Traversal is an explicit stack rather than recursion: nesting depth comes
 * from the input, and a payload a few kilobytes long can nest deep enough to
 * exhaust the call stack.
 *
 * One pass over own *names*, arrays included: an array's names are the
 * indices it actually holds, `length`, and any named property hung on it —
 * which `JSON.parse` never produces but a structured clone carries — so a
 * dangerous name on an array is stripped like one on an object, and a sparse
 * array costs its elements, not its `length`. Own names rather than own
 * enumerable keys, because `Object.defineProperty` can hide a `__proto__`
 * from `Object.keys` while leaving it a live pollution vector. Values come
 * from the descriptor so a getter is never called — running caller code
 * inside a sanitizer would hand an attacker a side effect triggered by the
 * defence itself. An accessor is therefore neither traversed nor removed
 * unless its *name* is one of the three.
 */
function _sanitizeInPlace(root: object, seen: WeakSet<object>): void {
  seen.add(root);
  const stack: object[] = [root];

  while (stack.length > 0) {
    const record = stack.pop()! as Record<string, unknown>;
    const keys = Object.getOwnPropertyNames(record);
    for (let i = 0; i < keys.length; i++) {
      const key = keys[i]!;
      if (_isDangerousKey(key)) {
        if (!Reflect.deleteProperty(record, key)) {
          throw new UnsecureError(
            "FROZEN",
            `sanitizeObject: cannot remove "${key}" from a frozen object; use sanitizeObjectCopy().`,
          );
        }
        continue;
      }
      const descriptor = Object.getOwnPropertyDescriptor(record, key);
      if (descriptor === undefined || !("value" in descriptor)) continue;
      const v = descriptor.value as unknown;
      if (v !== null && typeof v === "object" && !seen.has(v)) {
        seen.add(v);
        stack.push(v);
      }
    }
  }
}

/** What `Object` prints as, in any realm: the one native constructor a plain object may have. */
const _OBJECT_SOURCE: string = /* @__PURE__ */ Function.prototype.toString.call(Object);

/**
 * An object the copy may safely rebuild: its own properties are all the state
 * it carries. Anything else — a `Date`'s internal slot, a `Map`'s entries, a
 * typed array's buffer, a class instance's identity — is invisible to a
 * property walk, so rebuilding it would silently drop what it is.
 *
 * Another realm's `Object.prototype` is not `===` this one's, so it is
 * recognized by shape: a root prototype whose own `constructor` is a native
 * `Object`. Read through the descriptor, so no getter runs; compared by
 * source text, so a class merely named `Object` does not pass. A forged root
 * carrying some realm's real `Object` only earns a rebuild, which strips it.
 */
/* @__NO_SIDE_EFFECTS__ */
function _isPlainObject(value: object): boolean {
  const proto = Object.getPrototypeOf(value) as object | null;
  if (proto === null || proto === Object.prototype) return true;
  if (Object.getPrototypeOf(proto) !== null) return false;
  const ctor = Object.getOwnPropertyDescriptor(proto, "constructor");
  return (
    ctor !== undefined &&
    "value" in ctor &&
    typeof ctor.value === "function" &&
    Function.prototype.toString.call(ctor.value) === _OBJECT_SOURCE
  );
}

/** Values the copy descends into. */
/* @__NO_SIDE_EFFECTS__ */
function _isCopyable(value: unknown): value is object {
  return (
    value !== null &&
    typeof value === "object" &&
    (Array.isArray(value) || _isPlainObject(value as object))
  );
}

type _Constructor = abstract new (...args: never[]) => object;

/** The constructors a copy trusts, checked once per call rather than per node. */
/* @__NO_SIDE_EFFECTS__ */
function _allowlist(value: Iterable<_Constructor> | undefined): _Constructor[] {
  if (value === undefined) return [];
  if (
    typeof value === "string" ||
    typeof (value as Iterable<unknown>)[Symbol.iterator] !== "function"
  ) {
    throw new UnsecureError(
      "INVALID_TYPE",
      `sanitizeObjectCopy: allowlist must be an iterable of constructors, got ${describeValue(value)}.`,
    );
  }
  const list: _Constructor[] = [];
  for (const entry of value) {
    if (typeof entry !== "function") {
      throw new UnsecureError(
        "INVALID_TYPE",
        `sanitizeObjectCopy: allowlist entries must be constructors, got ${describeValue(entry)}.`,
      );
    }
    list.push(entry);
  }
  return list;
}

/* @__NO_SIDE_EFFECTS__ */
function _isTrusted(value: object, trusted: readonly _Constructor[]): boolean {
  for (let i = 0; i < trusted.length; i++) if (value instanceof trusted[i]!) return true;
  return false;
}

/* @__NO_SIDE_EFFECTS__ */
function _notCopyable(value: object): UnsecureError {
  return new UnsecureError(
    "INVALID_TYPE",
    `sanitizeObjectCopy: cannot copy an instance of ${describeValue(value)}; add it to allowlist, or use sanitizeObject().`,
  );
}

/** One node still to be filled: its source and the empty container standing in for it. */
interface CopyTask {
  source: object;
  target: unknown[] | Record<string, unknown>;
}

/** Whether `key` is an array index as the language defines one: the canonical form of an integer below 2^32 - 1. */
/* @__NO_SIDE_EFFECTS__ */
function _isIndex(key: string): boolean {
  const n = Number(key);
  return n >>> 0 === n && n !== 0xffff_ffff && String(n) === key;
}

/**
 * Iterative for the same reason as {@link _sanitizeInPlace}: each node's
 * container is created and registered before its children are queued, so a
 * cycle resolves to the copy already standing in for it.
 */
function _sanitizeCopy(
  root: object,
  trusted: readonly _Constructor[],
  seen: WeakMap<object, unknown>,
): unknown {
  const rootTarget: unknown[] | Record<string, unknown> = Array.isArray(root) ? [] : {};
  seen.set(root, rootTarget);
  const stack: CopyTask[] = [{ source: root, target: rootTarget }];

  while (stack.length > 0) {
    const { source, target } = stack.pop()!;

    // Elements are read from their descriptors, so an accessor index is
    // skipped rather than invoked and a hole is not read through a polluted
    // `Array.prototype`. Both leave a hole at that index in the copy: the
    // length is set up front, so every other element keeps its position. Only
    // the indices present are visited — the names, not `0..length` — so a
    // sparse array costs its elements; a named property on an array is not
    // part of the JSON shape and is dropped.
    if (Array.isArray(source)) {
      const out = target as unknown[];
      out.length = source.length;
      const names = Object.getOwnPropertyNames(source);
      for (let i = 0; i < names.length; i++) {
        const key = names[i]!;
        if (!_isIndex(key)) continue;
        const descriptor = Object.getOwnPropertyDescriptor(source, key);
        if (descriptor === undefined || !("value" in descriptor)) continue;
        out[Number(key)] = _copyValue(descriptor.value as unknown, trusted, seen, stack);
      }
      continue;
    }

    // Own enumerable data properties only — the JSON shape. A getter is
    // skipped rather than called, for the same reason the in-place walk skips
    // one: the sanitizer must not run caller code.
    const out = target as Record<string, unknown>;
    const record = source as Record<string, unknown>;
    const keys = Object.keys(record);
    for (let i = 0; i < keys.length; i++) {
      const key = keys[i]!;
      if (_isDangerousKey(key)) continue;
      const descriptor = Object.getOwnPropertyDescriptor(record, key);
      if (descriptor === undefined || !("value" in descriptor)) continue;
      out[key] = _copyValue(descriptor.value as unknown, trusted, seen, stack);
    }
  }

  return rootTarget;
}

/** Resolve a child to its place in the copy, queueing it when it is new. */
function _copyValue(
  value: unknown,
  trusted: readonly _Constructor[],
  seen: WeakMap<object, unknown>,
  stack: CopyTask[],
): unknown {
  if (value === null || typeof value !== "object") return value;
  if (!_isCopyable(value)) {
    if (_isTrusted(value, trusted)) return value;
    throw _notCopyable(value);
  }
  const existing = seen.get(value);
  if (existing !== undefined) return existing;
  const target: unknown[] | Record<string, unknown> = Array.isArray(value) ? [] : {};
  seen.set(value, target);
  stack.push({ source: value, target });
  return target;
}
