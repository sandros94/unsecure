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
 * @throws {SyntaxError} If `json` is not valid JSON.
 * @throws {TypeError} If a dangerous key sits on a frozen or sealed object —
 *                     see {@link sanitizeObject}.
 *
 * @example
 * const payload = safeJsonParse<{ user: { name: string } }>(untrustedInput);
 */
export function safeJsonParse<T = any>(json: string): T {
  const parsed = JSON.parse(json) as unknown;
  if (parsed === null || typeof parsed !== "object") return parsed as T;
  _sanitizeInPlace(parsed, new WeakSet<object>());
  return parsed as T;
}

/**
 * Remove prototype-pollution vectors from a plain record in-place.
 *
 * Strips own properties named `__proto__`, `prototype`, and `constructor`
 * through nested objects and arrays, enumerable or not. Cycle-safe.
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
 * @throws {TypeError} If a dangerous key cannot be removed because the object
 *                     holding it is frozen or sealed. Leaving the key in
 *                     place would report a sanitized object that is not one.
 */
export function sanitizeObject<T extends Record<string, unknown> | undefined>(obj: T): T {
  if (!obj || typeof obj !== "object") return obj;
  _sanitizeInPlace(obj, new WeakSet<object>());
  return obj;
}

/**
 * Return a sanitized deep copy of `obj`. The input is never mutated.
 *
 * Dangerous keys (`__proto__`, `prototype`, `constructor`) are stripped from
 * every array and plain object reached. A plain object is one rooted on
 * `Object.prototype` or on `null`; copies of both are rooted on
 * `Object.prototype`. Every other value — `Date`, `Map`, `Set`, typed
 * arrays, `RegExp`, class instances, functions — is carried into the copy by
 * reference, exactly as {@link sanitizeObject} leaves it in place. By
 * reference means unchanged *and* unsanitized: what a `Map` or `Set` holds is
 * never read by either function.
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
 * Non-object / undefined inputs — and objects that are not arrays or plain
 * objects — are returned unchanged.
 */
export function sanitizeObjectCopy<T extends Record<string, unknown> | undefined>(obj: T): T {
  if (!_isCopyable(obj)) return obj;
  return _sanitizeCopy(obj, new WeakMap<object, unknown>()) as T;
}

// #region Internal

function _isDangerousKey(key: string): boolean {
  return key === "__proto__" || key === "prototype" || key === "constructor";
}

/**
 * Traversal is an explicit stack rather than recursion: nesting depth comes
 * from the input, and a payload a few kilobytes long can nest deep enough to
 * exhaust the call stack.
 */
function _sanitizeInPlace(root: object, seen: WeakSet<object>): void {
  seen.add(root);
  const stack: object[] = [root];

  while (stack.length > 0) {
    const current = stack.pop()!;

    // Array branch: numeric for-loop avoids the Object.keys alloc for dense
    // arrays. Elements come from their descriptors for the same reason the
    // object branch reads them that way — an index can hold an accessor, and a
    // hole would otherwise be read through a polluted `Array.prototype`.
    if (Array.isArray(current)) {
      for (let i = 0; i < current.length; i++) {
        const descriptor = Object.getOwnPropertyDescriptor(current, i);
        if (descriptor === undefined || !("value" in descriptor)) continue;
        const v = descriptor.value as unknown;
        if (v !== null && typeof v === "object" && !seen.has(v)) {
          seen.add(v);
          stack.push(v);
        }
      }
      continue;
    }

    // Object branch: single pass — inline the dangerous-key check and queue
    // children in the same loop, so we neither allocate a values array nor
    // scan twice.
    //
    // Own *names*, not own enumerable keys: `Object.defineProperty` can hide a
    // `__proto__` from `Object.keys` while leaving it a live pollution vector.
    // Values come from the descriptor so a getter is never called — running
    // caller code inside a sanitizer would hand an attacker a side effect
    // triggered by the defence itself. An accessor is therefore neither
    // traversed nor removed unless its *name* is one of the three.
    const record = current as Record<string, unknown>;
    const keys = Object.getOwnPropertyNames(record);
    for (let i = 0; i < keys.length; i++) {
      const key = keys[i]!;
      if (_isDangerousKey(key)) {
        if (!Reflect.deleteProperty(record, key)) {
          throw new TypeError(
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

/**
 * An object the copy may safely rebuild: its own properties are all the state
 * it carries. Anything else — a `Date`'s internal slot, a `Map`'s entries, a
 * typed array's buffer, a class instance's identity — is invisible to a
 * property walk, so rebuilding it would silently drop what it is.
 */
function _isPlainObject(value: object): boolean {
  const proto = Object.getPrototypeOf(value);
  return proto === Object.prototype || proto === null;
}

/** Values the copy descends into; everything else is carried by reference. */
function _isCopyable(value: unknown): value is object {
  return (
    value !== null &&
    typeof value === "object" &&
    (Array.isArray(value) || _isPlainObject(value as object))
  );
}

/** One node still to be filled: its source and the empty container standing in for it. */
interface CopyTask {
  source: object;
  target: unknown[] | Record<string, unknown>;
}

/**
 * Iterative for the same reason as {@link _sanitizeInPlace}: each node's
 * container is created and registered before its children are queued, so a
 * cycle resolves to the copy already standing in for it.
 */
function _sanitizeCopy(root: object, seen: WeakMap<object, unknown>): unknown {
  const rootTarget: unknown[] | Record<string, unknown> = Array.isArray(root) ? [] : {};
  seen.set(root, rootTarget);
  const stack: CopyTask[] = [{ source: root, target: rootTarget }];

  while (stack.length > 0) {
    const { source, target } = stack.pop()!;

    // Elements are read from their descriptors, so an accessor index is
    // skipped rather than invoked and a hole is not read through a polluted
    // `Array.prototype`. Both leave a hole at that index in the copy: the
    // length is set up front, so every other element keeps its position.
    if (Array.isArray(source)) {
      const out = target as unknown[];
      out.length = source.length;
      for (let i = 0; i < source.length; i++) {
        const descriptor = Object.getOwnPropertyDescriptor(source, i);
        if (descriptor === undefined || !("value" in descriptor)) continue;
        out[i] = _copyValue(descriptor.value as unknown, seen, stack);
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
      out[key] = _copyValue(descriptor.value as unknown, seen, stack);
    }
  }

  return rootTarget;
}

/** Resolve a child to its place in the copy, queueing it when it is new. */
function _copyValue(value: unknown, seen: WeakMap<object, unknown>, stack: CopyTask[]): unknown {
  if (!_isCopyable(value)) return value;
  const existing = seen.get(value);
  if (existing !== undefined) return existing;
  const target: unknown[] | Record<string, unknown> = Array.isArray(value) ? [] : {};
  seen.set(value, target);
  stack.push({ source: value, target });
  return target;
}
