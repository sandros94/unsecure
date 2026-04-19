/**
 * Parse JSON while stripping prototype-pollution vectors during parsing.
 *
 * Uses a reviver to drop own properties named `__proto__`, `prototype`, or
 * `constructor` before they can be assigned. For nested payloads this is
 * cheaper than parsing first and sanitizing after, and it guarantees no
 * unsanitized object ever exists.
 *
 * @param json The JSON text to parse.
 * @returns The parsed value with dangerous keys stripped.
 * @throws {SyntaxError} If `json` is not valid JSON.
 *
 * @example
 * const payload = safeJsonParse<{ user: { name: string } }>(untrustedInput);
 */
export function safeJsonParse<T = any>(json: string): T {
  return JSON.parse(json, _jsonReviver) as T;
}

/**
 * Remove prototype-pollution vectors from a plain record in-place.
 *
 * Strips own properties named `__proto__`, `prototype`, and `constructor`
 * recursively through nested objects and arrays. Cycle-safe.
 *
 * Returns the same reference for convenience. Use {@link sanitizeObjectCopy}
 * if you need a deep copy with the original preserved.
 */
export function sanitizeObject<T extends Record<string, unknown> | undefined>(obj: T): T {
  if (!obj || typeof obj !== "object") return obj;
  const seen = new WeakSet<object>();
  seen.add(obj);
  _sanitizeInPlace(obj as Record<string, unknown>, seen);
  return obj;
}

/**
 * Return a sanitized deep copy of `obj`. The input is never mutated.
 *
 * Dangerous keys (`__proto__`, `prototype`, `constructor`) are stripped
 * recursively. The returned structure consists of plain objects (rooted on
 * `Object.prototype`) and arrays. Cycle-safe: circular references in the
 * input are preserved in the output (pointing at the copied node, not the
 * original reference).
 *
 * Non-object / undefined inputs are returned unchanged.
 */
export function sanitizeObjectCopy<T extends Record<string, unknown> | undefined>(obj: T): T {
  if (!obj || typeof obj !== "object") return obj;
  return _sanitizeCopy(obj, new WeakMap<object, unknown>()) as T;
}

// #region Internal

const _jsonReviver = (key: string, value: unknown): unknown =>
  _isDangerousKey(key) ? undefined : value;

function _isDangerousKey(key: string): boolean {
  return key === "__proto__" || key === "prototype" || key === "constructor";
}

function _sanitizeInPlace(current: Record<string, unknown> | unknown[], seen: WeakSet<object>) {
  // Array branch: numeric for-loop avoids the Object.keys alloc for dense arrays.
  if (Array.isArray(current)) {
    for (let i = 0; i < current.length; i++) {
      const v = current[i];
      if (v !== null && typeof v === "object" && !seen.has(v)) {
        seen.add(v);
        _sanitizeInPlace(v as Record<string, unknown> | unknown[], seen);
      }
    }
    return;
  }

  // Object branch: single pass — inline the dangerous-key check and recurse
  // in the same loop, so we neither allocate a values array nor scan twice.
  const keys = Object.keys(current);
  for (let i = 0; i < keys.length; i++) {
    const key = keys[i]!;
    if (_isDangerousKey(key)) {
      delete current[key];
      continue;
    }
    const v = current[key];
    if (v !== null && typeof v === "object" && !seen.has(v)) {
      seen.add(v);
      _sanitizeInPlace(v as Record<string, unknown> | unknown[], seen);
    }
  }
}

function _sanitizeCopy(current: object, seen: WeakMap<object, unknown>): unknown {
  // If we've already started copying this node, return that copy so cycles
  // in the input become cycles in the output (pointing at new nodes, not old).
  const existing = seen.get(current);
  if (existing !== undefined) return existing;

  if (Array.isArray(current)) {
    const out: unknown[] = [];
    seen.set(current, out);
    for (let i = 0; i < current.length; i++) {
      const v = current[i];
      out.push(v !== null && typeof v === "object" ? _sanitizeCopy(v, seen) : v);
    }
    return out;
  }

  const out: Record<string, unknown> = {};
  seen.set(current, out);
  const keys = Object.keys(current);
  for (let i = 0; i < keys.length; i++) {
    const key = keys[i]!;
    if (_isDangerousKey(key)) continue;
    const v = (current as Record<string, unknown>)[key];
    out[key] = v !== null && typeof v === "object" ? _sanitizeCopy(v, seen) : v;
  }
  return out;
}
