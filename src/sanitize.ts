/**
 * Remove prototype-pollution vectors from a plain record in-place.
 * This strips __proto__, prototype, and constructor own properties.
 * Returns the same reference for convenience.
 */
export function sanitizeObject<T extends Record<string, unknown> | undefined>(obj: T): T {
  // Fast-path for non-objects and undefined
  if (!obj || typeof obj !== "object") return obj;

  const seen = new WeakSet<object>();
  seen.add(obj);
  sanitizeKeys(obj as any, seen);
  return obj;
}

function sanitizeKeys(current: any, seen: WeakSet<object>) {
  // Remove dangerous own-properties
  if (Object.prototype.hasOwnProperty.call(current, "__proto__")) delete current["__proto__"];
  if (Object.prototype.hasOwnProperty.call(current, "prototype")) delete current["prototype"];
  if (Object.prototype.hasOwnProperty.call(current, "constructor")) delete current["constructor"];

  const items = Array.isArray(current) ? current : Object.values(current);
  for (const v of items) {
    if (v && typeof v === "object") {
      if (!seen.has(v)) {
        seen.add(v);
        sanitizeKeys(v, seen);
      }
    }
  }
}
