import { describe, it, expect } from "vitest";
import { safeJsonParse, sanitizeObject, sanitizeObjectCopy } from "../src/index.ts";

function withDangerousKeys() {
  const o: Record<string, unknown> = {};
  (o as any).prototype = { x: 1 };
  (o as any).constructor = function C() {};
  (o as any)["__proto__"] = { poisoned: true };
  return o;
}

describe("sanitizeObject", () => {
  it("returns same reference and removes dangerous top-level keys", () => {
    const o = withDangerousKeys();
    const ref = sanitizeObject(o);
    expect(ref).toBe(o);

    expect(Object.prototype.hasOwnProperty.call(o, "__proto__")).toBe(false);
    expect(Object.prototype.hasOwnProperty.call(o, "prototype")).toBe(false);
    expect(Object.prototype.hasOwnProperty.call(o, "constructor")).toBe(false);
  });

  it("deeply removes dangerous keys from nested objects", () => {
    const obj: any = {
      a: 1,
      b: { c: 2, d: withDangerousKeys() },
      e: [{ f: 3, g: withDangerousKeys() }],
    };
    sanitizeObject(obj);
    // top
    expect(Object.prototype.hasOwnProperty.call(obj, "__proto__")).toBe(false);
    expect(Object.prototype.hasOwnProperty.call(obj, "prototype")).toBe(false);
    expect(Object.prototype.hasOwnProperty.call(obj, "constructor")).toBe(false);
    // nested
    expect(Object.prototype.hasOwnProperty.call(obj.b, "__proto__")).toBe(false);
    expect(Object.prototype.hasOwnProperty.call(obj.b, "prototype")).toBe(false);
    expect(Object.prototype.hasOwnProperty.call(obj.b, "constructor")).toBe(false);
    // deeper
    expect(Object.prototype.hasOwnProperty.call(obj.b.d, "__proto__")).toBe(false);
    expect(Object.prototype.hasOwnProperty.call(obj.b.d, "prototype")).toBe(false);
    expect(Object.prototype.hasOwnProperty.call(obj.b.d, "constructor")).toBe(false);
    // array element
    expect(Object.prototype.hasOwnProperty.call(obj.e[0]!, "__proto__")).toBe(false);
    expect(Object.prototype.hasOwnProperty.call(obj.e[0]!, "prototype")).toBe(false);
    expect(Object.prototype.hasOwnProperty.call(obj.e[0]!, "constructor")).toBe(false);
    expect(Object.prototype.hasOwnProperty.call((obj.e[0] as any).g, "__proto__")).toBe(false);
  });

  it("handles objects with null prototype", () => {
    const obj = Object.create(null);
    (obj as any).safe = 1;
    (obj as any).constructor = 2;
    sanitizeObject(obj);
    expect(Object.prototype.hasOwnProperty.call(obj, "constructor")).toBe(false);
    expect((obj as any).safe).toBe(1);
  });

  it("is safe with cyclic references", () => {
    const a: any = { x: 1 };
    const b: any = { y: 2 };
    a.self = a;
    a.b = b;
    b.a = a;
    (a as any)["__proto__"] = {};
    (b as any).prototype = {};

    sanitizeObject(a);

    expect(Object.prototype.hasOwnProperty.call(a, "__proto__")).toBe(false);
    expect(Object.prototype.hasOwnProperty.call(b, "prototype")).toBe(false);
    // sanity: structure intact
    expect(a.b).toBe(b);
    expect(a.self).toBe(a);
  });

  it("removes __proto__ when it is an actual own property", () => {
    // JSON.parse creates __proto__ as an actual own property (unlike assignment)
    const obj = JSON.parse('{"__proto__": {"poisoned": true}, "safe": 1}');
    expect(Object.prototype.hasOwnProperty.call(obj, "__proto__")).toBe(true);

    sanitizeObject(obj);
    expect(Object.prototype.hasOwnProperty.call(obj, "__proto__")).toBe(false);
    expect(obj.safe).toBe(1);
  });

  it("removes nested __proto__ own properties created via JSON.parse", () => {
    const obj = JSON.parse('{"nested": {"__proto__": {"evil": true}}}');
    expect(Object.prototype.hasOwnProperty.call(obj.nested, "__proto__")).toBe(true);

    sanitizeObject(obj);
    expect(Object.prototype.hasOwnProperty.call(obj.nested, "__proto__")).toBe(false);
  });

  it("returns input unchanged for primitives and undefined", () => {
    expect(sanitizeObject(undefined)).toBeUndefined();
    expect(sanitizeObject(1 as any)).toBe(1);
    expect(sanitizeObject("x" as any)).toBe("x");
    expect(sanitizeObject(true as any)).toBe(true);
  });

  it("preserves null values (does not recurse into them)", () => {
    const obj: any = { a: null, b: { c: null } };
    sanitizeObject(obj);
    expect(obj.a).toBeNull();
    expect(obj.b.c).toBeNull();
  });
});

describe("sanitizeObjectCopy", () => {
  it("returns a new reference and does not mutate the input", () => {
    const original = JSON.parse('{"__proto__": {"x": 1}, "safe": 2, "nested": {"y": 3}}');
    const nestedBefore = original.nested;

    const copy = sanitizeObjectCopy(original);

    expect(copy).not.toBe(original);
    // Input is untouched
    expect(Object.prototype.hasOwnProperty.call(original, "__proto__")).toBe(true);
    expect(original.nested).toBe(nestedBefore);
    // Copy is clean
    expect(Object.prototype.hasOwnProperty.call(copy, "__proto__")).toBe(false);
    expect(copy.safe).toBe(2);
    expect(copy.nested).not.toBe(nestedBefore);
    expect(copy.nested).toEqual({ y: 3 });
  });

  it("strips dangerous keys at every depth", () => {
    const input = JSON.parse(
      '{"a": {"__proto__": {"evil": true}, "k": 1}, "b": [{"constructor": "x", "ok": 2}]}',
    );
    const copy = sanitizeObjectCopy(input);
    expect(Object.prototype.hasOwnProperty.call(copy.a, "__proto__")).toBe(false);
    expect(copy.a.k).toBe(1);
    expect(Object.prototype.hasOwnProperty.call(copy.b[0], "constructor")).toBe(false);
    expect(copy.b[0].ok).toBe(2);
  });

  it("copies arrays as new arrays", () => {
    const input = { list: [1, 2, { nested: 3 }] };
    const copy = sanitizeObjectCopy(input);
    expect(copy.list).not.toBe(input.list);
    expect((copy.list as any)[2]).not.toBe(input.list[2]);
    expect(Array.isArray(copy.list)).toBe(true);
    expect(copy.list).toEqual([1, 2, { nested: 3 }]);
  });

  it("preserves cycles pointing at the copied node (not the original)", () => {
    const a: any = { name: "a" };
    a.self = a;
    a.child = { back: a };

    const copy = sanitizeObjectCopy(a) as any;

    // Cycle preserved, but pointing at the copied node
    expect(copy.self).toBe(copy);
    expect(copy.child.back).toBe(copy);
    // Never leaks the original reference
    expect(copy.self).not.toBe(a);
    expect(copy.child.back).not.toBe(a);
  });

  it("copy is rooted on Object.prototype even if input had null prototype", () => {
    const input = Object.create(null);
    (input as any).safe = 1;
    const copy = sanitizeObjectCopy(input);
    expect(Object.getPrototypeOf(copy)).toBe(Object.prototype);
    expect(copy.safe).toBe(1);
  });

  it("returns input unchanged for primitives and undefined", () => {
    expect(sanitizeObjectCopy(undefined)).toBeUndefined();
    expect(sanitizeObjectCopy(1 as any)).toBe(1);
    expect(sanitizeObjectCopy("x" as any)).toBe("x");
    expect(sanitizeObjectCopy(true as any)).toBe(true);
  });
});

describe("safeJsonParse", () => {
  it("strips __proto__ during parse (never appears on the result)", () => {
    const result = safeJsonParse<{ safe: number }>('{"__proto__": {"poisoned": true}, "safe": 1}');
    expect(Object.prototype.hasOwnProperty.call(result, "__proto__")).toBe(false);
    expect(result.safe).toBe(1);
    // No prototype pollution occurred on plain objects afterwards
    expect(({} as any).poisoned).toBeUndefined();
  });

  it("strips dangerous keys at nested depths", () => {
    const result = safeJsonParse<any>(
      '{"nested": {"__proto__": {"x": 1}, "constructor": "c", "prototype": "p", "ok": 2}}',
    );
    const nested = result.nested;
    expect(Object.prototype.hasOwnProperty.call(nested, "__proto__")).toBe(false);
    expect(Object.prototype.hasOwnProperty.call(nested, "constructor")).toBe(false);
    expect(Object.prototype.hasOwnProperty.call(nested, "prototype")).toBe(false);
    expect(nested.ok).toBe(2);
  });

  it("preserves safe keys and array ordering", () => {
    const result = safeJsonParse<any>('{"a": 1, "b": [1, 2, {"c": 3}]}');
    expect(result).toEqual({ a: 1, b: [1, 2, { c: 3 }] });
  });

  it("propagates SyntaxError for invalid JSON", () => {
    expect(() => safeJsonParse("not json")).toThrow(SyntaxError);
  });
});
