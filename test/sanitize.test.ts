import { describe, it, expect } from "vitest";
import { sanitizeObject } from "../src/index.ts";

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
    expect(Object.prototype.hasOwnProperty.call(obj, "constructor")).toBe(
      false,
    );
    // nested
    expect(Object.prototype.hasOwnProperty.call(obj.b, "__proto__")).toBe(
      false,
    );
    expect(Object.prototype.hasOwnProperty.call(obj.b, "prototype")).toBe(
      false,
    );
    expect(Object.prototype.hasOwnProperty.call(obj.b, "constructor")).toBe(
      false,
    );
    // deeper
    expect(Object.prototype.hasOwnProperty.call(obj.b.d, "__proto__")).toBe(
      false,
    );
    expect(Object.prototype.hasOwnProperty.call(obj.b.d, "prototype")).toBe(
      false,
    );
    expect(Object.prototype.hasOwnProperty.call(obj.b.d, "constructor")).toBe(
      false,
    );
    // array element
    expect(Object.prototype.hasOwnProperty.call(obj.e[0]!, "__proto__")).toBe(
      false,
    );
    expect(Object.prototype.hasOwnProperty.call(obj.e[0]!, "prototype")).toBe(
      false,
    );
    expect(Object.prototype.hasOwnProperty.call(obj.e[0]!, "constructor")).toBe(
      false,
    );
    expect(
      Object.prototype.hasOwnProperty.call((obj.e[0] as any).g, "__proto__"),
    ).toBe(false);
  });

  it("skips non-plain objects like Date, Map, Set, and functions", () => {
    const date = new Date();
    const map = new Map();
    const set = new Set();
    const fn = () => {};
    expect(sanitizeObject(date as any)).toBe(date);
    expect(sanitizeObject(map as any)).toBe(map);
    expect(sanitizeObject(set as any)).toBe(set);
    expect(sanitizeObject(fn as any)).toBe(fn);
  });

  it("handles objects with null prototype", () => {
    const obj = Object.create(null);
    (obj as any).safe = 1;
    (obj as any).constructor = 2;
    sanitizeObject(obj);
    expect(Object.prototype.hasOwnProperty.call(obj, "constructor")).toBe(
      false,
    );
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

  it("returns input unchanged for primitives and undefined", () => {
    expect(sanitizeObject(undefined)).toBeUndefined();
    expect(sanitizeObject(1 as any)).toBe(1);
    expect(sanitizeObject("x" as any)).toBe("x");
    expect(sanitizeObject(true as any)).toBe(true);
  });
});
