import { describe, it, expect } from "vitest";
import { safeJsonParse, sanitizeObject, sanitizeObjectCopy } from "../src/sanitize.ts";
import { expectUnsecureError } from "./_helpers.ts";

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

  it("reports invalid JSON as MALFORMED, keeping the engine's own error as cause", () => {
    const error = expectUnsecureError(() => safeJsonParse("not json"), "MALFORMED");
    expect(error.message.startsWith("safeJsonParse: ")).toBe(true);
    expect(error.cause).toBeInstanceOf(SyntaxError);
  });
});

describe("sanitizeObjectCopy refusal and allowlist", () => {
  class Thing {
    v = 1;
  }

  it("refuses a value that is neither plain nor an array with INVALID_TYPE", () => {
    for (const value of [new Date(0), new Map(), new Set(), new Uint8Array(2), /x/g, new Thing()]) {
      expectUnsecureError(
        () => sanitizeObjectCopy({ value } as any),
        "INVALID_TYPE",
        "sanitizeObjectCopy: cannot copy an instance of",
      );
    }
  });

  it("refuses a non-plain root the same way", () => {
    expectUnsecureError(() => sanitizeObjectCopy(new Map() as any), "INVALID_TYPE");
  });

  it("carries an allowlisted instance by reference, subclasses included", () => {
    class Later extends Date {}
    const date = new Later(0);
    const map = new Map([["a", 1]]);
    const copy = sanitizeObjectCopy({ date, map, n: { date } } as any, {
      allowlist: [Date, Map],
    }) as any;
    expect(copy.date).toBe(date);
    expect(copy.map).toBe(map);
    expect(copy.n.date).toBe(date);
    expect(sanitizeObjectCopy(map as any, { allowlist: new Set([Map]) })).toBe(map);
  });

  it("still refuses what the allowlist does not name", () => {
    expectUnsecureError(
      () => sanitizeObjectCopy({ set: new Set() } as any, { allowlist: [Map] }),
      "INVALID_TYPE",
    );
  });

  it("does not inspect an allowlisted instance", () => {
    const thing = new Thing();
    Object.defineProperty(thing, "__proto__", { value: { polluted: true }, enumerable: true });
    const copy = sanitizeObjectCopy({ thing } as any, { allowlist: [Thing] }) as any;
    expect(copy.thing).toBe(thing);
    expect(Object.getOwnPropertyNames(thing)).toContain("__proto__");
  });

  it("carries functions by reference", () => {
    const fn = (): number => 1;
    expect((sanitizeObjectCopy({ fn } as any) as any).fn).toBe(fn);
  });

  it("rejects an allowlist that is not an iterable of constructors", () => {
    expectUnsecureError(
      () => sanitizeObjectCopy({}, { allowlist: "Date" as any }),
      "INVALID_TYPE",
      "allowlist must be an iterable of constructors",
    );
    expectUnsecureError(
      () => sanitizeObjectCopy({}, { allowlist: [1] as any }),
      "INVALID_TYPE",
      "allowlist entries must be constructors",
    );
  });

  it("reads allowlist as an own property only", () => {
    (Object.prototype as any).allowlist = [Map];
    try {
      expectUnsecureError(() => sanitizeObjectCopy({ m: new Map() } as any), "INVALID_TYPE");
    } finally {
      delete (Object.prototype as any).allowlist;
    }
  });

  it("copies null-prototype nested objects onto Object.prototype", () => {
    const nested = Object.create(null) as Record<string, unknown>;
    nested.safe = 1;
    const copy = sanitizeObjectCopy({ nested }) as any;
    expect(copy.nested).not.toBe(nested);
    expect(Object.getPrototypeOf(copy.nested)).toBe(Object.prototype);
    expect(copy.nested.safe).toBe(1);
  });
});

describe("deep nesting", () => {
  const DEPTH = 100_000;

  function deepObject(): Record<string, unknown> {
    const root: Record<string, unknown> = {};
    let node = root;
    for (let i = 0; i < DEPTH; i++) {
      const next: Record<string, unknown> = {};
      node.a = next;
      node = next;
    }
    node.leaf = 1;
    return root;
  }

  function depthOf(value: unknown): number {
    let depth = 0;
    let node = value as Record<string, unknown> | undefined;
    while (node && typeof node === "object" && "a" in node) {
      node = node.a as Record<string, unknown>;
      depth++;
    }
    return depth;
  }

  it("sanitizeObject walks a 100 000-level tree", () => {
    const obj = deepObject();
    expect(depthOf(sanitizeObject(obj))).toBe(DEPTH);
  });

  it("sanitizeObjectCopy copies a 100 000-level tree", () => {
    const obj = deepObject();
    const copy = sanitizeObjectCopy(obj);
    // `expect().not.toBe()` builds a structural hint that recurses.
    expect(copy === obj).toBe(false);
    expect(depthOf(copy)).toBe(DEPTH);
  });

  it("safeJsonParse parses a 100 000-level payload", () => {
    const json = `{"a":`.repeat(DEPTH) + "1" + "}".repeat(DEPTH);
    expect(depthOf(safeJsonParse(json))).toBe(DEPTH);
  });

  it("safeJsonParse strips dangerous keys deep in a 10 000-level payload", () => {
    const inner = '{"__proto__":{"evil":true},"ok":1}';
    const json = `{"a":`.repeat(10_000) + inner + "}".repeat(10_000);
    let node = safeJsonParse<any>(json);
    for (let i = 0; i < 10_000; i++) node = node.a;
    expect(Object.prototype.hasOwnProperty.call(node, "__proto__")).toBe(false);
    expect(node.ok).toBe(1);
  });

  it("safeJsonParse sanitizes array and primitive roots", () => {
    expect(safeJsonParse('[{"__proto__":{"x":1},"ok":2}]')).toEqual([{ ok: 2 }]);
    expect(safeJsonParse("42")).toBe(42);
    expect(safeJsonParse("null")).toBeNull();
    expect(safeJsonParse('"text"')).toBe("text");
  });

  it("sanitizeObject strips a dangerous key deep in a 10 000-level tree", () => {
    const root: Record<string, unknown> = {};
    let node = root;
    for (let i = 0; i < 10_000; i++) {
      const next: Record<string, unknown> = {};
      node.a = next;
      node = next;
    }
    Object.defineProperty(node, "constructor", { value: 1, configurable: true, enumerable: true });
    sanitizeObject(root);
    expect(Object.prototype.hasOwnProperty.call(node, "constructor")).toBe(false);
  });
});

describe("property handling", () => {
  it("removes a non-enumerable own dangerous key", () => {
    const obj: Record<string, unknown> = {};
    Object.defineProperty(obj, "__proto__", {
      value: { poisoned: true },
      enumerable: false,
      configurable: true,
      writable: true,
    });
    sanitizeObject(obj);
    expect(Object.prototype.hasOwnProperty.call(obj, "__proto__")).toBe(false);
  });

  it("never invokes an accessor while traversing", () => {
    let reads = 0;
    const obj: Record<string, unknown> = { safe: 1 };
    Object.defineProperty(obj, "trap", {
      enumerable: true,
      configurable: true,
      get() {
        reads++;
        return {};
      },
    });
    sanitizeObject(obj);
    expect(reads).toBe(0);
    // The accessor itself is left alone — only dangerous names are removed.
    expect(Object.prototype.hasOwnProperty.call(obj, "trap")).toBe(true);
  });

  it("removes a dangerous key that is an accessor without invoking it", () => {
    let reads = 0;
    const obj: Record<string, unknown> = {};
    Object.defineProperty(obj, "constructor", {
      enumerable: true,
      configurable: true,
      get() {
        reads++;
        return 1;
      },
    });
    sanitizeObject(obj);
    expect(Object.prototype.hasOwnProperty.call(obj, "constructor")).toBe(false);
    expect(reads).toBe(0);
  });

  it("traverses into a non-enumerable own data property", () => {
    const inner = JSON.parse('{"__proto__": {"evil": true}}');
    const obj: Record<string, unknown> = {};
    Object.defineProperty(obj, "hidden", {
      value: inner,
      enumerable: false,
      configurable: true,
      writable: true,
    });
    sanitizeObject(obj);
    expect(Object.prototype.hasOwnProperty.call(inner, "__proto__")).toBe(false);
  });

  it("refuses a frozen object holding a dangerous key", () => {
    const obj = Object.freeze(JSON.parse('{"__proto__": {"x": 1}, "safe": 1}'));
    expectUnsecureError(() => sanitizeObject(obj), "FROZEN");
    expect(() => sanitizeObject(obj)).toThrow(
      'sanitizeObject: cannot remove "__proto__" from a frozen object; use sanitizeObjectCopy().',
    );
  });

  it("leaves a frozen object without dangerous keys alone", () => {
    const obj = Object.freeze({ safe: 1 });
    expect(sanitizeObject(obj)).toBe(obj);
  });

  it("copy skips accessors and non-enumerable properties", () => {
    let reads = 0;
    const input: Record<string, unknown> = { plain: 1 };
    Object.defineProperty(input, "lazy", {
      enumerable: true,
      configurable: true,
      get() {
        reads++;
        return 2;
      },
    });
    Object.defineProperty(input, "hidden", { value: 3, enumerable: false, configurable: true });

    const copy = sanitizeObjectCopy(input) as any;

    expect(reads).toBe(0);
    expect(Object.prototype.hasOwnProperty.call(copy, "lazy")).toBe(false);
    expect(Object.prototype.hasOwnProperty.call(copy, "hidden")).toBe(false);
    expect(copy.plain).toBe(1);
  });
});

describe("array elements", () => {
  it("never invokes an accessor stored at an array index", () => {
    const arr: unknown[] = [];
    Object.defineProperty(arr, 0, {
      enumerable: true,
      configurable: true,
      get() {
        throw new Error("accessor invoked");
      },
    });
    arr[1] = JSON.parse('{"__proto__": {"evil": true}}');

    expect(() => sanitizeObject({ body: arr })).not.toThrow();
    expect(Object.prototype.hasOwnProperty.call(arr[1], "__proto__")).toBe(false);
    expect(() => sanitizeObjectCopy({ body: arr })).not.toThrow();
  });

  it("copies around an accessor index, keeping every other element in place", () => {
    const arr: unknown[] = ["first"];
    Object.defineProperty(arr, 1, {
      enumerable: true,
      configurable: true,
      get() {
        throw new Error("accessor invoked");
      },
    });
    arr[2] = { safe: 1 };

    const copy = sanitizeObjectCopy({ body: arr }) as any;
    expect(copy.body.length).toBe(3);
    expect(copy.body[0]).toBe("first");
    expect(Object.prototype.hasOwnProperty.call(copy.body, 1)).toBe(false);
    expect(copy.body[2]).toEqual({ safe: 1 });
  });

  it("does not read a hole through a polluted Array.prototype", () => {
    Object.defineProperty(Array.prototype, "1", {
      configurable: true,
      get() {
        throw new Error("prototype accessor invoked");
      },
    });
    try {
      const holey: unknown[] = [JSON.parse('{"__proto__": {"evil": true}}')];
      holey.length = 2;

      expect(() => sanitizeObject({ body: holey })).not.toThrow();
      expect(Object.prototype.hasOwnProperty.call(holey[0], "__proto__")).toBe(false);
      expect(() => sanitizeObjectCopy({ body: holey })).not.toThrow();
    } finally {
      delete (Array.prototype as any)["1"];
    }
  });
});

describe("arrays with named own properties", () => {
  it("sanitizeObject strips dangerous names hung on an array and walks named children", () => {
    const a: unknown[] & Record<string, unknown> = [1, 2] as never;
    Reflect.set(a, "constructor", { prototype: { polluted: true } });
    Object.defineProperty(a, "__proto__", {
      value: { polluted: true },
      enumerable: true,
      configurable: true,
    });
    a.nested = JSON.parse('{"__proto__":{"polluted":true}}');
    const received = structuredClone({ a });
    sanitizeObject(received);
    expect(Object.getOwnPropertyNames(received.a)).toEqual(["0", "1", "length", "nested"]);
    expect(Object.getOwnPropertyNames(received.a.nested as object)).toEqual([]);
  });

  it("both walkers cost the elements present, not the declared length", () => {
    const sparse: unknown[] = [];
    sparse[2 ** 32 - 2] = JSON.parse('{"__proto__":{"polluted":true},"keep":1}');
    const started = performance.now();
    const copy = sanitizeObjectCopy({ sparse }) as any;
    sanitizeObject({ sparse });
    expect(performance.now() - started).toBeLessThan(500);
    expect(copy.sparse).toHaveLength(2 ** 32 - 1);
    expect(Object.getOwnPropertyNames(copy.sparse[2 ** 32 - 2])).toEqual(["keep"]);
  });
});

describe("objects from another realm", () => {
  it("sanitizeObjectCopy rebuilds a foreign JSON object and strips it", async () => {
    const vm = await import("node:vm");
    const context = vm.createContext({});
    const foreign = vm.runInContext(
      `JSON.parse('{"a":1,"__proto__":{"polluted":"yes"},"n":{"constructor":{"prototype":{"p":1}}},"list":[{"__proto__":{"x":1}}]}')`,
      context,
    );
    expect(Object.getPrototypeOf(foreign)).not.toBe(Object.prototype);
    const copy = sanitizeObjectCopy(foreign) as any;
    expect(copy).not.toBe(foreign);
    expect(Object.getPrototypeOf(copy)).toBe(Object.prototype);
    expect(Object.getOwnPropertyNames(copy)).toEqual(["a", "n", "list"]);
    expect(Object.getOwnPropertyNames(copy.n)).toEqual([]);
    expect(Object.getOwnPropertyNames(copy.list[0])).toEqual([]);
    expect(Object.getPrototypeOf(copy.list[0])).toBe(Object.prototype);
    // Still refused: a foreign Date is not plain in any realm.
    const date = vm.runInContext("new Date(0)", context);
    expectUnsecureError(() => sanitizeObjectCopy({ date }), "INVALID_TYPE");
  });

  it("a prototype merely named Object is not plain", () => {
    const Fake = { Object: class Object {} }.Object;
    const proto = Object.create(null);
    proto.constructor = Fake;
    const value = Object.create(proto);
    expectUnsecureError(() => sanitizeObjectCopy({ value }), "INVALID_TYPE");
  });
});
