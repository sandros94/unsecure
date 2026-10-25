import { describe, expect, it } from "vitest";
import {
  createUUIDv7Generator,
  isUUIDv4,
  isUUIDv7,
  secureUUID,
  uuidv4,
  uuidv7,
  uuidv7Timestamp,
} from "unsecure/uuid";
import { newOrderId, newUserId, orderCreatedAt } from "../../examples/generate/record-ids.ts";
import { expectUnsecureError } from "../_helpers.ts";

describe("examples/generate/record-ids", () => {
  it("mints order ids that sort in the order they were made", () => {
    const ids = Array.from({ length: 5000 }, () => newOrderId());
    expect([...ids].sort()).toEqual(ids);
    expect(new Set(ids).size).toBe(ids.length);
    for (const id of ids.slice(0, 10)) expect(isUUIDv7(id)).toBe(true);
  });

  it("reads the creation time back, and null for anything else", () => {
    const before = Date.now();
    const created = orderCreatedAt(newOrderId())!;
    expect(created.getTime()).toBeGreaterThanOrEqual(before);
    expect(created.getTime()).toBeLessThanOrEqual(Date.now() + 1);

    expect(orderCreatedAt(uuidv4())).toBeNull();
    expect(orderCreatedAt("order-1042")).toBeNull();
    expect(orderCreatedAt(42)).toBeNull();
    expect(orderCreatedAt(undefined)).toBeNull();
    expect(orderCreatedAt(uuidv7(new Date("2020-01-01T00:00:00Z")))?.toISOString()).toBe(
      "2020-01-01T00:00:00.000Z",
    );
  });

  it("mints user ids that carry no timestamp", () => {
    const id = newUserId();
    expect(isUUIDv4(id)).toBe(true);
    expect(isUUIDv7(id)).toBe(false);
  });

  it("embeds a caller's time, and a failed call leaves the generator as it was", () => {
    expect(uuidv7(new Date("2020-01-01T00:00:00Z")).startsWith("016f5e66-e800-7")).toBe(true);
    const gen = createUUIDv7Generator();
    const first = gen.next();
    const backfilled = gen.next(new Date("2020-01-01T00:00:00Z"));
    expect(backfilled < first).toBe(true);
    expectUnsecureError(() => gen.next(-1), "OUT_OF_RANGE");
    expect(gen.next() > first).toBe(true);
    expect(uuidv7Timestamp(uuidv7(2 ** 48 - 1))).toBe(2 ** 48 - 1);
    expect(uuidv7Timestamp(uuidv7(1_577_836_800_000.9))).toBe(1_577_836_800_000);
    expect(secureUUID).toBe(uuidv7);
  });

  it("fails the way the page lists", () => {
    expectUnsecureError(() => uuidv7Timestamp(uuidv4()), "MALFORMED");
    expectUnsecureError(() => uuidv7Timestamp("order-1042"), "MALFORMED");
    expectUnsecureError(() => uuidv7Timestamp(42 as unknown as string), "INVALID_TYPE");
    expectUnsecureError(() => uuidv7(-1), "OUT_OF_RANGE");
    expectUnsecureError(() => uuidv7(2 ** 48), "OUT_OF_RANGE");
    expectUnsecureError(() => uuidv7(new Date("not a date")), "OUT_OF_RANGE");
    expectUnsecureError(() => uuidv7("2020-01-01" as unknown as Date), "INVALID_TYPE");
    expect(isUUIDv7(uuidv7().toUpperCase())).toBe(true);
  });
});
